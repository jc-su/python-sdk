"""Attestation-bound tool authorization for TEE-MCP.

Implements the Authorization layer of the Identity -> Authentication -> Authorization
pipeline described in the RATS (Remote Attestation Procedures) architecture:

- Identity:       Binary integrity (RTMR3 hash chain via trustd)
- Authentication:  TDX attestation proves code runs in hardware TEE
- Authorization:   This module — MCP Server enforces tool-level access control

Authorization is enforced at the MCP Server level, BELOW the LLM. This makes it
immune to prompt injection attacks — even if an injection tricks the LLM into
calling an unauthorized tool, the MCP Server blocks it before execution.

Design principles:
- Fail-closed: no matching policy -> denied
- Security-consequence categories: grouped by damage type, not function verb
- One-time analysis: tool capabilities derived at registration, not per-call
- Hardware enforcement: decisions enforced below the LLM, in attested MCP Server
"""

from __future__ import annotations

import enum
import fnmatch
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security capability taxonomy (11 categories)
# ---------------------------------------------------------------------------


class ToolCapability(str, enum.Enum):
    """Security capability classes for MCP tools.

    Each class represents a distinct security consequence. A tool may belong
    to multiple classes (e.g., send_money is both VALUE_TRANSFER and
    CROSS_BOUNDARY_EGRESS).

    Validated against ~500 tools from AgentDojo (NeurIPS 2024),
    Agent Security Bench (ICLR 2025), and MCP-Universe.
    """

    # -- LOW risk --
    READ_PUBLIC = "read_public"
    """Read publicly available data (hotel prices, weather, flight schedules).
    No privacy violation if exposed. OWASP: LOW."""

    EXTERNAL_INGESTION = "external_ingestion"
    """Fetch content from external URLs/APIs (web scrape, RSS, search).
    Lethal Trifecta Risk_A: injection entry point. OWASP: LOW."""

    # -- MEDIUM risk --
    READ_PRIVATE = "read_private"
    """Read user's private workspace data (email, calendar, files, messages, transactions).
    Exposure = privacy breach. Lethal Trifecta Risk_B. OWASP: MEDIUM."""

    WRITE_MUTATE = "write_mutate"
    """Create/update/modify records, files, events, profiles.
    State tampering, record falsification. OWASP: MEDIUM."""

    # -- HIGH risk --
    READ_IDENTITY = "read_identity"
    """Read PII, contacts, personal identifiers (passport, credit card, SSN).
    Exposure = identity theft. OWASP: HIGH."""

    DATA_DESTRUCTION = "data_destruction"
    """Delete email, files, records, accounts. Irreversible data loss.
    Also used for evidence cleanup in multi-step attacks. OWASP: HIGH."""

    CROSS_BOUNDARY_EGRESS = "cross_boundary_egress"
    """Send data to external systems (email, HTTP POST, webhook, Slack).
    The PRIMARY exfiltration channel. Lethal Trifecta Risk_C. OWASP: HIGH."""

    VALUE_TRANSFER = "value_transfer"
    """Financial transactions, bookings, payments, refunds.
    Irreversible real-world consequences. OWASP: HIGH."""

    # -- CRITICAL risk --
    CREDENTIAL_ACCESS = "credential_access"
    """Read/write credentials, tokens, passwords, API keys, secrets.
    Enables privilege escalation. OWASP: CRITICAL (ASI03)."""

    IDENTITY_ADMIN = "identity_admin"
    """Manage users, permissions, roles, access sharing.
    Enables lateral movement and privilege escalation. OWASP: CRITICAL (ASI03)."""

    CODE_EXECUTION = "code_execution"
    """Execute code, shell commands, subprocess, eval, Docker.
    Can escalate to arbitrary access. OWASP: CRITICAL (ASI05)."""


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolScope:
    """Registered tool: its analyzed capabilities and description integrity binding.

    Created at tool registration time by the ToolAnalyzer. The description_hash
    ensures the tool description hasn't been tampered with since analysis.
    """

    tool_name: str
    capabilities: frozenset[ToolCapability]
    description_hash: str  # SHA-384 of tool description
    verified: bool = False  # True if offline behavior analysis has been performed


@dataclass(frozen=True)
class AccessRule:
    """Access control rule for a subject identity pattern.

    Matched via glob against the caller's identity (cgroup path, authority subject).
    First matching rule wins. Rules are evaluated in registration order.

    Examples:
        # Read-only agent: can only read private data
        AccessRule(
            subject_pattern="cgroup://*/email-reader*",
            allowed_capabilities=frozenset({ToolCapability.READ_PUBLIC, ToolCapability.READ_PRIVATE}),
        )

        # Finance agent: can read + transfer, but not send externally
        AccessRule(
            subject_pattern="cgroup://*/finance-bot*",
            allowed_capabilities=frozenset({
                ToolCapability.READ_PUBLIC, ToolCapability.READ_PRIVATE,
                ToolCapability.VALUE_TRANSFER,
            }),
            denied_tools=frozenset({"run_script"}),
            require_verified=True,
        )
    """

    subject_pattern: str
    allowed_capabilities: frozenset[ToolCapability] = frozenset()
    denied_tools: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] | None = None  # None = no tool-level allowlist
    max_calls_per_minute: int = 0  # 0 = unlimited
    require_verified: bool = False  # Require offline-analyzed tools only
    # Argument constraints: per-tool parameter validation.
    # Maps tool_name -> param_name -> frozenset of allowed values.
    # If a tool+param appears here, the argument MUST be in the allowed set.
    # Example: {"send_money": {"recipient": frozenset({"DE89...", "CH93..."})}}
    argument_constraints: dict[str, dict[str, frozenset[str]]] | None = None


@dataclass(frozen=True)
class AuthorizationDecision:
    """Result of an authorization check."""

    authorized: bool
    reason: str
    matched_rule: str = ""
    denied_capabilities: frozenset[ToolCapability] = frozenset()


# ---------------------------------------------------------------------------
# Tool analyzer protocol + default implementation
# ---------------------------------------------------------------------------

# Keyword table: maps capabilities to description keywords.
# Word-level matching (tokenized, not substring).
_CAPABILITY_KEYWORDS: dict[ToolCapability, list[str]] = {
    # CRITICAL — only unambiguous keywords that imply code/credential/admin operations
    ToolCapability.CODE_EXECUTION: [
        "execute",
        "eval",
        "shell",
        "script",
        "command",
        "spawn",
        "subprocess",
        "docker",
        "inject",
        "malware",
        "infiltration",
    ],
    ToolCapability.CREDENTIAL_ACCESS: [
        "password",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "apikey",
        "token",
        "login",
        "decrypt",
        "encrypt",
        "harvest",
    ],
    ToolCapability.IDENTITY_ADMIN: [
        "admin",
        "permission",
        "permissions",
        "role",
        "roles",
        "invite",
        "revoke",
        "grant",
        "deny",
        "chmod",
        "chown",
        "escalation",
        "hijack",
    ],
    # HIGH
    ToolCapability.VALUE_TRANSFER: [
        "pay",
        "transfer",
        "transaction",
        "purchase",
        "buy",
        "refund",
        "charge",
        "invoice",
        "deposit",
        "withdraw",
        "book",
        "reserve",
        "payment",
        "diversion",
        "fraud",
    ],
    ToolCapability.CROSS_BOUNDARY_EGRESS: [
        "send",
        "notify",
        "forward",
        "reply",
        "broadcast",
        "webhook",
        "publish",
        "emit",
        "export",
        "exfiltrate",
        "exfiltration",
        "leak",
    ],
    ToolCapability.DATA_DESTRUCTION: [
        "delete",
        "remove",
        "cancel",
        "purge",
        "drop",
        "truncate",
        "wipe",
        "destroy",
        "sabotage",
        "corruption",
        "disruption",
        "tamper",
    ],
    ToolCapability.READ_IDENTITY: [
        "pii",
        "passport",
        "ssn",
        "personal",
        "contact",
        "phone",
        "confidential",
        "confidentiality",
    ],
    # MEDIUM
    ToolCapability.WRITE_MUTATE: [
        "write",
        "create",
        "update",
        "modify",
        "set",
        "edit",
        "add",
        "insert",
        "append",
        "upload",
        "save",
        "rename",
        "move",
        "copy",
        "reschedule",
        "alter",
        "alteration",
        "manipulate",
        "manipulation",
        "fabrication",
    ],
    ToolCapability.READ_PRIVATE: [
        "read",
        "get",
        "list",
        "search",
        "find",
        "view",
        "fetch",
        "query",
        "retrieve",
        "check",
        "show",
        "summarize",
        "browse",
        "download",
        "inbox",
        "message",
        "email",
        "calendar",
        "file",
        "document",
        "record",
        "transaction",
        "balance",
        "monitor",
        "analyze",
        "assess",
        "recommend",
        "access",
        "theft",
    ],
    # LOW
    ToolCapability.EXTERNAL_INGESTION: [
        "scrape",
        "crawl",
        "spider",
        "rss",
        "feed",
        "webpage",
    ],
    ToolCapability.READ_PUBLIC: [
        "weather",
        "news",
        "stock",
        "price",
        "hotel",
        "restaurant",
        "flight",
        "wikipedia",
        "forecast",
        "rating",
        "review",
        "public",
        "directory",
        "market",
    ],
}


@runtime_checkable
class ToolAnalyzer(Protocol):
    """Protocol for tool description analysis.

    Implementations analyze a tool's description to derive security capability classes.
    Pluggable: KeywordToolAnalyzer (default), LLM-based, or Joern CPG-based.
    """

    def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
        """Derive security capabilities from a tool's name and description."""
        ...


class KeywordToolAnalyzer:
    """Default analyzer: derives capabilities from description keywords.

    Tokenizes the tool name and description into words, then checks for
    keyword membership in each capability category. Word-level matching avoids
    false positives from substring collisions.

    If no keywords match, defaults to READ_PRIVATE (safest non-trivial assumption).
    """

    def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
        text = f"{tool_name} {description}".lower()
        words = set(_tokenize(text))
        capabilities: set[ToolCapability] = set()
        for capability, keywords in _CAPABILITY_KEYWORDS.items():
            if words.intersection(keywords):
                capabilities.add(capability)
        if not capabilities:
            capabilities.add(ToolCapability.READ_PRIVATE)
        return capabilities


def _tokenize(text: str) -> list[str]:
    """Split text into words on whitespace, underscores, hyphens, and punctuation."""
    return re.findall(r"[a-z0-9]+", text)


# ---------------------------------------------------------------------------
# Authorization manager
# ---------------------------------------------------------------------------


@dataclass
class _RateWindow:
    """Sliding window rate limiter state for a (subject, tool) pair."""

    timestamps: list[float] = field(default_factory=lambda: [])

    def check(self, max_per_minute: int, now: float) -> bool:
        """Return True if the call is within rate limits."""
        self.timestamps = [t for t in self.timestamps if now - t < 60.0]
        if len(self.timestamps) >= max_per_minute:
            return False
        self.timestamps.append(now)
        return True


class AuthorizationManager:
    """MCP Server-level attestation-bound authorization for tool calls.

    Enforced below the LLM — immune to prompt injection.

    Usage:
        manager = AuthorizationManager()

        # Register tools (auto-analyzes capabilities from description)
        manager.register_tool("read_email", "Read emails from inbox")
        manager.register_tool("send_email", "Send an email to a recipient")

        # Add access rules (first match wins)
        manager.add_rule(AccessRule(
            subject_pattern="cgroup://*/agent-reader.scope",
            allowed_capabilities=frozenset({ToolCapability.READ_PUBLIC, ToolCapability.READ_PRIVATE}),
        ))

        # Authorize (fail-closed: no matching rule -> denied)
        decision = manager.authorize("cgroup:///kubepods/agent-reader.scope", "send_email")
        assert not decision.authorized  # READ-only agent cannot CROSS_BOUNDARY_EGRESS
    """

    def __init__(
        self,
        *,
        analyzer: ToolAnalyzer | None = None,
        default_rule: AccessRule | None = None,
    ) -> None:
        """Create authorization manager.

        Args:
            analyzer: Tool description analyzer (default: KeywordToolAnalyzer).
            default_rule: Fallback rule when no pattern matches.
                          If None, unmatched subjects are denied (fail-closed).
        """
        self._analyzer: ToolAnalyzer = analyzer or KeywordToolAnalyzer()
        self._tool_scopes: dict[str, ToolScope] = {}
        self._rules: list[AccessRule] = []
        self._default_rule: AccessRule | None = default_rule
        self._rate_windows: dict[tuple[str, str], _RateWindow] = {}

    # -- Tool registration ---------------------------------------------------

    def register_tool(
        self,
        tool_name: str,
        description: str,
        *,
        capabilities_override: set[ToolCapability] | None = None,
    ) -> ToolScope:
        """Register a tool with description-derived capabilities (UNVERIFIED).

        This is a convenience method for development/testing. In production,
        use register_verified_tool() with Pysa-analyzed capabilities.

        The tool is marked verified=False. If the access rule has
        require_verified=True, this tool will be denied.
        """
        if capabilities_override is not None:
            capabilities = capabilities_override
        else:
            capabilities = self._analyzer.analyze(tool_name, description)

        scope = ToolScope(
            tool_name=tool_name,
            capabilities=frozenset(capabilities),
            description_hash=hashlib.sha384(description.encode()).hexdigest(),
        )
        self._tool_scopes[tool_name] = scope
        logger.debug(
            "Registered unverified tool '%s' with capabilities: %s",
            tool_name,
            sorted(c.value for c in capabilities),
        )
        return scope

    def register_verified_tool(
        self,
        tool_name: str,
        description: str,
        *,
        code_capabilities: set[ToolCapability],
        source_hash: str = "",
    ) -> ToolScope:
        """Register a tool with Pysa-verified capabilities (PRODUCTION PATH).

        Called after offline static analysis (Pysa taint flow). The
        code_capabilities come from ACTUAL source code analysis.
        Sets verified=True — required by production access rules.

        The description is used ONLY for mismatch detection (comparing
        code capabilities vs description claims), not for authorization.
        """
        scope = ToolScope(
            tool_name=tool_name,
            capabilities=frozenset(code_capabilities),
            description_hash=hashlib.sha384(description.encode()).hexdigest(),
            verified=True,
        )
        self._tool_scopes[tool_name] = scope
        logger.info(
            "Registered verified tool '%s' with capabilities: %s (source_hash=%s)",
            tool_name,
            sorted(c.value for c in code_capabilities),
            source_hash[:16] + "..." if source_hash else "none",
        )
        return scope

    def get_tool_scope(self, tool_name: str) -> ToolScope | None:
        """Get the registered scope for a tool."""
        return self._tool_scopes.get(tool_name)

    # -- Rule management -----------------------------------------------------

    def add_rule(self, rule: AccessRule) -> None:
        """Add an access rule. Rules are evaluated in insertion order (first match wins)."""
        self._rules.append(rule)

    def set_default_rule(self, rule: AccessRule) -> None:
        """Set the fallback rule for unmatched subjects."""
        self._default_rule = rule

    @property
    def rules(self) -> list[AccessRule]:
        """Get registered rules in evaluation order."""
        return list(self._rules)

    # -- Authorization -------------------------------------------------------

    def authorize(
        self,
        subject: str,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> AuthorizationDecision:
        """Check if subject is authorized to call tool with given arguments.

        Authorization cascade (fail-closed):
        1. Tool must be registered (analyzed at tools/list time)
        2. A matching access rule must exist for the subject
        3. If rule requires verified tools, check ToolScope.verified
        4. Tool must not be in the rule's denied_tools
        5. If rule has allowed_tools, tool must be in it
        6. Tool's capabilities must be subset of rule's allowed_capabilities
        7. Argument constraints must be satisfied (recipient allowlists, etc.)
        8. Call rate must be within limits
        """
        # 1. Tool must be registered
        scope = self._tool_scopes.get(tool_name)
        if scope is None:
            return AuthorizationDecision(
                authorized=False,
                reason=f"tool '{tool_name}' not registered for authorization",
            )

        # 2. Find matching rule
        rule = self._resolve_rule(subject)
        if rule is None:
            return AuthorizationDecision(
                authorized=False,
                reason=f"no authorization rule matches subject '{subject}'",
            )

        rule_name = rule.subject_pattern

        # 3. Behavior verification requirement
        if rule.require_verified and not scope.verified:
            return AuthorizationDecision(
                authorized=False,
                reason=f"tool '{tool_name}' requires behavior verification but is not verified",
                matched_rule=rule_name,
            )

        # 4. Explicit deny list
        if tool_name in rule.denied_tools:
            return AuthorizationDecision(
                authorized=False,
                reason=f"tool '{tool_name}' is in deny list",
                matched_rule=rule_name,
            )

        # 5. Explicit allow list (if set)
        if rule.allowed_tools is not None and tool_name not in rule.allowed_tools:
            return AuthorizationDecision(
                authorized=False,
                reason=f"tool '{tool_name}' not in allow list",
                matched_rule=rule_name,
            )

        # 6. Capability check
        denied_caps = scope.capabilities - rule.allowed_capabilities
        if denied_caps:
            return AuthorizationDecision(
                authorized=False,
                reason=f"tool '{tool_name}' requires capabilities {_fmt_caps(denied_caps)} not granted by rule",
                matched_rule=rule_name,
                denied_capabilities=frozenset(denied_caps),
            )

        # 7. Argument constraints
        if arguments is not None and rule.argument_constraints is not None:
            tool_constraints = rule.argument_constraints.get(tool_name)
            if tool_constraints:
                for param_name, allowed_values in tool_constraints.items():
                    actual = arguments.get(param_name)
                    if actual is None:
                        continue
                    # Normalize: handle both single values and lists
                    actuals = actual if isinstance(actual, list) else [actual]
                    for val in actuals:
                        if str(val) not in allowed_values:
                            return AuthorizationDecision(
                                authorized=False,
                                reason=f"argument '{param_name}'='{val}' not in allowed values for tool '{tool_name}'",
                                matched_rule=rule_name,
                            )

        # 8. Rate limiting
        if rule.max_calls_per_minute > 0:
            key = (subject, tool_name)
            window = self._rate_windows.setdefault(key, _RateWindow())
            if not window.check(rule.max_calls_per_minute, time.monotonic()):
                return AuthorizationDecision(
                    authorized=False,
                    reason=f"rate limit exceeded ({rule.max_calls_per_minute}/min)",
                    matched_rule=rule_name,
                )

        return AuthorizationDecision(
            authorized=True,
            reason="authorized",
            matched_rule=rule_name,
        )

    def get_authorized_tools(self, subject: str) -> list[str]:
        """Get list of tools this subject is authorized to call."""
        return [tool_name for tool_name in self._tool_scopes if self.authorize(subject, tool_name).authorized]

    def is_authorized(self, subject: str, tool_name: str) -> bool:
        """Convenience: check authorization as boolean."""
        return self.authorize(subject, tool_name).authorized

    # -- Introspection -------------------------------------------------------

    def registered_tools(self) -> dict[str, ToolScope]:
        """Get all registered tool scopes."""
        return dict(self._tool_scopes)

    def to_metadata(self, subject: str) -> dict[str, Any]:
        """Export authorization state as metadata for _meta.tee."""
        authorized_tools: list[dict[str, Any]] = []
        for tool_name in self._tool_scopes:
            decision = self.authorize(subject, tool_name)
            scope = self._tool_scopes[tool_name]
            authorized_tools.append(
                {
                    "tool": tool_name,
                    "authorized": decision.authorized,
                    "capabilities": sorted(c.value for c in scope.capabilities),
                    "reason": decision.reason if not decision.authorized else "",
                }
            )
        return {"authorization": {"subject": subject, "tools": authorized_tools}}

    # -- Internal ------------------------------------------------------------

    def _resolve_rule(self, subject: str) -> AccessRule | None:
        """Find the first matching rule for a subject (glob match)."""
        for rule in self._rules:
            if fnmatch.fnmatch(subject, rule.subject_pattern):
                return rule
        return self._default_rule


def _fmt_caps(caps: frozenset[ToolCapability]) -> str:
    """Format capabilities for log messages."""
    return "{" + ", ".join(sorted(c.value for c in caps)) + "}"
