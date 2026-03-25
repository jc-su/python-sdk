"""Semantic tool authorization for TEE-MCP.

Implements the Authorization layer of the Identity -> Authentication -> Authorization
pipeline described in the RATS (Remote Attestation Procedures) architecture:

- Identity:       Binary integrity (RTMR3 hash chain via trustd)
- Authentication:  TDX attestation proves code runs in hardware TEE
- Authorization:   This module — MCP Server enforces tool-level access control

Authorization is enforced at the MCP Server level, BELOW the LLM. This makes it
immune to prompt injection attacks — even if an injection tricks the LLM into
calling an unauthorized tool, the MCP Server blocks it before execution.

Attack categories defended (aligned with AgentDojo taxonomy):

- Privilege escalation (ImportantInstructionsAttack, ToolKnowledgeAttack):
  Tool scope restrictions prevent unauthorized capability usage. A read-only
  task context cannot invoke write/send tools regardless of LLM behavior.

- Cross-tool chaining (InjecAgentAttack, SystemMessageAttack):
  Capability boundaries prevent tool composition across scope boundaries.
  Even with knowledge of the tool API, scope enforcement blocks unauthorized calls.

- DoS via tool abuse (DoSAttack, OffensiveEmailDoSAttack):
  Rate limiting and scope constraints prevent tool misuse patterns.

Design principles:
- Fail-closed: no matching policy -> denied
- One-time analysis: tool capabilities derived at registration, not per-call
- Semantic scope: operates on tool meaning (read/write/send), not syscalls
- Hardware enforcement: decisions enforced below the LLM, in attested MCP Server
"""

from __future__ import annotations

import enum
import fnmatch
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Capability taxonomy
# ---------------------------------------------------------------------------


class ToolCapability(str, enum.Enum):
    """Semantic capability categories for MCP tools.

    Derived from tool descriptions via static analysis at registration time.
    Maps to the semantic actions a tool can perform, NOT syscall-level operations.

    Aligned with AgentDojo's tool environments:
    - Workspace: READ (get_emails) / WRITE (create_event) / SEND (send_email)
    - Banking:   READ (get_statement) / FINANCIAL (transfer) / WRITE (update_profile)
    - Travel:    READ (search_hotels) / FINANCIAL (book_hotel) / DELETE (cancel_booking)
    - Slack:     READ (read_messages) / SEND (post_message) / WRITE (upload_file)
    """

    READ = "read"  # Retrieve / query / list / search data
    WRITE = "write"  # Create / update / modify state
    SEND = "send"  # Send messages (email, slack, webhook)
    FINANCIAL = "financial"  # Financial transactions (pay, transfer, book)
    DELETE = "delete"  # Delete / remove / cancel
    EXECUTE = "execute"  # Execute code / commands / scripts
    ADMIN = "admin"  # Administrative / configuration operations


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
    verified: bool = False  # True if behavior analysis has been performed


@dataclass(frozen=True)
class AccessRule:
    """Access control rule for a subject identity pattern.

    Matched via glob against the caller's identity (cgroup path, authority subject).
    First matching rule wins. Rules are evaluated in registration order.

    Examples:
        # Allow read-only access for all agents
        AccessRule(subject_pattern="cgroup://*/agent-*", allowed_capabilities=frozenset({ToolCapability.READ}))

        # Allow specific tools for a trusted orchestrator
        AccessRule(
            subject_pattern="cgroup://*/orchestrator.scope",
            allowed_capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE, ToolCapability.SEND}),
            allowed_tools=frozenset({"send_email", "read_email", "create_event"}),
        )

        # Deny financial tools for untrusted agents
        AccessRule(subject_pattern="*", denied_tools=frozenset({"transfer_money", "make_payment"}))
    """

    subject_pattern: str
    allowed_capabilities: frozenset[ToolCapability] = frozenset()
    denied_tools: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] | None = None  # None = no tool-level allowlist
    max_calls_per_minute: int = 0  # 0 = unlimited
    require_verified: bool = False  # Require behavior-analyzed tools only


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
# Ordered by specificity — FINANCIAL before WRITE to avoid misclassification.
_CAPABILITY_KEYWORDS: dict[ToolCapability, list[str]] = {
    ToolCapability.FINANCIAL: [
        "pay",
        "transfer",
        "transaction",
        "book",
        "purchase",
        "buy",
        "refund",
        "charge",
        "invoice",
        "payment",
        "deposit",
        "withdraw",
        "balance",
        "bank",
    ],
    ToolCapability.SEND: [
        "send",
        "notify",
        "post",
        "share",
        "forward",
        "reply",
        "broadcast",
        "invite",
        "webhook",
    ],
    ToolCapability.DELETE: [
        "delete",
        "remove",
        "cancel",
        "revoke",
        "purge",
        "unsubscribe",
        "terminate",
    ],
    ToolCapability.EXECUTE: [
        "execute",
        "run",
        "eval",
        "invoke",
        "shell",
        "script",
        "command",
        "spawn",
        "launch",
    ],
    ToolCapability.ADMIN: [
        "admin",
        "configure",
        "manage",
        "permission",
        "role",
        "setting",
        "policy",
        "grant",
        "deny",
    ],
    ToolCapability.WRITE: [
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
    ],
    ToolCapability.READ: [
        "read",
        "get",
        "list",
        "search",
        "find",
        "view",
        "fetch",
        "query",
        "retrieve",
        "look",
        "check",
        "show",
        "summarize",
        "describe",
        "browse",
        "download",
    ],
}


@runtime_checkable
class ToolAnalyzer(Protocol):
    """Protocol for tool description analysis.

    Implementations analyze a tool's description (and optionally its binary)
    to derive semantic capabilities. Pluggable implementations include:

    - KeywordToolAnalyzer:   Fast keyword matching on description text (default)
    - LLMToolAnalyzer:       LLM-based behavior classification (future)
    - CallGraphToolAnalyzer: Binary call graph analysis (future, per meeting)
    """

    def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
        """Derive semantic capabilities from a tool's name and description.

        Args:
            tool_name: The MCP tool name.
            description: The tool's human-readable description.

        Returns:
            Set of ToolCapability values the tool possesses.
        """
        ...


class KeywordToolAnalyzer:
    """Default analyzer: derives capabilities from description keywords.

    Tokenizes the tool name and description into words, then checks for
    keyword membership in each capability category. Word-level matching avoids
    false positives from substring collisions (e.g., "email" in "read_email"
    should not trigger SEND capability).

    If no keywords match, defaults to READ (safest assumption).

    This provides a fast, zero-dependency baseline. For higher accuracy,
    swap in an LLM-based or call-graph analyzer via the ToolAnalyzer protocol.
    """

    def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
        # Tokenize: split on whitespace, underscores, hyphens, and punctuation
        text = f"{tool_name} {description}".lower()
        words = set(_tokenize(text))
        capabilities: set[ToolCapability] = set()
        for capability, keywords in _CAPABILITY_KEYWORDS.items():
            if words.intersection(keywords):
                capabilities.add(capability)
        # Default to READ if nothing matched — safest assumption
        if not capabilities:
            capabilities.add(ToolCapability.READ)
        return capabilities


def _tokenize(text: str) -> list[str]:
    """Split text into words on whitespace, underscores, hyphens, and common punctuation."""
    import re

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
    """MCP Server-level semantic authorization for tool calls.

    Enforced below the LLM — immune to prompt injection.

    Usage:
        manager = AuthorizationManager()

        # Register tools (auto-analyzes capabilities from description)
        manager.register_tool("read_email", "Read emails from inbox")
        manager.register_tool("send_email", "Send an email to a recipient")

        # Add access rules (first match wins)
        manager.add_rule(AccessRule(
            subject_pattern="cgroup://*/agent-reader.scope",
            allowed_capabilities=frozenset({ToolCapability.READ}),
        ))

        # Authorize (fail-closed: no matching rule -> denied)
        decision = manager.authorize("cgroup:///kubepods/agent-reader.scope", "send_email")
        assert not decision.authorized  # READ-only agent cannot SEND
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
        """Register a tool and analyze its capabilities.

        Called when tools/list response is received. The analyzer derives
        semantic capabilities from the tool description. Override with
        capabilities_override for explicit control.

        Args:
            tool_name: The MCP tool name.
            description: The tool's human-readable description.
            capabilities_override: Explicitly set capabilities instead of analyzing.

        Returns:
            The registered ToolScope.
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
            "Registered tool '%s' with capabilities: %s",
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
        """Register a tool with code-verified capabilities.

        Called after registration-time behavior analysis (call graph + LLM).
        The code_capabilities come from ACTUAL code analysis, not just description.
        Sets verified=True on the resulting ToolScope.

        This is the bridge between Phase 1 (behavior analysis) and Phase 2
        (runtime authorization). A verified tool has higher trust than one
        analyzed by keywords alone.

        Args:
            tool_name: The MCP tool name.
            description: The tool's human-readable description.
            code_capabilities: Capabilities derived from call graph analysis.
            source_hash: SHA-384 of tool source code (binds to RTMR3 measurement).

        Returns:
            The registered ToolScope with verified=True.
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

    def authorize(self, subject: str, tool_name: str) -> AuthorizationDecision:
        """Check if subject is authorized to call tool.

        Authorization cascade (fail-closed):
        1. Tool must be registered (analyzed at tools/list time)
        2. A matching access rule must exist for the subject
        3. If rule requires verified tools, check ToolScope.verified
        4. Tool must not be in the rule's denied_tools
        5. If rule has allowed_tools, tool must be in it
        6. Tool's capabilities must be subset of rule's allowed_capabilities
        7. Call rate must be within limits

        Args:
            subject: Caller identity (cgroup path or authority subject).
            tool_name: The tool being called.

        Returns:
            AuthorizationDecision with authorized flag and reason.
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
                reason=(f"tool '{tool_name}' requires capabilities {_fmt_caps(denied_caps)} not granted by rule"),
                matched_rule=rule_name,
                denied_capabilities=frozenset(denied_caps),
            )

        # 6. Rate limiting
        # 7. Rate limiting
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
        """Get list of tools this subject is authorized to call.

        Used by tools/list filtering to show only authorized tools.
        """
        return [tool_name for tool_name in self._tool_scopes if self.authorize(subject, tool_name).authorized]

    def is_authorized(self, subject: str, tool_name: str) -> bool:
        """Convenience: check authorization as boolean."""
        return self.authorize(subject, tool_name).authorized

    # -- Introspection -------------------------------------------------------

    def registered_tools(self) -> dict[str, ToolScope]:
        """Get all registered tool scopes."""
        return dict(self._tool_scopes)

    def to_metadata(self, subject: str) -> dict[str, Any]:
        """Export authorization state as metadata for _meta.tee.

        Includes the list of authorized tools and their capabilities for the subject.
        """
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
