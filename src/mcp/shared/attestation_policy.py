"""Attestation policy framework for per-workload attestation requirements.

Provides AttestationPolicy dataclass for configuring attestation requirements
and PolicyRegistry for mapping workload identities to policies.

Usage:
    from mcp.shared.attestation_policy import AttestationPolicy, PolicyRegistry

    registry = PolicyRegistry()
    registry.set_default(AttestationPolicy(name="default"))
    registry.register("mcp://agent-*", AttestationPolicy(
        name="agents",
        require_attestation=True,
        allowed_rtmr3=["abc123*"],
        max_evidence_age_ms=60_000,
    ))

    policy = registry.resolve("mcp://agent-orchestrator.example.com")
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttestationPolicy:
    """Per-workload attestation requirements.

    Defines what attestation properties are required for a given workload.
    """

    name: str
    require_attestation: bool = True
    require_encryption: bool = True
    allowed_rtmr3: list[str] | None = None
    allowed_cgroups: list[str] | None = None
    max_evidence_age_ms: int = 300_000
    rtmr3_transition_policy: str = "log_and_accept"


class PolicyRegistry:
    """Registry mapping workload identity patterns to attestation policies.

    Patterns use glob-style matching (fnmatch). The first matching pattern
    wins, checked in registration order. If no pattern matches, the default
    policy is returned.
    """

    def __init__(self) -> None:
        self._patterns: list[tuple[str, AttestationPolicy]] = []
        self._default: AttestationPolicy = AttestationPolicy(name="default")

    def register(self, workload_id_pattern: str, policy: AttestationPolicy) -> None:
        """Register a policy for a workload identity pattern.

        Args:
            workload_id_pattern: Glob pattern to match workload IDs.
            policy: AttestationPolicy to apply for matching workloads.
        """
        self._patterns.append((workload_id_pattern, policy))

    def resolve(self, workload_id: str) -> AttestationPolicy:
        """Resolve the policy for a given workload identity.

        Returns the first matching registered policy, or the default.

        Args:
            workload_id: The workload identity string to match.

        Returns:
            The matching AttestationPolicy.
        """
        for pattern, policy in self._patterns:
            if fnmatch.fnmatch(workload_id, pattern):
                return policy
        return self._default

    def set_default(self, policy: AttestationPolicy) -> None:
        """Set the default policy for unmatched workload IDs.

        Args:
            policy: The default AttestationPolicy.
        """
        self._default = policy

    @property
    def default(self) -> AttestationPolicy:
        """Get the current default policy."""
        return self._default

    @property
    def patterns(self) -> list[tuple[str, AttestationPolicy]]:
        """Get registered patterns and policies (in registration order)."""
        return list(self._patterns)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicyRegistry:
        """Load a PolicyRegistry from a YAML file.

        Expected schema (all keys optional; unknowns are ignored):

            default:                 # overrides the built-in default policy
              name: default
              require_attestation: true
              require_encryption: true
              allowed_rtmr3: ["abc...", "def..."]
              max_evidence_age_ms: 300000
              rtmr3_transition_policy: log_and_accept

            tools:                   # maps tool-id glob -> policy
              "agent-*":
                name: agents
                allowed_rtmr3: ["abc..."]
              "search_tool":
                name: search
                allowed_rtmr3: ["def..."]

        Notes:
          * The top-level `tools:` key takes tool-identity glob patterns the
            same way `register(pattern, policy)` does. (The workload id the
            session resolves against is what the tool call dispatches under;
            ablation tables use this to whitelist specific RTMR3s per tool.)
          * Missing file raises FileNotFoundError — callers decide whether
            that's fatal. tee_config.py treats it as "no registry".

        Args:
            path: filesystem path to the YAML file.

        Returns:
            A populated PolicyRegistry.
        """
        try:
            import yaml  # PyYAML; soft dep — no extra package in the lock
        except ImportError as e:
            raise RuntimeError(
                "PolicyRegistry.from_yaml requires PyYAML; `pip install pyyaml`"
            ) from e

        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"PolicyRegistry YAML not found: {p}")

        with p.open("r", encoding="utf-8") as fh:
            data: dict[str, Any] = yaml.safe_load(fh) or {}

        registry = cls()

        default_spec = data.get("default")
        if isinstance(default_spec, dict):
            registry.set_default(_policy_from_dict(default_spec, fallback_name="default"))

        tools = data.get("tools") or {}
        if isinstance(tools, dict):
            for pattern, spec in tools.items():
                if not isinstance(spec, dict):
                    logger.warning(
                        "policy YAML: tool entry %r is not a dict; skipping", pattern
                    )
                    continue
                registry.register(
                    str(pattern),
                    _policy_from_dict(spec, fallback_name=str(pattern)),
                )

        return registry


def _policy_from_dict(spec: dict[str, Any], *, fallback_name: str) -> AttestationPolicy:
    """Build an AttestationPolicy from a parsed YAML mapping.

    Tolerates extra keys (ignored) so a registry file can grow new fields
    without immediately breaking older SDKs.
    """
    allowed_rtmr3 = spec.get("allowed_rtmr3")
    if allowed_rtmr3 is not None and not isinstance(allowed_rtmr3, list):
        logger.warning(
            "policy YAML: allowed_rtmr3 must be a list; got %r — ignoring",
            type(allowed_rtmr3).__name__,
        )
        allowed_rtmr3 = None

    allowed_cgroups = spec.get("allowed_cgroups")
    if allowed_cgroups is not None and not isinstance(allowed_cgroups, list):
        allowed_cgroups = None

    return AttestationPolicy(
        name=str(spec.get("name", fallback_name)),
        require_attestation=bool(spec.get("require_attestation", True)),
        require_encryption=bool(spec.get("require_encryption", True)),
        allowed_rtmr3=list(allowed_rtmr3) if allowed_rtmr3 else None,
        allowed_cgroups=list(allowed_cgroups) if allowed_cgroups else None,
        max_evidence_age_ms=int(spec.get("max_evidence_age_ms", 300_000)),
        rtmr3_transition_policy=str(spec.get("rtmr3_transition_policy", "log_and_accept")),
    )
