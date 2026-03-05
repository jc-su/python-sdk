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
