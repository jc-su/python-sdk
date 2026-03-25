"""Authority-first tool trust management with local RTMR3 downgrade checks.

Tier 1 (local, always available):
- Query trustd for container RTMR3 integrity.
- Detect tampering by comparing with initial RTMR3 captured at boot.
- No network dependency (~0.1ms Unix socket).

Tier 2 (remote, policy):
- Query attestation-service for authority verdict/policy.
- Subscribe to verdict updates via watch stream.
- Provides admin revocation, version policy, cross-TD decisions.

Trust decision logic:
- Authority available + trusted → cross-check with local RTMR3 (tampered → override to untrusted).
- Authority available + untrusted/stale/unknown → blocked.
- Authority unavailable + local RTMR3 intact → still fail-closed (unknown).
- Authority unavailable + local check fails → untrusted.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp.shared.attestation_authority_client import (
    AttestationAuthorityClient,
    AuthorityVerdict,
)
from mcp.shared.trust_verdict import TrustVerdict

if TYPE_CHECKING:
    from mcp.shared.trustd_client import TrustdClient

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_MS = 10_000  # 10 seconds

AUTHORITY_SUBJECT_ENV = "TEE_MCP_ATTESTATION_SUBJECT"


def normalize_cgroup_path(cgroup: str | None) -> str:
    """Canonicalize cgroup path for cross-service subject matching."""
    raw_path = (cgroup or "").strip()
    if not raw_path:
        return ""
    if raw_path.startswith("cgroup://"):
        raw_path = raw_path[len("cgroup://") :]
    if not raw_path.startswith("/"):
        raw_path = f"/{raw_path}"
    return raw_path


def subject_for_cgroup(cgroup: str | None) -> str:
    """Build canonical attestation subject for a cgroup path."""
    normalized = normalize_cgroup_path(cgroup)
    if not normalized:
        return ""
    return f"cgroup://{normalized}"


def cgroup_from_subject(subject: str | None) -> str:
    """Extract canonical cgroup path from cgroup:// subject."""
    raw_subject = (subject or "").strip()
    if not raw_subject.startswith("cgroup://"):
        return ""
    return normalize_cgroup_path(raw_subject)


def normalize_authority_subject(subject: str | None, *, cgroup: str) -> str:
    """Normalize authority subject, defaulting to canonical cgroup subject."""
    raw_subject = (subject or "").strip()
    if not raw_subject:
        return subject_for_cgroup(cgroup)
    if raw_subject.startswith("cgroup://") or raw_subject.startswith("/"):
        return subject_for_cgroup(raw_subject)
    return raw_subject


@dataclass
class SubjectTrustState:
    """Trust state for one authority subject."""

    status: str  # TrustVerdict value (str enum, backward-compatible)
    rtmr3: str  # hex, current
    initial_rtmr3: str  # hex, at session start
    measurement_count: int
    cgroup: str
    timestamp_ms: int

    # Centralized authority fields
    policy_action: str = "none"
    version: int = 0
    verified_at_ms: int = 0
    expires_at_ms: int = 0
    attestation_token: str = ""
    source: str = "authority"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verdict": self.status,  # alias for wire compat with authority protocol
            "rtmr3": self.rtmr3,
            "initial_rtmr3": self.initial_rtmr3,
            "measurement_count": self.measurement_count,
            "cgroup": self.cgroup,
            "timestamp_ms": self.timestamp_ms,
            "policy_action": self.policy_action,
            "version": self.version,
            "verified_at_ms": self.verified_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "attestation_token": self.attestation_token,
            "source": self.source,
            "message": self.message,
        }


class ToolTrustManager:
    """Authority-backed trust manager for per-tool subject enforcement."""

    def __init__(
        self,
        initial_rtmr3: bytes | None,
        cgroup: str = "",
        *,
        cache_ttl_ms: int = DEFAULT_CACHE_TTL_MS,
        authority_client: AttestationAuthorityClient | None = None,
        authority_subject: str | None = None,
        trustd_client: Any = None,
    ) -> None:
        self._initial_rtmr3_hex = initial_rtmr3.hex() if initial_rtmr3 else ""
        self._cgroup = normalize_cgroup_path(cgroup)
        self._cache_ttl_ms = cache_ttl_ms
        self._lock = threading.RLock()

        self._authority = authority_client or AttestationAuthorityClient.from_env()
        self._authority_subject = normalize_authority_subject(
            authority_subject or os.environ.get(AUTHORITY_SUBJECT_ENV, ""),
            cgroup=self._cgroup,
        )
        self._authority_preflight_error = ""
        self._configuration_error: str | None = None
        self._authority_available = bool(self._authority and self._authority.enabled)

        # subject-specific cache state
        self._cached_info_by_subject: dict[str, SubjectTrustState] = {}
        self._last_check_ms_by_subject: dict[str, int] = {}
        self._dirty_subjects: set[str] = set()
        self._tool_subjects: dict[str, str] = {}
        self._last_authority_version: int = 0
        self._revision: int = 0

        # watch stream state
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._watch_subjects: tuple[str, ...] = ()

        # trustd client for local RTMR3 checks + remediation
        self._trustd: TrustdClient | None = trustd_client
        self._trustd_checked = trustd_client is not None

        if self._authority_available and self._authority is not None:
            preflight = getattr(self._authority, "preflight", None)
            if callable(preflight):
                preflight_ok, preflight_reason = preflight(check_health=True)
                if not preflight_ok:
                    self._authority_available = False
                    self._authority_preflight_error = preflight_reason
                    logger.warning(
                        "Attestation authority preflight failed (default_subject=%s): %s",
                        self._authority_subject,
                        preflight_reason,
                    )

        if not self._authority_available:
            # Check if local trust via trustd is available as fallback
            if self._get_trustd() is not None:
                logger.warning(
                    "Authority unavailable; local RTMR3 via trustd available only for fail-closed diagnostics "
                    "(default_subject=%s)",
                    self._authority_subject,
                )
            else:
                reason = "Neither attestation authority nor trustd is available for trust verification"
                if self._authority_preflight_error:
                    reason = f"{reason}: {self._authority_preflight_error}"
                self._configuration_error = reason

        if self._authority_available and self._authority is not None:
            with self._lock:
                self._restart_watch_locked(force=True)
            logger.info(
                "ToolTrustManager enabled: default_subject=%s",
                self._authority_subject,
            )
        else:
            if self._configuration_error:
                logger.warning(
                    "ToolTrustManager has no trust backend "
                    "(default_subject=%s, authority=%s, trustd=%s). Calls will fail closed.",
                    self._authority_subject,
                    bool(self._authority and self._authority.enabled),
                    self._get_trustd() is not None,
                )
            else:
                logger.warning(
                    "ToolTrustManager operating without authority verdicts; calls remain fail-closed "
                    "(default_subject=%s)",
                    self._authority_subject,
                )
            if self._authority_preflight_error:
                logger.warning("Authority preflight error: %s", self._authority_preflight_error)

    def close(self) -> None:
        """Stop background watchers and close authority channel."""
        with self._lock:
            self._watch_stop.set()
        if self._authority is not None:
            self._authority.close()

    def _get_trustd(self) -> TrustdClient | None:
        """Lazy-init trustd client."""
        if not self._trustd_checked:
            from mcp.shared.trustd_client import get_trustd_client

            self._trustd = get_trustd_client()
            self._trustd_checked = True
        return self._trustd

    def _normalize_subject(self, subject: str | None, *, fallback_to_default: bool) -> str:
        raw_subject = (subject or "").strip()
        if raw_subject:
            if raw_subject.startswith("cgroup://") or raw_subject.startswith("/"):
                return subject_for_cgroup(raw_subject)
            return raw_subject
        if fallback_to_default:
            return self._authority_subject
        return ""

    def _current_watch_subjects_locked(self) -> tuple[str, ...]:
        subjects = set(self._tool_subjects.values())
        if self._authority_subject:
            subjects.add(self._authority_subject)
        return tuple(sorted(subject for subject in subjects if subject))

    def _restart_watch_locked(self, *, force: bool = False) -> None:
        if self._authority is None or not self._authority.enabled:
            return
        subjects = self._current_watch_subjects_locked()
        if not force and subjects == self._watch_subjects:
            return

        # Stop current watch loop (if any) before replacing it.
        self._watch_stop.set()
        self._watch_stop = threading.Event()
        self._watch_subjects = subjects
        self._watch_thread = self._authority.start_watch(
            subjects=list(subjects),
            after_version=self._last_authority_version,
            on_update=self._on_authority_update,
            stop_event=self._watch_stop,
        )

    def invalidate(self) -> None:
        """Invalidate local trust cache."""
        with self._lock:
            self._cached_info_by_subject.clear()
            self._last_check_ms_by_subject.clear()
            for subject in self._current_watch_subjects_locked():
                self._dirty_subjects.add(subject)
            self._revision += 1

    def update_tool_subjects(self, tool_subjects: Mapping[str, str | None]) -> bool:
        """Replace tool->subject map. Returns True when mapping changed."""
        normalized: dict[str, str] = {}
        for tool_name, subject in tool_subjects.items():
            if not tool_name:
                continue
            normalized_subject = self._normalize_subject(subject, fallback_to_default=True)
            if normalized_subject:
                normalized[tool_name] = normalized_subject

        with self._lock:
            if normalized == self._tool_subjects:
                return False
            self._tool_subjects = normalized
            for subject in normalized.values():
                self._dirty_subjects.add(subject)
            self._revision += 1
            self._restart_watch_locked()
            return True

    def register_tool_subject(self, tool_name: str, subject: str | None) -> bool:
        """Register one tool->subject mapping. Returns True when changed."""
        if not tool_name:
            return False
        normalized_subject = self._normalize_subject(subject, fallback_to_default=True)
        with self._lock:
            old_subject = self._tool_subjects.get(tool_name, "")
            if not normalized_subject:
                if tool_name not in self._tool_subjects:
                    return False
                del self._tool_subjects[tool_name]
                self._revision += 1
                self._restart_watch_locked()
                return True
            if old_subject == normalized_subject:
                return False
            self._tool_subjects[tool_name] = normalized_subject
            self._dirty_subjects.add(normalized_subject)
            self._revision += 1
            self._restart_watch_locked()
            return True

    def get_tool_subject(self, tool_name: str) -> str:
        """Resolve a tool's subject, falling back to default subject."""
        with self._lock:
            subject = self._tool_subjects.get(tool_name, "")
        if subject:
            return subject
        return self._authority_subject

    def _on_authority_update(self, verdict: AuthorityVerdict) -> None:
        """Handle push updates from attestation-service watch stream."""
        subject = self._normalize_subject(verdict.subject, fallback_to_default=False)
        if not subject:
            return

        now_ms = int(time.time() * 1000)
        trust_state = self._verdict_to_trust_state(verdict, now_ms, subject=subject)
        with self._lock:
            cached_info = self._cached_info_by_subject.get(subject)
            current_version = max(
                self._last_authority_version,
                cached_info.version if cached_info is not None else -1,
            )
            if trust_state.version >= current_version:
                self._last_authority_version = max(self._last_authority_version, trust_state.version)
                self._cached_info_by_subject[subject] = trust_state
                self._last_check_ms_by_subject[subject] = now_ms
                # Force a sync refresh before next execution attempt.
                self._dirty_subjects.add(subject)
                self._revision += 1
        logger.debug(
            "Received authority update: subject=%s verdict=%s version=%d",
            subject,
            verdict.verdict,
            verdict.version,
        )

    # =========================================================================
    # Tier 1: Local RTMR3 integrity via trustd
    # =========================================================================

    def _check_local_integrity(self, subject: str) -> tuple[bool | None, str, str]:
        """Check container integrity via trustd RTMR3.

        Returns:
            Tuple of (intact, error_message, current_rtmr3_hex):
            - intact=True: container exists and RTMR3 unchanged from initial.
            - intact=False: RTMR3 changed (tampered).
            - intact=None: check not possible (trustd unavailable, non-cgroup subject, etc).
        """
        cgroup = cgroup_from_subject(subject)
        if not cgroup:
            return None, "non-cgroup subject", ""

        trustd = self._get_trustd()
        if trustd is None:
            return None, "trustd unavailable", ""

        try:
            state = trustd.get_container_state(cgroup)
        except Exception:
            logger.debug("Local integrity: trustd query failed for %s", cgroup, exc_info=True)
            return None, "trustd query failed", ""

        if state is None:
            return None, f"container not tracked: {cgroup}", ""

        current_rtmr3 = state.get("rtmr3", "")

        # For default subject with known initial RTMR3, detect tampering
        if self._initial_rtmr3_hex and subject == self._authority_subject:
            if current_rtmr3 and current_rtmr3 != self._initial_rtmr3_hex:
                return False, "RTMR3 changed since session start", current_rtmr3

        return True, "", current_rtmr3

    def _cross_check_with_local(
        self, authority_state: SubjectTrustState, subject: str, now_ms: int
    ) -> SubjectTrustState:
        """Cross-check authority 'trusted' verdict with local RTMR3.

        Called when authority says trusted. If local RTMR3 shows tampering,
        overrides to untrusted. If local check is not possible (trustd unavailable,
        non-cgroup subject), trusts authority.
        """
        intact, local_err, local_rtmr3 = self._check_local_integrity(subject)

        if intact is False:
            # Container tampered despite authority trust
            logger.warning(
                "Authority says trusted but local integrity check failed for %s: %s",
                subject,
                local_err,
            )
            return SubjectTrustState(
                status=TrustVerdict.UNTRUSTED,
                rtmr3=local_rtmr3,
                initial_rtmr3=self._initial_rtmr3_hex,
                measurement_count=0,
                cgroup=cgroup_from_subject(subject) or self._cgroup,
                timestamp_ms=now_ms,
                policy_action=authority_state.policy_action,
                version=authority_state.version,
                verified_at_ms=authority_state.verified_at_ms,
                expires_at_ms=authority_state.expires_at_ms,
                source="local-rtmr3-override",
                message=f"authority trusted but local check failed: {local_err}",
            )

        # intact is True or None: trust authority verdict
        return authority_state

    def _local_trust_fallback(self, subject: str, now_ms: int) -> SubjectTrustState:
        """Fail-closed fallback when authority is unavailable.

        trustd may confirm a local tamper event, but it must not authorize
        execution in place of the centralized authority.
        """
        intact, local_err, local_rtmr3 = self._check_local_integrity(subject)

        if intact is True:
            return SubjectTrustState(
                status=TrustVerdict.UNKNOWN,
                rtmr3=local_rtmr3,
                initial_rtmr3=self._initial_rtmr3_hex,
                measurement_count=0,
                cgroup=cgroup_from_subject(subject) or self._cgroup,
                timestamp_ms=now_ms,
                policy_action="alert",
                source="local-rtmr3",
                message="authority unavailable; local RTMR3 intact but cannot authorize without authority verdict",
            )
        elif intact is False:
            return SubjectTrustState(
                status=TrustVerdict.UNTRUSTED,
                rtmr3=local_rtmr3,
                initial_rtmr3=self._initial_rtmr3_hex,
                measurement_count=0,
                cgroup=cgroup_from_subject(subject) or self._cgroup,
                timestamp_ms=now_ms,
                source="local-rtmr3",
                message=f"local integrity check failed: {local_err}",
            )
        else:
            # None: trustd also unavailable — fail closed
            fallback = self._make_unavailable_state(now_ms, subject)
            if local_err:
                fallback.message = f"{fallback.message}; local check: {local_err}"
            return fallback

    # =========================================================================
    # Tier 2: Authority verdict
    # =========================================================================

    def _make_unavailable_state(self, now_ms: int, subject: str) -> SubjectTrustState:
        message = "authority verdict unavailable"
        if self._authority_preflight_error:
            message = f"{message}: {self._authority_preflight_error}"
        return SubjectTrustState(
            status=TrustVerdict.UNKNOWN,
            rtmr3="",
            initial_rtmr3=self._initial_rtmr3_hex,
            measurement_count=0,
            cgroup=cgroup_from_subject(subject) or self._cgroup,
            timestamp_ms=now_ms,
            policy_action="alert",
            source="authority",
            message=message,
        )

    def _query_authority(self, subject: str, now_ms: int) -> SubjectTrustState | None:
        if self._authority is None or not self._authority.enabled or not subject:
            return None

        verdict = self._authority.get_latest_verdict(subject)
        if verdict is None:
            return None
        return self._verdict_to_trust_state(verdict, now_ms, subject=subject)

    def _verdict_to_trust_state(self, verdict: AuthorityVerdict, now_ms: int, *, subject: str) -> SubjectTrustState:
        expires_at_ms = verdict.expires_at * 1000 if verdict.expires_at > 0 else 0
        status = verdict.verdict
        message = verdict.message
        attestation_token = verdict.attestation_token
        source = verdict.source or "authority"
        if status == TrustVerdict.TRUSTED and expires_at_ms > 0 and now_ms >= expires_at_ms:
            status = TrustVerdict.STALE
            attestation_token = ""
            source = "authority-expired"
            if message:
                message = f"{message}; latest verdict expired; re-attestation required"
            else:
                message = "latest verdict expired; re-attestation required"
        return SubjectTrustState(
            status=status,
            rtmr3="",
            initial_rtmr3=self._initial_rtmr3_hex,
            measurement_count=0,
            cgroup=cgroup_from_subject(subject) or self._cgroup,
            timestamp_ms=now_ms,
            policy_action=verdict.policy_action or "none",
            version=verdict.version,
            verified_at_ms=verdict.verified_at * 1000 if verdict.verified_at > 0 else 0,
            expires_at_ms=expires_at_ms,
            attestation_token=attestation_token,
            source=source,
            message=message,
        )

    def get_subject_trust_state(self, subject: str | None, *, require_fresh: bool = False) -> SubjectTrustState:
        """Get trust info using authority verdicts with local downgrade checks."""
        now_ms = int(time.time() * 1000)
        normalized_subject = self._normalize_subject(subject, fallback_to_default=True)
        if not normalized_subject:
            return self._make_unavailable_state(now_ms, "")

        with self._lock:
            cached = self._cached_info_by_subject.get(normalized_subject)
            last_check_ms = self._last_check_ms_by_subject.get(normalized_subject, 0)
            cache_recent = cached is not None and (now_ms - last_check_ms) < self._cache_ttl_ms
            cache_not_expired = cached is not None and (
                cached.expires_at_ms == 0 or now_ms < cached.expires_at_ms
            )
            dirty = normalized_subject in self._dirty_subjects
            if cached is not None and cache_recent and cache_not_expired and not (require_fresh and dirty):
                return cached

        # Tier 2: try authority
        trust_state = self._query_authority(normalized_subject, now_ms)

        if trust_state is not None:
            if trust_state.status == TrustVerdict.TRUSTED:
                # Cross-check: authority trusts, verify local RTMR3
                trust_state = self._cross_check_with_local(trust_state, normalized_subject, now_ms)
        else:
            # Tier 1: authority unavailable, fall back to local RTMR3
            trust_state = self._local_trust_fallback(normalized_subject, now_ms)

        with self._lock:
            self._cached_info_by_subject[normalized_subject] = trust_state
            self._last_check_ms_by_subject[normalized_subject] = now_ms
            self._last_authority_version = max(self._last_authority_version, trust_state.version)
            self._dirty_subjects.discard(normalized_subject)
        return trust_state

    def get_server_trust_state(self, *, require_fresh: bool = False) -> SubjectTrustState:
        """Get trust info for the default server subject."""
        return self.get_subject_trust_state(self._authority_subject, require_fresh=require_fresh)

    def get_tool_trust_state(self, tool_name: str, *, require_fresh: bool = False) -> SubjectTrustState:
        """Get trust info for a tool's mapped subject."""
        subject = self.get_tool_subject(tool_name)
        return self.get_subject_trust_state(subject, require_fresh=require_fresh)

    def is_tool_trusted(
        self,
        tool_name: str,
        *,
        trust_info: SubjectTrustState | None = None,
        require_fresh: bool = False,
    ) -> bool:
        """Fail-closed trust decision for one tool."""
        info = trust_info or self.get_tool_trust_state(tool_name, require_fresh=require_fresh)
        return info.status == TrustVerdict.TRUSTED

    @property
    def authority_available(self) -> bool:
        return self._authority_available

    @property
    def authority_subject(self) -> str:
        return self._authority_subject

    @property
    def configuration_error(self) -> str | None:
        return self._configuration_error

    @property
    def revision(self) -> int:
        """Monotonic revision for trust/mapping updates."""
        with self._lock:
            return self._revision

    def trigger_remediation(self, tool_name: str, *, action: str = "restart") -> dict[str, Any] | None:
        """Trigger container restart remediation via trustd.

        Args:
            tool_name: Tool that triggered remediation.
            action: none|alert|restart|kill.
        """
        normalized = (action or "none").strip().lower()
        if normalized in {"none", "alert"}:
            return None
        subject = self.get_tool_subject(tool_name)
        target_cgroup = cgroup_from_subject(subject)
        if not target_cgroup:
            logger.warning(
                "Cannot trigger remediation for tool '%s': subject '%s' is not a restartable cgroup target",
                tool_name,
                subject,
            )
            return None
        if normalized == "kill":
            # trustd currently exposes restart, not kill.
            logger.warning("Policy action 'kill' mapped to restart for cgroup '%s'", target_cgroup)

        trustd = self._get_trustd()
        if trustd is None:
            logger.warning("Cannot trigger remediation: trustd=%s, cgroup='%s'", trustd, target_cgroup)
            return None

        try:
            logger.warning(
                "Triggering remediation for tool '%s' on cgroup '%s' (action=%s)",
                tool_name,
                target_cgroup,
                normalized,
            )
            result = trustd.restart_container(target_cgroup)
            logger.info(
                "Remediation complete: cgroup=%s signaled=%s force_killed=%s",
                result.get("cgroup_path"),
                result.get("signaled_pids"),
                result.get("force_killed_pids"),
            )
            self.invalidate()
            return result
        except Exception:
            logger.exception("Remediation failed")
            return None
