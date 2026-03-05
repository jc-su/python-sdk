"""Tool trust management with centralized verifier authority.

This module is hard-locked to authority-based decisions:
- Query attestation-service for latest verdict/policy.
- Subscribe to authority verdict updates.
- Fail closed when no trusted authority verdict is available.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from typing import Mapping

from mcp.shared.attestation_authority_client import (
    AttestationAuthorityClient,
    AuthorityVerdict,
)

if TYPE_CHECKING:
    from mcp.shared.trustd_client import TrustdClient

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_MS = 10_000  # 10 seconds

AUTHORITY_SUBJECT_ENV = "TEE_MCP_ATTESTATION_SUBJECT"


def normalize_cgroup_path(cgroup: str | None) -> str:
    """Canonicalize cgroup path for cross-service subject matching."""
    raw = (cgroup or "").strip()
    if not raw:
        return ""
    if raw.startswith("cgroup://"):
        raw = raw[len("cgroup://") :]
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw


def subject_for_cgroup(cgroup: str | None) -> str:
    """Build canonical attestation subject for a cgroup path."""
    normalized = normalize_cgroup_path(cgroup)
    if not normalized:
        return ""
    return f"cgroup://{normalized}"


def cgroup_from_subject(subject: str | None) -> str:
    """Extract canonical cgroup path from cgroup:// subject."""
    raw = (subject or "").strip()
    if not raw.startswith("cgroup://"):
        return ""
    return normalize_cgroup_path(raw)


def normalize_authority_subject(subject: str | None, *, cgroup: str) -> str:
    """Normalize authority subject, defaulting to canonical cgroup subject."""
    raw = (subject or "").strip()
    if not raw:
        return subject_for_cgroup(cgroup)
    if raw.startswith("cgroup://") or raw.startswith("/"):
        return subject_for_cgroup(raw)
    return raw


@dataclass
class ServerTrustInfo:
    """Trust state for one authority subject."""

    status: str  # trusted | untrusted | stale | unknown
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
            "verdict": self.status,
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
        self._cached_info_by_subject: dict[str, ServerTrustInfo] = {}
        self._last_check_ms_by_subject: dict[str, int] = {}
        self._dirty_subjects: set[str] = set()
        self._tool_subjects: dict[str, str] = {}
        self._last_authority_version: int = 0
        self._revision: int = 0

        # watch stream state
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._watch_subjects: tuple[str, ...] = ()

        # Lazy trustd client (remediation only)
        self._trustd: TrustdClient | None = None
        self._trustd_checked = False

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
            reason = "Authority trust mode requires a reachable attestation authority"
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
            logger.warning(
                "ToolTrustManager running without authority availability "
                "(default_subject=%s, authority=%s). Calls will fail closed.",
                self._authority_subject,
                bool(self._authority and self._authority.enabled),
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
        raw = (subject or "").strip()
        if raw:
            if raw.startswith("cgroup://") or raw.startswith("/"):
                return subject_for_cgroup(raw)
            return raw
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
        info = self._authority_to_info(verdict, now_ms, subject=subject)
        with self._lock:
            cached_info = self._cached_info_by_subject.get(subject)
            current_version = max(
                self._last_authority_version,
                cached_info.version if cached_info is not None else -1,
            )
            if info.version >= current_version:
                self._last_authority_version = max(self._last_authority_version, info.version)
                self._cached_info_by_subject[subject] = info
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

    def _authority_unavailable_info(self, now_ms: int, subject: str) -> ServerTrustInfo:
        message = "authority verdict unavailable"
        if self._authority_preflight_error:
            message = f"{message}: {self._authority_preflight_error}"
        return ServerTrustInfo(
            status="unknown",
            rtmr3="",
            initial_rtmr3=self._initial_rtmr3_hex,
            measurement_count=0,
            cgroup=cgroup_from_subject(subject) or self._cgroup,
            timestamp_ms=now_ms,
            policy_action="alert",
            source="authority",
            message=message,
        )

    def _query_authority(self, subject: str, now_ms: int) -> ServerTrustInfo | None:
        if self._authority is None or not self._authority.enabled or not subject:
            return None

        verdict = self._authority.get_latest_verdict(subject)
        if verdict is None:
            return None
        return self._authority_to_info(verdict, now_ms, subject=subject)

    def _authority_to_info(self, verdict: AuthorityVerdict, now_ms: int, *, subject: str) -> ServerTrustInfo:
        return ServerTrustInfo(
            status=verdict.verdict,
            rtmr3="",
            initial_rtmr3=self._initial_rtmr3_hex,
            measurement_count=0,
            cgroup=cgroup_from_subject(subject) or self._cgroup,
            timestamp_ms=now_ms,
            policy_action=verdict.policy_action or "none",
            version=verdict.version,
            verified_at_ms=verdict.verified_at * 1000 if verdict.verified_at > 0 else 0,
            expires_at_ms=verdict.expires_at * 1000 if verdict.expires_at > 0 else 0,
            attestation_token=verdict.attestation_token,
            source=verdict.source or "authority",
            message=verdict.message,
        )

    def get_subject_trust_info(self, subject: str | None, *, require_fresh: bool = False) -> ServerTrustInfo:
        """Get trust info for a specific subject."""
        now_ms = int(time.time() * 1000)
        normalized_subject = self._normalize_subject(subject, fallback_to_default=True)
        if not normalized_subject:
            return self._authority_unavailable_info(now_ms, "")

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

        info = self._query_authority(normalized_subject, now_ms)
        if info is None:
            info = self._authority_unavailable_info(now_ms, normalized_subject)

        with self._lock:
            self._cached_info_by_subject[normalized_subject] = info
            self._last_check_ms_by_subject[normalized_subject] = now_ms
            if info.source == "authority":
                self._last_authority_version = max(self._last_authority_version, info.version)
            self._dirty_subjects.discard(normalized_subject)
        return info

    def get_server_trust_info(self, *, require_fresh: bool = False) -> ServerTrustInfo:
        """Get trust info for the default server subject."""
        return self.get_subject_trust_info(self._authority_subject, require_fresh=require_fresh)

    def get_tool_trust_info(self, tool_name: str, *, require_fresh: bool = False) -> ServerTrustInfo:
        """Get trust info for a tool's mapped subject."""
        subject = self.get_tool_subject(tool_name)
        return self.get_subject_trust_info(subject, require_fresh=require_fresh)

    def is_tool_trusted(
        self,
        tool_name: str,
        *,
        trust_info: ServerTrustInfo | None = None,
        require_fresh: bool = False,
    ) -> bool:
        """Fail-closed trust decision for one tool."""
        info = trust_info or self.get_tool_trust_info(tool_name, require_fresh=require_fresh)
        return info.status == "trusted"

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
        if normalized == "kill":
            # trustd currently exposes restart, not kill.
            logger.warning("Policy action 'kill' mapped to restart for cgroup '%s'", self._cgroup)

        trustd = self._get_trustd()
        if trustd is None or not self._cgroup:
            logger.warning("Cannot trigger remediation: trustd=%s, cgroup='%s'", trustd, self._cgroup)
            return None

        try:
            logger.warning(
                "Triggering remediation for tool '%s' on cgroup '%s' (action=%s)",
                tool_name,
                self._cgroup,
                normalized,
            )
            result = trustd.restart_container(self._cgroup)
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
