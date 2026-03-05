"""Tests for ToolTrustManager - authority-only trust management."""

import time
from unittest.mock import MagicMock

import pytest

from mcp.server.tool_trust import ServerTrustInfo, ToolTrustManager, subject_for_cgroup
from mcp.shared.attestation_authority_client import AuthorityVerdict


class TestServerTrustInfo:
    def test_to_dict(self):
        info = ServerTrustInfo(
            status="trusted",
            rtmr3="aa" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=5,
            cgroup="/docker/abc",
            timestamp_ms=1234567890000,
        )
        d = info.to_dict()
        assert d["status"] == "trusted"
        assert d["rtmr3"] == "aa" * 48
        assert d["initial_rtmr3"] == "aa" * 48
        assert d["measurement_count"] == 5
        assert d["cgroup"] == "/docker/abc"
        assert d["timestamp_ms"] == 1234567890000


class _FakeAuthority:
    enabled = True

    def __init__(self, verdict: AuthorityVerdict | None = None) -> None:
        self.calls = 0
        self._callback = None
        self.current = verdict
        self.by_subject: dict[str, AuthorityVerdict] = {}
        self.watch_subjects: list[str] | None = None
        if verdict is not None:
            self.by_subject[verdict.subject] = verdict

    def get_latest_verdict(self, subject: str) -> AuthorityVerdict | None:
        self.calls += 1
        if subject in self.by_subject:
            return self.by_subject[subject]
        return self.current

    def start_watch(self, **kwargs):  # noqa: ANN003
        self._callback = kwargs.get("on_update")
        self.watch_subjects = kwargs.get("subjects")
        return None

    def preflight(self, *, check_health: bool = True) -> tuple[bool, str]:
        return (True, "ok")

    def close(self) -> None:
        return None

    def emit(self, verdict: AuthorityVerdict) -> None:
        self.current = verdict
        self.by_subject[verdict.subject] = verdict
        assert self._callback is not None
        self._callback(verdict)


def _trusted_verdict(version: int = 1, *, subject: str = "cgroup:///docker/abc") -> AuthorityVerdict:
    return AuthorityVerdict(
        subject=subject,
        verdict="trusted",
        message="ok",
        policy_action="none",
        attestation_token=f"token-v{version}",
        verified_at=123 + version,
        expires_at=int(time.time()) + 60,
        version=version,
        source="attestation-service",
    )


class TestToolTrustManager:
    def test_subject_for_cgroup_canonicalizes_paths(self):
        assert subject_for_cgroup("/docker/abc") == "cgroup:///docker/abc"
        assert subject_for_cgroup("docker/abc") == "cgroup:///docker/abc"
        assert subject_for_cgroup("cgroup:///docker/abc") == "cgroup:///docker/abc"

    def test_rejects_removed_compatibility_kwargs(self):
        with pytest.raises(TypeError):
            ToolTrustManager(  # type: ignore[call-arg]
                initial_rtmr3=None,
                cgroup="/docker/abc",
                authority_client=_FakeAuthority(_trusted_verdict()),
                trust_mode="authority_only",
            )
        with pytest.raises(TypeError):
            ToolTrustManager(  # type: ignore[call-arg]
                initial_rtmr3=None,
                cgroup="/docker/abc",
                authority_client=_FakeAuthority(_trusted_verdict()),
                authoritative=False,
            )
        with pytest.raises(TypeError):
            ToolTrustManager(  # type: ignore[call-arg]
                initial_rtmr3=None,
                cgroup="/docker/abc",
                authority_client=_FakeAuthority(_trusted_verdict()),
                fail_open=True,
            )

    def test_configuration_error_when_authority_unavailable(self):
        class DisabledAuthority:
            enabled = False

            def close(self) -> None:
                return None

        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=DisabledAuthority(),
        )
        assert manager.configuration_error is not None
        assert manager.authority_available is False
        assert manager.is_tool_trusted("any_tool") is False

    def test_authority_mode_uses_verifier_verdict(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict(version=7)),
        )
        info = manager.get_server_trust_info()
        assert info.status == "trusted"
        assert info.source == "attestation-service"
        assert info.version == 7
        assert manager.is_tool_trusted("any_tool") is True

    def test_authority_mode_fails_closed_when_verdict_unavailable(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(None),
        )
        info = manager.get_server_trust_info()
        assert info.status == "unknown"
        assert info.source == "authority"
        assert manager.is_tool_trusted("any_tool") is False

    def test_cache_returns_cached_result(self):
        authority = _FakeAuthority(_trusted_verdict())
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
        )
        manager.get_server_trust_info()
        manager.get_server_trust_info()
        assert authority.calls == 1

    def test_cache_expires_after_ttl(self):
        authority = _FakeAuthority(_trusted_verdict())
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
            cache_ttl_ms=0,
        )
        manager.get_server_trust_info()
        manager.get_server_trust_info()
        assert authority.calls == 2

    def test_authority_watch_update_invalidates_trust_immediately(self):
        authority = _FakeAuthority(_trusted_verdict(version=1))
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
        )
        assert manager.is_tool_trusted("any_tool") is True

        authority.emit(
            AuthorityVerdict(
                subject="cgroup:///docker/abc",
                verdict="untrusted",
                message="revoked",
                policy_action="restart",
                attestation_token="token-v2",
                verified_at=200,
                expires_at=int(time.time()) + 60,
                version=2,
                source="attestation-service",
            )
        )

        info = manager.get_server_trust_info()
        assert info.status == "untrusted"
        assert info.policy_action == "restart"
        assert info.version == 2
        assert manager.is_tool_trusted("any_tool") is False

    def test_authority_dirty_cache_forces_sync_refresh_on_require_fresh(self):
        authority = _FakeAuthority(_trusted_verdict(version=1))
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
            cache_ttl_ms=60_000,
        )

        first = manager.get_server_trust_info()
        assert first.version == 1
        assert authority.calls == 1

        authority.emit(
            AuthorityVerdict(
                subject="cgroup:///docker/abc",
                verdict="untrusted",
                message="revoked",
                policy_action="restart",
                attestation_token="token-v2",
                verified_at=200,
                expires_at=int(time.time()) + 60,
                version=2,
                source="attestation-service",
            )
        )

        cached = manager.get_server_trust_info()
        assert cached.version == 2
        assert authority.calls == 1

        fresh = manager.get_server_trust_info(require_fresh=True)
        assert fresh.version == 2
        assert authority.calls == 2

    def test_trigger_remediation_calls_trustd(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        mock_trustd = MagicMock()
        mock_trustd.restart_container.return_value = {
            "cgroup_path": "/docker/abc",
            "signaled_pids": 2,
            "force_killed_pids": 0,
        }
        manager._trustd = mock_trustd
        manager._trustd_checked = True

        result = manager.trigger_remediation("bad_tool")
        assert result is not None
        assert result["signaled_pids"] == 2
        mock_trustd.restart_container.assert_called_once_with("/docker/abc")

    def test_trigger_remediation_returns_none_without_trustd(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        manager._trustd = None
        manager._trustd_checked = True
        assert manager.trigger_remediation("bad_tool") is None

    def test_trigger_remediation_returns_none_without_cgroup(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        manager._trustd = MagicMock()
        manager._trustd_checked = True
        assert manager.trigger_remediation("bad_tool") is None

    def test_trigger_remediation_invalidates_cache(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        manager._cached_info_by_subject["cgroup:///docker/abc"] = ServerTrustInfo(
            status="untrusted",
            rtmr3="",
            initial_rtmr3="",
            measurement_count=0,
            cgroup="/docker/abc",
            timestamp_ms=int(time.time() * 1000),
        )
        manager._last_check_ms_by_subject["cgroup:///docker/abc"] = int(time.time() * 1000)

        mock_trustd = MagicMock()
        mock_trustd.restart_container.return_value = {
            "cgroup_path": "/docker/abc",
            "signaled_pids": 1,
            "force_killed_pids": 0,
        }
        manager._trustd = mock_trustd
        manager._trustd_checked = True

        manager.trigger_remediation("bad_tool")
        assert manager._cached_info_by_subject == {}
        assert manager._last_check_ms_by_subject == {}

    def test_per_tool_subject_mapping_is_enforced(self):
        authority = _FakeAuthority()
        authority.by_subject["cgroup:///docker/tool-a"] = _trusted_verdict(subject="cgroup:///docker/tool-a")
        authority.by_subject["cgroup:///docker/tool-b"] = AuthorityVerdict(
            subject="cgroup:///docker/tool-b",
            verdict="untrusted",
            message="revoked",
            policy_action="restart",
            attestation_token="token-b",
            verified_at=200,
            expires_at=int(time.time()) + 60,
            version=2,
            source="attestation-service",
        )
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
        )
        manager.update_tool_subjects(
            {
                "tool_a": "cgroup:///docker/tool-a",
                "tool_b": "cgroup:///docker/tool-b",
            }
        )

        assert manager.is_tool_trusted("tool_a") is True
        assert manager.is_tool_trusted("tool_b") is False

    def test_tool_subject_update_refreshes_watch_subjects(self):
        authority = _FakeAuthority(_trusted_verdict())
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
        )
        # Initial watch includes only default subject.
        assert authority.watch_subjects == ["cgroup:///docker/abc"]

        manager.update_tool_subjects({"tool_a": "cgroup:///docker/tool-a"})
        assert set(authority.watch_subjects or []) == {
            "cgroup:///docker/abc",
            "cgroup:///docker/tool-a",
        }
