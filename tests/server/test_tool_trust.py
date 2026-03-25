"""Tests for ToolTrustManager - authority-only trust management."""

import time
from unittest.mock import MagicMock

import pytest

from mcp.server.tool_trust import SubjectTrustState, ToolTrustManager, subject_for_cgroup
from mcp.shared.attestation_authority_client import AuthorityVerdict


class TestSubjectTrustState:
    def test_to_dict(self):
        info = SubjectTrustState(
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


class _FakeTrustd:
    """Fake trustd client for testing local RTMR3 checks."""

    def __init__(self, states: dict[str, dict] | None = None) -> None:
        self.states: dict[str, dict] = states or {}
        self.restart_calls: list[str] = []

    def get_container_state(self, cgroup_path: str) -> dict | None:
        return self.states.get(cgroup_path)

    def restart_container(self, cgroup_path: str) -> dict:
        self.restart_calls.append(cgroup_path)
        return {"cgroup_path": cgroup_path, "signaled_pids": 1, "force_killed_pids": 0}

    def ping(self) -> dict:
        return {"version": "test", "uptime_seconds": 0, "containers_tracked": len(self.states)}


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
        info = manager.get_server_trust_state()
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
        info = manager.get_server_trust_state()
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
        manager.get_server_trust_state()
        manager.get_server_trust_state()
        assert authority.calls == 1

    def test_cache_expires_after_ttl(self):
        authority = _FakeAuthority(_trusted_verdict())
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=authority,
            cache_ttl_ms=0,
        )
        manager.get_server_trust_state()
        manager.get_server_trust_state()
        assert authority.calls == 2

    def test_expired_authority_verdict_downgrades_to_stale(self):
        expired = AuthorityVerdict(
            subject="cgroup:///docker/abc",
            verdict="trusted",
            message="ok",
            policy_action="none",
            attestation_token="token-v1",
            verified_at=100,
            expires_at=int(time.time()) - 1,
            version=1,
            source="attestation-service",
        )
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(expired),
        )

        info = manager.get_server_trust_state()
        assert info.status == "stale"
        assert info.attestation_token == ""
        assert info.source == "authority-expired"
        assert "expired" in info.message

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

        info = manager.get_server_trust_state()
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

        first = manager.get_server_trust_state()
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

        cached = manager.get_server_trust_state()
        assert cached.version == 2
        assert authority.calls == 1

        fresh = manager.get_server_trust_state(require_fresh=True)
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

    def test_trigger_remediation_uses_mapped_tool_subject_cgroup(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/server",
            authority_client=_FakeAuthority(_trusted_verdict(subject="cgroup:///docker/server")),
        )
        manager.update_tool_subjects({"bad_tool": "cgroup:///docker/tool-a"})
        mock_trustd = MagicMock()
        mock_trustd.restart_container.return_value = {
            "cgroup_path": "/docker/tool-a",
            "signaled_pids": 2,
            "force_killed_pids": 0,
        }
        manager._trustd = mock_trustd
        manager._trustd_checked = True

        result = manager.trigger_remediation("bad_tool")
        assert result is not None
        mock_trustd.restart_container.assert_called_once_with("/docker/tool-a")

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

    def test_trigger_remediation_returns_none_for_non_cgroup_subject(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/server",
            authority_client=_FakeAuthority(_trusted_verdict(subject="cgroup:///docker/server")),
        )
        manager.update_tool_subjects({"bad_tool": "image://tool-a"})
        manager._trustd = MagicMock()
        manager._trustd_checked = True

        assert manager.trigger_remediation("bad_tool") is None
        manager._trustd.restart_container.assert_not_called()

    def test_trigger_remediation_invalidates_cache(self):
        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        manager._cached_info_by_subject["cgroup:///docker/abc"] = SubjectTrustState(
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


class TestTwoTierTrust:
    """Tests for Tier 1 (local RTMR3 via trustd) + Tier 2 (authority) integration."""

    def test_local_fallback_keeps_fail_closed_when_container_intact(self):
        """Authority unavailable + trustd intact still fails closed."""
        initial = bytes.fromhex("aa" * 48)
        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "aa" * 48}})
        manager = ToolTrustManager(
            initial_rtmr3=initial,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(None),  # no verdict
            trustd_client=trustd,
        )
        info = manager.get_server_trust_state()
        assert info.status == "unknown"
        assert info.source == "local-rtmr3"
        assert "cannot authorize" in info.message
        assert manager.is_tool_trusted("any_tool") is False

    def test_local_fallback_rejects_tampered_container(self):
        """Authority unavailable + RTMR3 changed → untrusted."""
        initial = bytes.fromhex("aa" * 48)
        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "bb" * 48}})
        manager = ToolTrustManager(
            initial_rtmr3=initial,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(None),
            trustd_client=trustd,
        )
        info = manager.get_server_trust_state()
        assert info.status == "untrusted"
        assert info.source == "local-rtmr3"
        assert "RTMR3 changed" in info.message
        assert manager.is_tool_trusted("any_tool") is False

    def test_cross_check_overrides_trusted_when_tampered(self):
        """Authority says trusted but local RTMR3 changed → untrusted."""
        initial = bytes.fromhex("aa" * 48)
        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "bb" * 48}})
        manager = ToolTrustManager(
            initial_rtmr3=initial,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
            trustd_client=trustd,
        )
        info = manager.get_server_trust_state()
        assert info.status == "untrusted"
        assert info.source == "local-rtmr3-override"
        assert "authority trusted but local check failed" in info.message
        assert manager.is_tool_trusted("any_tool") is False

    def test_cross_check_passes_when_intact(self):
        """Authority trusted + local RTMR3 intact → trusted."""
        initial = bytes.fromhex("aa" * 48)
        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "aa" * 48}})
        manager = ToolTrustManager(
            initial_rtmr3=initial,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
            trustd_client=trustd,
        )
        info = manager.get_server_trust_state()
        assert info.status == "trusted"
        assert info.source == "attestation-service"
        assert manager.is_tool_trusted("any_tool") is True

    def test_cross_check_skipped_when_trustd_unavailable(self):
        """Authority trusted + no trustd → trusted (authority only)."""
        manager = ToolTrustManager(
            initial_rtmr3=bytes.fromhex("aa" * 48),
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
            # no trustd_client
        )
        manager._trustd = None
        manager._trustd_checked = True
        info = manager.get_server_trust_state()
        assert info.status == "trusted"
        assert info.source == "attestation-service"

    def test_authority_untrusted_not_overridden_by_local(self):
        """Authority says untrusted → untrusted, even if local RTMR3 is intact."""
        initial = bytes.fromhex("aa" * 48)
        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "aa" * 48}})
        revoked = AuthorityVerdict(
            subject="cgroup:///docker/abc",
            verdict="untrusted",
            message="admin revoked",
            policy_action="restart",
            attestation_token="",
            verified_at=200,
            expires_at=int(time.time()) + 60,
            version=2,
            source="attestation-service",
        )
        manager = ToolTrustManager(
            initial_rtmr3=initial,
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(revoked),
            trustd_client=trustd,
        )
        info = manager.get_server_trust_state()
        assert info.status == "untrusted"
        assert info.policy_action == "restart"
        assert manager.is_tool_trusted("any_tool") is False

    def test_no_configuration_error_when_trustd_available(self):
        """Authority unavailable + trustd available still stays fail-closed."""

        class DisabledAuthority:
            enabled = False

            def close(self) -> None:
                return None

        trustd = _FakeTrustd({"/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "aa" * 48}})
        manager = ToolTrustManager(
            initial_rtmr3=bytes.fromhex("aa" * 48),
            cgroup="/docker/abc",
            authority_client=DisabledAuthority(),
            trustd_client=trustd,
        )
        assert manager.configuration_error is None
        assert manager.authority_available is False
        assert manager.is_tool_trusted("any_tool") is False

    def test_both_unavailable_is_configuration_error(self):
        """Neither authority nor trustd → configuration error + fail-closed."""

        class DisabledAuthority:
            enabled = False

            def close(self) -> None:
                return None

        manager = ToolTrustManager(
            initial_rtmr3=None,
            cgroup="/docker/abc",
            authority_client=DisabledAuthority(),
            # no trustd_client, and force no lazy discovery
        )
        manager._trustd = None
        manager._trustd_checked = True
        assert manager.configuration_error is not None
        assert "Neither" in manager.configuration_error
        assert manager.is_tool_trusted("any_tool") is False

    def test_local_check_skipped_for_non_cgroup_subject(self):
        """Non-cgroup subjects skip local RTMR3 check."""
        manager = ToolTrustManager(
            initial_rtmr3=bytes.fromhex("aa" * 48),
            cgroup="/docker/abc",
            authority_client=_FakeAuthority(_trusted_verdict()),
        )
        manager.update_tool_subjects({"image_tool": "image://my-tool:v1"})
        # Authority returns trusted for default subject (fallback)
        assert manager.is_tool_trusted("image_tool") is True

    def test_local_fallback_for_tool_without_initial_rtmr3_stays_unknown(self):
        """Tool without authority verdict stays blocked even if trustd sees the container."""
        trustd = _FakeTrustd({
            "/docker/abc": {"cgroup_path": "/docker/abc", "rtmr3": "aa" * 48},
            "/docker/tool-a": {"cgroup_path": "/docker/tool-a", "rtmr3": "cc" * 48},
        })
        authority = _FakeAuthority(None)
        authority.by_subject["cgroup:///docker/abc"] = _trusted_verdict(subject="cgroup:///docker/abc")
        # No verdict for tool-a
        manager = ToolTrustManager(
            initial_rtmr3=bytes.fromhex("aa" * 48),
            cgroup="/docker/abc",
            authority_client=authority,
            trustd_client=trustd,
        )
        manager.update_tool_subjects({"tool_a": "cgroup:///docker/tool-a"})

        # Server itself is trusted (authority has verdict)
        assert manager.is_tool_trusted("default_tool") is True

        # tool_a: no authority verdict, so local state cannot promote it to trusted
        info = manager.get_tool_trust_state("tool_a")
        assert info.status == "unknown"
        assert info.source == "local-rtmr3"
