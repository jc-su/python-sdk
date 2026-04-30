"""Tests for RTMR3 state transition detection (Part C)."""

from unittest.mock import patch

from mcp.shared.secure_channel import (
    AttestationEvidence,
    PeerStateChange,
    RTMR3TransitionPolicy,
    SecureEndpoint,
)

# =============================================================================
# Helpers
# =============================================================================

RTMR3_A = bytes(range(48))
RTMR3_B = bytes(range(1, 49))
CGROUP_A = "/docker/container-a"
CGROUP_B = "/docker/container-b"


def _make_evidence(nonce: bytes, rtmr3: bytes = RTMR3_A, cgroup: str = CGROUP_A) -> AttestationEvidence:
    return AttestationEvidence(
        quote=b"mock_quote",
        public_key=b"mock_pubkey",
        nonce=nonce,
        cgroup=cgroup,
        rtmr3=rtmr3,
        timestamp_ms=9999999999999,
        role="client",
    )


def _always_valid(evidence, expected_nonce, allowed_rtmr3=None, *,
                  authority_enabled=True, skip_quote=False):
    """Stub for _verify_attestation_evidence that always succeeds."""
    del authority_enabled, skip_quote
    return True, "", evidence.public_key


# =============================================================================
# Tests
# =============================================================================


class TestRTMR3TransitionDetection:
    """RTMR3 transition detection in verify_peer_attestation."""

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_same_rtmr3_no_event(self, _mock_load, _mock_verify):
        """Same RTMR3 across calls produces no state change event."""
        ep = SecureEndpoint.create(role="server")
        nonce = ep.generate_nonce("client")

        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A)
        r1 = ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")
        assert r1.valid

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_A)
        r2 = ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")
        assert r2.valid

        assert len(ep.peer_state_history) == 0

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_different_rtmr3_callback_invoked(self, _mock_load, _mock_verify):
        """Different RTMR3 triggers callback and records change."""
        ep = SecureEndpoint.create(role="server")
        callback_calls: list[PeerStateChange] = []

        def on_change(change: PeerStateChange) -> RTMR3TransitionPolicy:
            callback_calls.append(change)
            return RTMR3TransitionPolicy.LOG_AND_ACCEPT

        ep.on_peer_state_change = on_change

        nonce = ep.generate_nonce("client")
        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A, cgroup=CGROUP_A)
        ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_B, cgroup=CGROUP_B)
        ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")

        assert len(callback_calls) == 1
        assert callback_calls[0].old_rtmr3 == RTMR3_A
        assert callback_calls[0].new_rtmr3 == RTMR3_B
        assert callback_calls[0].old_cgroup == CGROUP_A
        assert callback_calls[0].new_cgroup == CGROUP_B

        assert len(ep.peer_state_history) == 1

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_reject_policy_returns_invalid(self, _mock_load, _mock_verify):
        """REJECT policy causes verify_peer_attestation to return invalid."""
        ep = SecureEndpoint.create(role="server")
        ep.rtmr3_transition_policy = RTMR3TransitionPolicy.REJECT

        nonce = ep.generate_nonce("client")
        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A)
        r1 = ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")
        assert r1.valid

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_B)
        r2 = ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")
        assert not r2.valid
        assert "RTMR3 changed" in r2.error

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_log_and_accept_accepts_but_records(self, _mock_load, _mock_verify):
        """LOG_AND_ACCEPT accepts and records the change."""
        ep = SecureEndpoint.create(role="server")
        ep.rtmr3_transition_policy = RTMR3TransitionPolicy.LOG_AND_ACCEPT

        nonce = ep.generate_nonce("client")
        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A)
        ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_B)
        r2 = ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")
        assert r2.valid

        assert len(ep.peer_state_history) == 1
        assert ep.peers["client"].rtmr3 == RTMR3_B

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_accept_policy_no_record(self, _mock_load, _mock_verify):
        """ACCEPT policy accepts and records (still tracks history)."""
        ep = SecureEndpoint.create(role="server")
        ep.rtmr3_transition_policy = RTMR3TransitionPolicy.ACCEPT

        nonce = ep.generate_nonce("client")
        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A)
        ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_B)
        r2 = ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")
        assert r2.valid
        assert len(ep.peer_state_history) == 1

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_history_accumulates(self, _mock_load, _mock_verify):
        """History accumulates across multiple transitions."""
        ep = SecureEndpoint.create(role="server")
        ep.rtmr3_transition_policy = RTMR3TransitionPolicy.LOG_AND_ACCEPT

        rtmr3_values = [bytes([i] * 48) for i in range(4)]

        for i, rtmr3 in enumerate(rtmr3_values):
            nonce = ep.generate_nonce("client")
            ev = _make_evidence(nonce, rtmr3=rtmr3)
            ep.verify_peer_attestation(ev, expected_nonce=nonce, peer_role="client")

        # 3 transitions (between 4 different values)
        assert len(ep.peer_state_history) == 3

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_callback_overrides_default_policy(self, _mock_load, _mock_verify):
        """Callback return value overrides the default policy."""
        ep = SecureEndpoint.create(role="server")
        ep.rtmr3_transition_policy = RTMR3TransitionPolicy.ACCEPT  # default would accept

        def reject_all(change: PeerStateChange) -> RTMR3TransitionPolicy:
            return RTMR3TransitionPolicy.REJECT

        ep.on_peer_state_change = reject_all

        nonce = ep.generate_nonce("client")
        ev1 = _make_evidence(nonce, rtmr3=RTMR3_A)
        ep.verify_peer_attestation(ev1, expected_nonce=nonce, peer_role="client")

        nonce2 = ep.generate_nonce("client")
        ev2 = _make_evidence(nonce2, rtmr3=RTMR3_B)
        r2 = ep.verify_peer_attestation(ev2, expected_nonce=nonce2, peer_role="client")
        assert not r2.valid

    @patch("mcp.shared.secure_channel._verify_attestation_evidence", side_effect=_always_valid)
    @patch("mcp.shared.secure_channel.x25519.load_public_key", return_value="fake_pk")
    def test_explicit_peer_role_rejects_evidence_role_mismatch(self, _mock_load, _mock_verify):
        """Explicit peer_role must not be overridden by untrusted evidence.role."""
        ep = SecureEndpoint.create(role="server")
        nonce = ep.generate_nonce("client")

        ev = _make_evidence(nonce, rtmr3=RTMR3_A)
        ev.role = "server"
        result = ep.verify_peer_attestation(ev, expected_nonce=nonce, peer_role="client")

        assert result.valid is False
        assert "role mismatch" in result.error.lower()
        assert "client" not in ep.peers
