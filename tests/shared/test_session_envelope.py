"""Tests for session envelope functions (create_session_envelope, verify_session_envelope).

Session envelopes use HMAC(mac_key, counter) for authentication.
No encryption, no TDX quote. Wire format: {counter, auth_tag, timestamp_ms}.
"""

import base64
import hashlib
import hmac
import secrets

from mcp.shared.tee_envelope import (
    create_session_envelope,
    verify_session_envelope,
)

# =============================================================================
# Mock Classes (matching new SecureEndpoint API)
# =============================================================================


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing session envelopes."""

    def __init__(self, role: str = "server"):
        self.role = role
        self.mac_key: bytes | None = secrets.token_bytes(32)
        self._send_counter = 0
        self._recv_counter = 0

    def next_send_counter(self) -> int:
        counter = self._send_counter
        self._send_counter += 1
        return counter

    def verify_recv_counter(self, counter: int) -> None:
        if counter < self._recv_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._recv_counter}")
        self._recv_counter = counter + 1

    def create_session_auth(self, counter: int) -> bytes:
        if self.mac_key is None:
            raise ValueError("MAC key not established")
        return hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()

    def verify_session_auth(self, counter: int, auth_tag: bytes) -> bool:
        if self.mac_key is None:
            return False
        expected = hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        return hmac.compare_digest(expected, auth_tag)


class MockEndpointNoMacKey:
    """Mock endpoint without mac_key."""

    def __init__(self):
        self.mac_key = None


# =============================================================================
# Tests for create_session_envelope
# =============================================================================


class TestCreateSessionEnvelope:
    def test_basic_session_envelope(self):
        """Session envelope includes counter, auth_tag, and timestamp."""
        endpoint = MockSecureEndpoint()

        tee = create_session_envelope(endpoint)

        assert "counter" in tee
        assert "auth_tag" in tee
        assert "timestamp_ms" in tee
        assert tee["counter"] == 0
        # No sig_data or entropy in new format
        assert "sig_data" not in tee
        assert "entropy" not in tee

    def test_includes_trust_metadata(self):
        """Trust metadata is included when provided."""
        endpoint = MockSecureEndpoint()

        metadata = {
            "status": "trusted",
            "rtmr3": "aa" * 48,
            "initial_rtmr3": "aa" * 48,
            "measurement_count": 5,
            "cgroup": "/docker/abc",
            "timestamp_ms": 1234567890000,
        }

        tee = create_session_envelope(endpoint, trust_metadata=metadata)

        assert "server_trust" in tee
        assert tee["server_trust"]["status"] == "trusted"
        assert tee["server_trust"]["rtmr3"] == "aa" * 48

    def test_no_trust_metadata_by_default(self):
        """No server_trust field when not provided."""
        endpoint = MockSecureEndpoint()

        tee = create_session_envelope(endpoint)

        assert "server_trust" not in tee

    def test_counter_increments(self):
        """Counter increments per call."""
        endpoint = MockSecureEndpoint()

        tee1 = create_session_envelope(endpoint)
        tee2 = create_session_envelope(endpoint)

        assert tee1["counter"] == 0
        assert tee2["counter"] == 1

    def test_auth_tag_is_valid_base64(self):
        """auth_tag is a valid base64-encoded string."""
        endpoint = MockSecureEndpoint()

        tee = create_session_envelope(endpoint)

        auth_tag_bytes = base64.b64decode(tee["auth_tag"])
        assert len(auth_tag_bytes) == 32  # SHA256 HMAC output


# =============================================================================
# Tests for verify_session_envelope
# =============================================================================


class TestVerifySessionEnvelope:
    def test_valid_session_envelope(self):
        """Valid session-bound envelope passes verification."""
        mac_key = secrets.token_bytes(32)

        sender = MockSecureEndpoint()
        sender.mac_key = mac_key

        receiver = MockSecureEndpoint()
        receiver.mac_key = mac_key

        tee = create_session_envelope(sender)
        valid, error = verify_session_envelope(receiver, tee)

        assert valid is True
        assert error == ""

    def test_missing_counter(self):
        """Missing counter fails verification."""
        endpoint = MockSecureEndpoint()

        valid, error = verify_session_envelope(endpoint, {"auth_tag": "x", "timestamp_ms": 123})

        assert valid is False
        assert "Missing or invalid counter" in error

    def test_invalid_counter_type(self):
        """Non-integer counter fails."""
        endpoint = MockSecureEndpoint()

        valid, error = verify_session_envelope(endpoint, {
            "counter": "not_int",
            "auth_tag": base64.b64encode(b"x" * 32).decode(),
        })

        assert valid is False
        assert "Missing or invalid counter" in error

    def test_missing_auth_tag(self):
        """Missing auth_tag fails verification."""
        endpoint = MockSecureEndpoint()

        valid, error = verify_session_envelope(endpoint, {"counter": 0})

        assert valid is False
        assert "Missing auth_tag" in error

    def test_invalid_auth_tag_base64(self):
        """Malformed base64 in auth_tag is rejected."""
        endpoint = MockSecureEndpoint()

        valid, error = verify_session_envelope(endpoint, {
            "counter": 0,
            "auth_tag": "!!!bad-base64!!!",
        })

        assert valid is False
        assert "Invalid base64 in auth_tag" in error

    def test_wrong_auth_tag_rejected(self):
        """Invalid auth_tag (wrong mac_key) is rejected."""
        sender = MockSecureEndpoint()
        receiver = MockSecureEndpoint()
        # Different mac_keys -> auth tag won't match
        sender.mac_key = secrets.token_bytes(32)
        receiver.mac_key = secrets.token_bytes(32)

        tee = create_session_envelope(sender)
        valid, error = verify_session_envelope(receiver, tee)

        assert valid is False
        assert "Invalid auth_tag" in error

    def test_stale_counter_rejected(self):
        """Replayed counter is rejected."""
        mac_key = secrets.token_bytes(32)

        sender = MockSecureEndpoint()
        sender.mac_key = mac_key

        receiver = MockSecureEndpoint()
        receiver.mac_key = mac_key

        tee1 = create_session_envelope(sender)
        tee2 = create_session_envelope(sender)

        # Verify second first (counter=1)
        valid, _ = verify_session_envelope(receiver, tee2)
        assert valid is True

        # Verify first (counter=0) -- stale
        valid, error = verify_session_envelope(receiver, tee1)
        assert valid is False
        assert "Replay detected" in error

    def test_round_trip_multiple(self):
        """Multiple session envelopes in sequence pass verification."""
        mac_key = secrets.token_bytes(32)

        sender = MockSecureEndpoint()
        sender.mac_key = mac_key

        receiver = MockSecureEndpoint()
        receiver.mac_key = mac_key

        for i in range(5):
            tee = create_session_envelope(sender)
            valid, error = verify_session_envelope(receiver, tee)
            assert valid is True, f"Failed on envelope {i}: {error}"
            assert tee["counter"] == i
