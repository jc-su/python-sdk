"""Tests for session envelope functions (create_session_envelope, verify_session_envelope)."""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

import pytest

from mcp.shared.tee_envelope import (
    create_session_envelope,
    verify_session_envelope,
)


# =============================================================================
# Mock Classes (same pattern as test_tee_envelope.py)
# =============================================================================


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing session envelopes."""

    def __init__(self, role: str = "server"):
        self.role = role
        self.session_id: bytes | None = None
        self._call_counter = 0
        self._peer_call_counter = 0

    def derive_sig_data(self, entropy: bytes) -> tuple[bytes, int]:
        if self.session_id is None:
            raise ValueError("Session not established")
        counter = self._call_counter
        self._call_counter += 1
        counter_bytes = counter.to_bytes(8, "big")
        sig_data = hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()
        return sig_data, counter

    def verify_derived_sig_data(self, entropy: bytes, counter: int) -> bytes:
        if self.session_id is None:
            raise ValueError("Session not established")
        if counter < self._peer_call_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._peer_call_counter}")
        self._peer_call_counter = counter + 1
        counter_bytes = counter.to_bytes(8, "big")
        return hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()


class MockEndpointNoSession:
    """Mock endpoint without session_id."""

    def __init__(self):
        self.session_id = None


# =============================================================================
# Tests for create_session_envelope
# =============================================================================


class TestCreateSessionEnvelope:
    def test_basic_session_envelope(self):
        """Session envelope includes sig_data and timestamp."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee = create_session_envelope(endpoint)

        assert "sig_data" in tee
        assert "timestamp_ms" in tee
        assert "entropy" in tee
        assert "counter" in tee
        assert tee["counter"] == 0

    def test_includes_trust_metadata(self):
        """Trust metadata is included when provided."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

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
        endpoint.session_id = secrets.token_bytes(32)

        tee = create_session_envelope(endpoint)

        assert "server_trust" not in tee

    def test_counter_increments(self):
        """Counter increments per call."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee1 = create_session_envelope(endpoint)
        tee2 = create_session_envelope(endpoint)

        assert tee1["counter"] == 0
        assert tee2["counter"] == 1

    def test_without_session_no_binding(self):
        """Without session_id, no entropy/counter in envelope."""
        endpoint = MockEndpointNoSession()

        tee = create_session_envelope(endpoint)

        assert "sig_data" in tee
        assert "timestamp_ms" in tee
        assert "entropy" not in tee
        assert "counter" not in tee


# =============================================================================
# Tests for verify_session_envelope
# =============================================================================


class TestVerifySessionEnvelope:
    def test_valid_session_envelope(self):
        """Valid session-bound envelope passes verification."""
        session_id = secrets.token_bytes(32)

        sender = MockSecureEndpoint()
        sender.session_id = session_id

        receiver = MockSecureEndpoint()
        receiver.session_id = session_id

        tee = create_session_envelope(sender)
        valid, error = verify_session_envelope(receiver, tee)

        assert valid is True
        assert error == ""

    def test_missing_sig_data(self):
        """Missing sig_data fails verification."""
        endpoint = MockEndpointNoSession()

        valid, error = verify_session_envelope(endpoint, {"timestamp_ms": 123})

        assert valid is False
        assert "sig_data" in error

    def test_invalid_sig_data_base64(self):
        """Malformed base64 in sig_data is rejected."""
        endpoint = MockEndpointNoSession()

        valid, error = verify_session_envelope(endpoint, {"sig_data": "!!!bad!!!"})

        assert valid is False
        assert "Invalid base64" in error

    def test_missing_session_binding_when_session_exists(self):
        """Missing entropy/counter when session exists fails."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee = {"sig_data": base64.b64encode(b"x" * 32).decode()}
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is False
        assert "Missing session binding" in error

    def test_partial_session_binding_rejected(self):
        """Having entropy but not counter (or vice versa) fails."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee = {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": base64.b64encode(b"y" * 32).decode(),
        }
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is False
        assert "Both entropy and counter" in error

    def test_session_binding_before_establishment(self):
        """Session binding fields before session establishment fails."""
        endpoint = MockEndpointNoSession()

        tee = {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": base64.b64encode(b"y" * 32).decode(),
            "counter": 0,
        }
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is False
        assert "before session establishment" in error

    def test_invalid_counter_type(self):
        """Non-integer counter fails."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee = {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": base64.b64encode(b"y" * 32).decode(),
            "counter": "not_int",
        }
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is False
        assert "Invalid counter type" in error

    def test_invalid_entropy_base64(self):
        """Malformed base64 in entropy is rejected."""
        endpoint = MockSecureEndpoint()
        endpoint.session_id = secrets.token_bytes(32)

        tee = {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": "!!!bad!!!",
            "counter": 0,
        }
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is False
        assert "Invalid base64 in entropy" in error

    def test_stale_counter_rejected(self):
        """Replayed counter is rejected."""
        session_id = secrets.token_bytes(32)

        sender = MockSecureEndpoint()
        sender.session_id = session_id

        receiver = MockSecureEndpoint()
        receiver.session_id = session_id

        tee1 = create_session_envelope(sender)
        tee2 = create_session_envelope(sender)

        # Verify second first (counter=1)
        valid, _ = verify_session_envelope(receiver, tee2)
        assert valid is True

        # Verify first (counter=0) — stale
        valid, error = verify_session_envelope(receiver, tee1)
        assert valid is False
        assert "Session binding failed" in error

    def test_without_session_no_binding_accepted(self):
        """Without session, no binding fields is acceptable."""
        endpoint = MockEndpointNoSession()

        tee = {"sig_data": base64.b64encode(b"x" * 32).decode()}
        valid, error = verify_session_envelope(endpoint, tee)

        assert valid is True
        assert error == ""
