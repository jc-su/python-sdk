"""Tests for self-check before decrypt in tee_envelope.py.

Self-check RTMR3 is now in open_tool_request_envelope (post-bootstrap),
since open_request_envelope is bootstrap-only (plaintext, no decryption).
"""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from mcp.shared.crypto.envelope import SessionEncryptedMessage
from mcp.shared.tee_envelope import (
    open_request_envelope,
    open_tool_request_envelope,
)


# =============================================================================
# Mock Classes
# =============================================================================


@dataclass
class MockAttestationEvidence:
    """Mock attestation evidence for testing."""

    quote: bytes = b"mock_quote"
    public_key: bytes = b"mock_public_key"
    cgroup: str = "/docker/container"
    rtmr3: bytes = bytes(48)
    timestamp_ms: int = 1234567890000
    nonce: bytes = b"\x00" * 32
    role: str = "client"

    def to_dict(self) -> dict:
        d = {
            "quote": base64.b64encode(self.quote).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "cgroup": self.cgroup,
            "rtmr3": self.rtmr3.hex(),
            "timestamp_ms": self.timestamp_ms,
            "role": self.role,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "MockAttestationEvidence":
        return cls(
            quote=base64.b64decode(data["quote"]),
            public_key=base64.b64decode(data["public_key"]),
            cgroup=data["cgroup"],
            rtmr3=bytes.fromhex(data["rtmr3"]),
            timestamp_ms=data["timestamp_ms"],
            role=data.get("role", "client"),
            nonce=base64.b64decode(data["nonce"]),
        )


@dataclass
class MockVerifyResult:
    valid: bool = True
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = bytes(48)


class MockToolEndpoint:
    """Mock SecureEndpoint with session_key + session binding for tool envelopes."""

    def __init__(self, role: str = "server") -> None:
        self.role = role
        self.session_id: bytes = secrets.token_bytes(32)
        self.session_key: bytes = secrets.token_bytes(32)
        self.mac_key: bytes = secrets.token_bytes(32)
        self._call_counter = 0
        self._peer_call_counter = 0
        self._initial_rtmr3: bytes | None = None

    def derive_sig_data(self, entropy: bytes) -> tuple[bytes, int]:
        counter = self._call_counter
        self._call_counter += 1
        counter_bytes = counter.to_bytes(8, "big")
        sig_data = hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()
        return sig_data, counter

    def verify_derived_sig_data(self, entropy: bytes, counter: int) -> bytes:
        if counter < self._peer_call_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._peer_call_counter}")
        self._peer_call_counter = counter + 1
        counter_bytes = counter.to_bytes(8, "big")
        return hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()

    def encrypt_message(self, plaintext: bytes) -> tuple[bytes, bytes]:
        from mcp.shared.crypto import aes
        result = aes.encrypt(self.session_key, plaintext)
        return result.nonce, result.ciphertext

    def decrypt_message(self, nonce: bytes, ciphertext: bytes) -> bytes:
        from mcp.shared.crypto import aes
        return aes.decrypt(self.session_key, nonce, ciphertext)


class MockBootstrapEndpoint:
    """Mock SecureEndpoint for bootstrap (no session_key, no decryption)."""

    def __init__(self, role: str = "server") -> None:
        self.role = role
        self.peers: dict = {}
        self.private_key = "mock_private_key"
        self.session_id: bytes | None = None
        self._verify_valid = True
        self._verify_error = ""
        self._initial_rtmr3: bytes | None = None

    def create_evidence(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer(
        self,
        evidence: object,
        expected_nonce: bytes | None = None,
        peer_role: str = "default",
        allowed_rtmr3: list[str] | None = None,
    ) -> MockVerifyResult:
        return MockVerifyResult(valid=self._verify_valid, error=self._verify_error)


def _make_tool_tee_dict(endpoint: MockToolEndpoint) -> dict:
    """Create a valid tool request tee_dict with encrypted data."""
    entropy = secrets.token_bytes(32)
    sig_data, counter = endpoint.derive_sig_data(entropy)

    plaintext = json.dumps({"name": "test_tool", "arguments": {"key": "value"}}, separators=(",", ":")).encode()
    nonce, ciphertext = endpoint.encrypt_message(plaintext)

    return {
        "sig_data": base64.b64encode(sig_data).decode(),
        "entropy": base64.b64encode(entropy).decode(),
        "counter": counter,
        "enc": SessionEncryptedMessage(nonce=nonce, ciphertext=ciphertext).to_dict(),
    }


class TestSelfCheck:
    """Tests for self-check RTMR3 before decrypt in open_tool_request_envelope."""

    def test_self_check_passes_when_rtmr3_unchanged(self) -> None:
        """Self-check passes when current RTMR3 matches initial."""
        initial_rtmr3 = bytes(range(48))

        # Sender creates the envelope
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        # Receiver verifies (same session keys)
        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=initial_rtmr3):
            decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert valid is True
        assert error == ""
        assert decrypted is not None
        assert decrypted["name"] == "test_tool"

    def test_self_check_fails_when_rtmr3_changed(self) -> None:
        """Self-check refuses to decrypt when RTMR3 has changed."""
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(range(1, 49))

        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert not valid
        assert "Self-check failed" in error
        assert "container integrity changed" in error

    def test_self_check_skipped_when_no_initial_rtmr3(self) -> None:
        """Self-check is skipped when _initial_rtmr3 is None."""
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        assert receiver._initial_rtmr3 is None

        decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert valid is True
        assert decrypted is not None

    def test_self_check_skipped_when_no_encryption(self) -> None:
        """Self-check is skipped for requests without enc field."""
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(range(1, 49))

        sender = MockToolEndpoint(role="client")
        # Create tee_dict without enc
        entropy = secrets.token_bytes(32)
        sig_data, counter = sender.derive_sig_data(entropy)
        tee_dict = {
            "sig_data": base64.b64encode(sig_data).decode(),
            "entropy": base64.b64encode(entropy).decode(),
            "counter": counter,
        }

        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        # Should succeed — self-check only runs when enc is present
        assert valid is True
        assert decrypted is None  # No enc to decrypt

    def test_self_check_graceful_when_rtmr3_read_fails(self) -> None:
        """Self-check continues gracefully if RTMR3 read fails."""
        initial_rtmr3 = bytes(range(48))

        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", side_effect=Exception("read failed")):
            decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        # Read failure is non-fatal — decryption proceeds
        assert valid is True
        assert "Self-check" not in error

    def test_self_check_blocks_before_decryption(self) -> None:
        """Verify self-check blocks BEFORE attempting decryption."""
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(range(1, 49))

        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.session_id = sender.session_id
        receiver.session_key = sender.session_key
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

        # Self-check should have returned BEFORE decryption
        assert not valid
        assert "Self-check" in error
        assert decrypted is None  # No decryption happened


class TestSelfCheckBootstrapUnaffected:
    """Bootstrap open_request_envelope doesn't do decryption, so no self-check needed."""

    def test_bootstrap_ignores_enc_field(self) -> None:
        """open_request_envelope (bootstrap) doesn't decrypt even if enc is present."""
        endpoint = MockBootstrapEndpoint()
        endpoint._initial_rtmr3 = bytes(range(48))

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        # Even with enc present, bootstrap doesn't decrypt
        tee_dict["enc"] = {"nonce": "abc", "ciphertext": "def"}

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict)

        # Bootstrap verification passes (no decryption)
        assert valid is True
        assert error == ""


class TestSelfCheckWithVerifyFailure:
    """Session binding should fail before self-check runs."""

    def test_session_binding_failure_prevents_self_check(self) -> None:
        """If session binding fails, self-check should never run."""
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        # Receiver with DIFFERENT session_id — binding will fail
        receiver = MockToolEndpoint(role="server")
        receiver._initial_rtmr3 = bytes(48)

        rtmr3_called = False

        def mock_get_rtmr3(*args, **kwargs):
            nonlocal rtmr3_called
            rtmr3_called = True
            return bytes(48)

        with patch("mcp.shared.tdx.get_container_rtmr3", side_effect=mock_get_rtmr3):
            _, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert not valid
        # Session binding mismatch prevents reaching self-check
        assert not rtmr3_called
