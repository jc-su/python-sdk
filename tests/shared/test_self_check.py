"""Tests for self-check before decrypt in verify_encrypted_envelope."""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from unittest.mock import patch

from mcp.shared.crypto.envelope import EnvelopePayload, envelope_encrypt
from mcp.shared.tee_envelope import (
    verify_bootstrap_envelope,
    verify_encrypted_envelope,
)

# =============================================================================
# Mock Classes
# =============================================================================


@dataclass
class MockAttestationEvidence:
    quote: bytes = b"mock_quote"
    public_key: bytes = b"mock_public_key"
    cgroup: str = "/docker/container"
    rtmr3: bytes = bytes(48)
    timestamp_ms: int = 1234567890000
    nonce: bytes = b"\x00" * 32
    role: str = "client"

    def to_dict(self) -> dict:
        return {
            "quote": base64.b64encode(self.quote).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "cgroup": self.cgroup,
            "rtmr3": self.rtmr3.hex(),
            "timestamp_ms": self.timestamp_ms,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: dict) -> MockAttestationEvidence:
        return cls(
            quote=base64.b64decode(data["quote"]),
            public_key=base64.b64decode(data["public_key"]),
            cgroup=data["cgroup"],
            rtmr3=bytes.fromhex(data["rtmr3"]),
            timestamp_ms=data["timestamp_ms"],
            role=data.get("role", "client"),
            nonce=base64.b64decode(data.get("sig_data", data.get("nonce", ""))),
        )


@dataclass
class MockVerifyResult:
    valid: bool = True
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = bytes(48)


class MockToolEndpoint:
    """Mock SecureEndpoint with KEK for envelope encryption."""

    def __init__(self, role: str = "server") -> None:
        self.role = role
        self.session_id: bytes = secrets.token_bytes(32)
        self.kek: bytes = secrets.token_bytes(32)
        self.mac_key: bytes = secrets.token_bytes(32)
        self._send_counter = 0
        self._recv_counter = 0
        self._initial_rtmr3: bytes | None = None

    def next_send_counter(self) -> int:
        counter = self._send_counter
        self._send_counter += 1
        return counter

    def verify_recv_counter(self, counter: int) -> None:
        if counter < self._recv_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._recv_counter}")
        self._recv_counter = counter + 1

    def wrap_and_encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> EnvelopePayload:
        return envelope_encrypt(self.kek, plaintext, aad=aad)

    def unwrap_and_decrypt(self, payload: EnvelopePayload, *, aad: bytes | None = None) -> bytes:
        from mcp.shared.crypto.envelope import envelope_decrypt

        return envelope_decrypt(self.kek, payload, aad=aad)


class MockBootstrapEndpoint:
    """Mock SecureEndpoint for bootstrap (no KEK)."""

    def __init__(self, role: str = "server") -> None:
        self.role = role
        self.peers: dict = {}
        self.session_id: bytes | None = None
        self._verify_valid = True
        self._verify_error = ""
        self._initial_rtmr3: bytes | None = None

    def create_attestation(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer_attestation(
        self,
        evidence: object,
        expected_nonce: bytes | None = None,
        peer_role: str = "default",
        allowed_rtmr3: list[str] | None = None,
    ) -> MockVerifyResult:
        return MockVerifyResult(valid=self._verify_valid, error=self._verify_error)


def _make_tool_tee_dict(endpoint: MockToolEndpoint) -> dict:
    """Create a valid encrypted envelope tee_dict."""
    counter = endpoint.next_send_counter()
    plaintext = json.dumps({"name": "test_tool", "arguments": {"key": "value"}}, separators=(",", ":")).encode()
    enc_payload = endpoint.wrap_and_encrypt(plaintext)

    return {
        "counter": counter,
        "enc": enc_payload.to_dict(),
    }


class TestSelfCheck:
    """Tests for self-check RTMR3 before decrypt in verify_encrypted_envelope."""

    def test_self_check_passes_when_rtmr3_unchanged(self) -> None:
        initial_rtmr3 = bytes(range(48))
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=initial_rtmr3):
            decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)

        assert valid is True
        assert error == ""
        assert decrypted is not None
        assert decrypted["name"] == "test_tool"

    def test_self_check_fails_when_rtmr3_changed(self) -> None:
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(reversed(range(48)))

        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)

        assert valid is False
        assert "Self-check failed" in error
        assert decrypted is None

    def test_self_check_skipped_when_no_initial_rtmr3(self) -> None:
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = None  # No initial → skip check

        decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)
        assert valid is True
        assert decrypted is not None

    def test_self_check_skipped_when_no_encryption(self) -> None:
        """Self-check only runs when enc is present."""
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(reversed(range(48)))

        sender = MockToolEndpoint(role="client")
        counter = sender.next_send_counter()
        tee_dict = {"counter": counter}

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)

        assert valid is True  # No enc → no self-check

    def test_self_check_graceful_when_rtmr3_read_fails(self) -> None:
        initial_rtmr3 = bytes(range(48))
        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", side_effect=OSError("read failed")):
            decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)

        assert valid is True  # Graceful degradation
        assert decrypted is not None

    def test_self_check_blocks_before_decryption(self) -> None:
        """When RTMR3 changed, decryption must NOT happen."""
        initial_rtmr3 = bytes(range(48))
        changed_rtmr3 = bytes(reversed(range(48)))

        sender = MockToolEndpoint(role="client")
        tee_dict = _make_tool_tee_dict(sender)

        receiver = MockToolEndpoint(role="server")
        receiver.kek = sender.kek
        receiver._initial_rtmr3 = initial_rtmr3

        with patch("mcp.shared.tdx.get_container_rtmr3", return_value=changed_rtmr3):
            decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict, self_check_rtmr3=True)

        assert valid is False
        assert decrypted is None


class TestSelfCheckBootstrapUnaffected:
    """Bootstrap verify_bootstrap_envelope doesn't do decryption, so no self-check needed."""

    def test_bootstrap_ignores_enc_field(self) -> None:
        """verify_bootstrap_envelope (bootstrap) doesn't decrypt even if enc is present."""
        endpoint = MockBootstrapEndpoint(role="server")
        endpoint._initial_rtmr3 = bytes(range(48))
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["enc"] = {"wrapped_key": "abc", "iv": "def", "ciphertext": "ghi"}

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            valid, error = verify_bootstrap_envelope(endpoint, tee_dict)

        assert valid is True
        assert error == ""
