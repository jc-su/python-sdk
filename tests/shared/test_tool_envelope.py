"""Tests for post-bootstrap tool envelope functions.

These test create_encrypted_envelope, verify_encrypted_envelope
using the per-message DEK + AES Key Wrap envelope encryption.
"""

import hashlib
import hmac
import secrets
from typing import Any

import pytest

from mcp.shared.crypto.envelope import EnvelopePayload, envelope_decrypt, envelope_encrypt
from mcp.shared.tee_envelope import (
    create_encrypted_envelope,
    verify_encrypted_envelope,
)

# =============================================================================
# Mock Classes
# =============================================================================


class MockToolEndpoint:
    """Mock SecureEndpoint with kek + counter-based API for tool envelopes."""

    def __init__(self, role: str = "client") -> None:
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

    def create_session_auth(self, counter: int) -> bytes:
        return hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()

    def verify_session_auth(self, counter: int, auth_tag: bytes) -> bool:
        expected = hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        return hmac.compare_digest(expected, auth_tag)

    def wrap_and_encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> EnvelopePayload:
        return envelope_encrypt(self.kek, plaintext, aad=aad)

    def unwrap_and_decrypt(self, payload: EnvelopePayload, *, aad: bytes | None = None) -> bytes:
        return envelope_decrypt(self.kek, payload, aad=aad)


def _make_pair() -> tuple[MockToolEndpoint, MockToolEndpoint]:
    """Create sender/receiver pair with matching keys."""
    sender = MockToolEndpoint(role="client")
    receiver = MockToolEndpoint(role="server")
    receiver.session_id = sender.session_id
    receiver.kek = sender.kek
    receiver.mac_key = sender.mac_key
    return sender, receiver


class MockNoSessionEndpoint:
    """Mock endpoint without kek."""

    def __init__(self) -> None:
        self.kek = None
        self.session_id = None


# =============================================================================
# Tests for create_encrypted_envelope
# =============================================================================


class TestCreateToolRequestEnvelope:
    def test_basic_round_trip(self):
        """Encrypted tool request can be decrypted."""
        sender, receiver = _make_pair()
        params: dict[str, Any] = {"name": "my_tool", "arguments": {"key": "value"}, "_meta": {"tee": {}}}

        tee_dict = create_encrypted_envelope(sender, params)

        assert "counter" in tee_dict
        assert "enc" in tee_dict
        assert tee_dict["counter"] == 0
        # New wire format: no sig_data or entropy
        assert "sig_data" not in tee_dict
        assert "entropy" not in tee_dict
        # enc dict has wrapped_key, iv, ciphertext
        assert "wrapped_key" in tee_dict["enc"]
        assert "iv" in tee_dict["enc"]
        assert "ciphertext" in tee_dict["enc"]

        decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict)

        assert valid is True
        assert error == ""
        assert decrypted is not None
        assert decrypted["name"] == "my_tool"
        assert decrypted["arguments"] == {"key": "value"}
        # _meta should be excluded from encryption
        assert "_meta" not in decrypted

    def test_counter_increments(self):
        """Counter increments on each call."""
        sender, _ = _make_pair()

        tee1 = create_encrypted_envelope(sender, {"name": "tool1"})
        tee2 = create_encrypted_envelope(sender, {"name": "tool2"})

        assert tee1["counter"] == 0
        assert tee2["counter"] == 1

    def test_different_wrapped_key_per_call(self):
        """Each call generates different wrapped_key (per-message DEK)."""
        sender, _ = _make_pair()

        tee1 = create_encrypted_envelope(sender, {"name": "tool"})
        tee2 = create_encrypted_envelope(sender, {"name": "tool"})

        assert tee1["enc"]["wrapped_key"] != tee2["enc"]["wrapped_key"]

    def test_no_kek_raises(self):
        """Raises ValueError without KEK."""
        ep = MockNoSessionEndpoint()

        with pytest.raises(ValueError, match="KEK not established"):
            create_encrypted_envelope(ep, {"name": "tool"})

    def test_meta_excluded_from_encryption(self):
        """_meta field is excluded from encrypted params."""
        sender, receiver = _make_pair()
        params: dict[str, Any] = {"name": "tool", "_meta": {"tee": {"some": "data"}}}

        tee_dict = create_encrypted_envelope(sender, params)
        decrypted, valid, _ = verify_encrypted_envelope(receiver, tee_dict)

        assert valid is True
        assert "_meta" not in decrypted

    def test_empty_params_no_enc(self):
        """Params with only _meta produce no enc field."""
        sender, _ = _make_pair()
        params: dict[str, Any] = {"_meta": {"tee": {}}}

        tee_dict = create_encrypted_envelope(sender, params)

        assert "enc" not in tee_dict


# =============================================================================
# Tests for verify_encrypted_envelope
# =============================================================================


class TestOpenToolRequestEnvelope:
    def test_no_kek_fails(self):
        """Fails if KEK not established."""
        ep = MockNoSessionEndpoint()
        _, valid, error = verify_encrypted_envelope(ep, {"counter": 0})

        assert not valid
        assert "KEK not established" in error

    def test_missing_counter_fails(self):
        """Missing counter fails."""
        _, receiver = _make_pair()

        _, valid, error = verify_encrypted_envelope(receiver, {})

        assert not valid
        assert "Missing or invalid counter" in error

    def test_invalid_counter_type_fails(self):
        """Non-integer counter fails."""
        _, receiver = _make_pair()

        _, valid, error = verify_encrypted_envelope(receiver, {"counter": "not_int"})

        assert not valid
        assert "Missing or invalid counter" in error

    def test_stale_counter_fails(self):
        """Replayed counter fails."""
        sender, receiver = _make_pair()

        tee1 = create_encrypted_envelope(sender, {"name": "tool1"})
        tee2 = create_encrypted_envelope(sender, {"name": "tool2"})

        # Verify tee2 first (counter=1)
        _, valid, _ = verify_encrypted_envelope(receiver, tee2)
        assert valid

        # Try tee1 (counter=0) -- stale
        _, valid, error = verify_encrypted_envelope(receiver, tee1)
        assert not valid
        assert "Replay detected" in error

    def test_wrong_kek_decryption_fails(self):
        """Different KEK (decryption key mismatch) fails."""
        sender, receiver = _make_pair()
        tee_dict = create_encrypted_envelope(sender, {"name": "tool"})

        # Change receiver's kek (but keep session_id the same)
        receiver.kek = secrets.token_bytes(32)

        _, valid, error = verify_encrypted_envelope(receiver, tee_dict)

        assert not valid
        assert "Decryption failed" in error

    def test_counter_tampering_fails(self):
        """Counter is authenticated and cannot be rewritten."""
        sender, receiver = _make_pair()
        tee_dict = create_encrypted_envelope(sender, {"name": "tool"})
        tampered = dict(tee_dict)
        tampered["counter"] = 5

        _, valid, error = verify_encrypted_envelope(receiver, tampered)

        assert not valid
        assert "Decryption failed" in error

    def test_upstream_tokens_tampering_fails(self):
        """Upstream tokens are authenticated alongside the ciphertext."""
        sender, receiver = _make_pair()
        tee_dict = create_encrypted_envelope(
            sender,
            {"name": "tool"},
            upstream_tokens=[{"token": "a", "role": "client", "subject": "cgroup:///cg"}],
        )
        tampered = dict(tee_dict)
        tampered["upstream_tokens"] = [{"token": "b", "role": "client", "subject": "cgroup:///cg"}]

        _, valid, error = verify_encrypted_envelope(receiver, tampered)

        assert not valid
        assert "Decryption failed" in error


# =============================================================================
# Tests for tool response envelope
# =============================================================================


class TestToolResponseEnvelope:
    def test_response_round_trip(self):
        """Tool response can be created and opened."""
        sender, receiver = _make_pair()
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": "hello"}],
            "isError": False,
            "_meta": {"tee": {}},
        }

        tee_dict = create_encrypted_envelope(sender, result)

        assert "enc" in tee_dict
        assert "counter" in tee_dict
        assert "sig_data" not in tee_dict
        # enc has new fields
        assert "wrapped_key" in tee_dict["enc"]

        decrypted, valid, error = verify_encrypted_envelope(receiver, tee_dict)

        assert valid is True
        assert error == ""
        assert decrypted["content"] == [{"type": "text", "text": "hello"}]
        assert "_meta" not in decrypted

    def test_no_kek_create_raises(self):
        """create_encrypted_envelope raises without KEK."""
        ep = MockNoSessionEndpoint()

        with pytest.raises(ValueError, match="KEK not established"):
            create_encrypted_envelope(ep, {"content": []})

    def test_no_kek_open_fails(self):
        """verify_encrypted_envelope fails without KEK."""
        ep = MockNoSessionEndpoint()

        _, valid, error = verify_encrypted_envelope(ep, {"counter": 0})

        assert not valid
        assert "KEK not established" in error

    def test_stale_counter_rejected(self):
        """Replayed counter in response is rejected."""
        sender, receiver = _make_pair()

        tee1 = create_encrypted_envelope(sender, {"content": [], "n": 1})
        tee2 = create_encrypted_envelope(sender, {"content": [], "n": 2})

        # Verify tee2 first
        _, valid, _ = verify_encrypted_envelope(receiver, tee2)
        assert valid

        # Try tee1 -- stale
        _, valid, error = verify_encrypted_envelope(receiver, tee1)
        assert not valid
        assert "Replay detected" in error

    def test_wrong_kek_fails(self):
        """Decryption fails with different KEK."""
        sender, receiver = _make_pair()
        tee_dict = create_encrypted_envelope(sender, {"content": []})
        receiver.kek = secrets.token_bytes(32)

        _, valid, error = verify_encrypted_envelope(receiver, tee_dict)

        assert not valid
        assert "Decryption failed" in error


# =============================================================================
# Full round-trip integration tests
# =============================================================================


class TestToolEnvelopeIntegration:
    def test_bidirectional_communication(self):
        """Client sends request, server sends response -- full round trip."""
        kek = secrets.token_bytes(32)
        session_id = secrets.token_bytes(32)

        client = MockToolEndpoint(role="client")
        client.session_id = session_id
        client.kek = kek

        server = MockToolEndpoint(role="server")
        server.session_id = session_id
        server.kek = kek

        # Client -> Server: tool request
        req_tee = create_encrypted_envelope(client, {
            "name": "add",
            "arguments": {"a": 1, "b": 2},
        })
        req_params, valid, error = verify_encrypted_envelope(server, req_tee)
        assert valid is True
        assert req_params["name"] == "add"

        # Server -> Client: tool response
        resp_tee = create_encrypted_envelope(server, {
            "content": [{"type": "text", "text": "3"}],
            "isError": False,
        })
        resp_result, valid, error = verify_encrypted_envelope(client, resp_tee)
        assert valid is True
        assert resp_result["content"][0]["text"] == "3"

    def test_multiple_round_trips(self):
        """Multiple tool calls within the same session."""
        kek = secrets.token_bytes(32)
        session_id = secrets.token_bytes(32)

        client = MockToolEndpoint(role="client")
        client.session_id = session_id
        client.kek = kek

        server = MockToolEndpoint(role="server")
        server.session_id = session_id
        server.kek = kek

        for i in range(5):
            req_tee = create_encrypted_envelope(client, {"name": f"tool_{i}"})
            req_params, valid, _ = verify_encrypted_envelope(server, req_tee)
            assert valid
            assert req_params["name"] == f"tool_{i}"

            resp_tee = create_encrypted_envelope(server, {"content": [], "i": i})
            resp_result, valid, _ = verify_encrypted_envelope(client, resp_tee)
            assert valid
            assert resp_result["i"] == i
