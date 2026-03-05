"""Tests for post-bootstrap tool envelope functions.

These test create_tool_request_envelope, open_tool_request_envelope,
create_tool_response_envelope, open_tool_response_envelope.
"""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

import pytest

from mcp.shared.tee_envelope import (
    create_tool_request_envelope,
    create_tool_response_envelope,
    open_tool_request_envelope,
    open_tool_response_envelope,
)


# =============================================================================
# Mock Classes
# =============================================================================


class MockToolEndpoint:
    """Mock SecureEndpoint with session_key + session binding for tool envelopes."""

    def __init__(self, role: str = "client") -> None:
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


def _make_pair() -> tuple[MockToolEndpoint, MockToolEndpoint]:
    """Create sender/receiver pair with matching session keys."""
    sender = MockToolEndpoint(role="client")
    receiver = MockToolEndpoint(role="server")
    receiver.session_id = sender.session_id
    receiver.session_key = sender.session_key
    receiver.mac_key = sender.mac_key
    return sender, receiver


class MockNoSessionEndpoint:
    """Mock endpoint without session_key."""

    def __init__(self) -> None:
        self.session_key = None
        self.session_id = None


# =============================================================================
# Tests for create_tool_request_envelope
# =============================================================================


class TestCreateToolRequestEnvelope:
    def test_basic_round_trip(self):
        """Encrypted tool request can be decrypted."""
        sender, receiver = _make_pair()
        params = {"name": "my_tool", "arguments": {"key": "value"}, "_meta": {"tee": {}}}

        tee_dict = create_tool_request_envelope(sender, params)

        assert "sig_data" in tee_dict
        assert "entropy" in tee_dict
        assert "counter" in tee_dict
        assert "enc" in tee_dict
        assert tee_dict["counter"] == 0

        decrypted, valid, error = open_tool_request_envelope(receiver, tee_dict)

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

        tee1 = create_tool_request_envelope(sender, {"name": "tool1"})
        tee2 = create_tool_request_envelope(sender, {"name": "tool2"})

        assert tee1["counter"] == 0
        assert tee2["counter"] == 1

    def test_different_entropy_per_call(self):
        """Each call generates different entropy."""
        sender, _ = _make_pair()

        tee1 = create_tool_request_envelope(sender, {"name": "tool"})
        tee2 = create_tool_request_envelope(sender, {"name": "tool"})

        assert tee1["entropy"] != tee2["entropy"]

    def test_no_session_raises(self):
        """Raises ValueError without session key."""
        ep = MockNoSessionEndpoint()

        with pytest.raises(ValueError, match="Session key not established"):
            create_tool_request_envelope(ep, {"name": "tool"})

    def test_meta_excluded_from_encryption(self):
        """_meta field is excluded from encrypted params."""
        sender, receiver = _make_pair()
        params = {"name": "tool", "_meta": {"tee": {"some": "data"}}}

        tee_dict = create_tool_request_envelope(sender, params)
        decrypted, valid, _ = open_tool_request_envelope(receiver, tee_dict)

        assert valid is True
        assert "_meta" not in decrypted

    def test_empty_params_no_enc(self):
        """Params with only _meta produce no enc field."""
        sender, _ = _make_pair()
        params = {"_meta": {"tee": {}}}

        tee_dict = create_tool_request_envelope(sender, params)

        assert "enc" not in tee_dict


# =============================================================================
# Tests for open_tool_request_envelope
# =============================================================================


class TestOpenToolRequestEnvelope:
    def test_no_session_key_fails(self):
        """Fails if session key not established."""
        ep = MockNoSessionEndpoint()
        _, valid, error = open_tool_request_envelope(ep, {"sig_data": "x"})

        assert not valid
        assert "Session key not established" in error

    def test_missing_sig_data_fails(self):
        """Missing sig_data fails."""
        sender, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {"entropy": "x", "counter": 0})

        assert not valid
        assert "Missing sig_data" in error

    def test_missing_entropy_fails(self):
        """Missing entropy fails."""
        sender, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "counter": 0,
        })

        assert not valid
        assert "Missing session binding" in error

    def test_missing_counter_fails(self):
        """Missing counter fails."""
        sender, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": base64.b64encode(b"y" * 32).decode(),
        })

        assert not valid
        assert "Missing session binding" in error

    def test_invalid_counter_type_fails(self):
        """Non-integer counter fails."""
        sender, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": base64.b64encode(b"y" * 32).decode(),
            "counter": "not_int",
        })

        assert not valid
        assert "Invalid counter type" in error

    def test_sig_data_mismatch_fails(self):
        """Tampered sig_data fails."""
        sender, receiver = _make_pair()
        tee_dict = create_tool_request_envelope(sender, {"name": "tool"})

        # Tamper sig_data
        tee_dict["sig_data"] = base64.b64encode(b"tampered" * 4).decode()

        _, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert not valid
        assert "sig_data mismatch" in error

    def test_stale_counter_fails(self):
        """Replayed counter fails."""
        sender, receiver = _make_pair()

        tee1 = create_tool_request_envelope(sender, {"name": "tool1"})
        tee2 = create_tool_request_envelope(sender, {"name": "tool2"})

        # Verify tee2 first (counter=1)
        _, valid, _ = open_tool_request_envelope(receiver, tee2)
        assert valid

        # Try tee1 (counter=0) — stale
        _, valid, error = open_tool_request_envelope(receiver, tee1)
        assert not valid
        assert "Session binding failed" in error

    def test_wrong_session_key_decryption_fails(self):
        """Different session_key (decryption key mismatch) fails."""
        sender, receiver = _make_pair()
        tee_dict = create_tool_request_envelope(sender, {"name": "tool"})

        # Change receiver's session_key (but keep session_id the same for binding)
        receiver.session_key = secrets.token_bytes(32)

        _, valid, error = open_tool_request_envelope(receiver, tee_dict)

        assert not valid
        assert "Decryption failed" in error

    def test_invalid_base64_sig_data(self):
        """Malformed base64 in sig_data rejected."""
        _, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {
            "sig_data": "!!!bad!!!",
            "entropy": base64.b64encode(b"y" * 32).decode(),
            "counter": 0,
        })

        assert not valid
        assert "Invalid base64 in sig_data" in error

    def test_invalid_base64_entropy(self):
        """Malformed base64 in entropy rejected."""
        _, receiver = _make_pair()

        _, valid, error = open_tool_request_envelope(receiver, {
            "sig_data": base64.b64encode(b"x" * 32).decode(),
            "entropy": "!!!bad!!!",
            "counter": 0,
        })

        assert not valid
        assert "Invalid base64 in entropy" in error


# =============================================================================
# Tests for tool response envelope
# =============================================================================


class TestToolResponseEnvelope:
    def test_response_round_trip(self):
        """Tool response can be created and opened."""
        sender, receiver = _make_pair()
        result = {"content": [{"type": "text", "text": "hello"}], "isError": False, "_meta": {"tee": {}}}

        tee_dict = create_tool_response_envelope(sender, result)

        assert "sig_data" in tee_dict
        assert "enc" in tee_dict
        assert "counter" in tee_dict

        decrypted, valid, error = open_tool_response_envelope(receiver, tee_dict)

        assert valid is True
        assert error == ""
        assert decrypted["content"] == [{"type": "text", "text": "hello"}]
        assert "_meta" not in decrypted

    def test_no_session_key_create_raises(self):
        """create_tool_response_envelope raises without session key."""
        ep = MockNoSessionEndpoint()

        with pytest.raises(ValueError, match="Session key not established"):
            create_tool_response_envelope(ep, {"content": []})

    def test_no_session_key_open_fails(self):
        """open_tool_response_envelope fails without session key."""
        ep = MockNoSessionEndpoint()

        _, valid, error = open_tool_response_envelope(ep, {"sig_data": "x"})

        assert not valid
        assert "Session key not established" in error

    def test_missing_sig_data_fails(self):
        """Missing sig_data in response fails."""
        _, receiver = _make_pair()

        _, valid, error = open_tool_response_envelope(receiver, {"entropy": "x", "counter": 0})

        assert not valid
        assert "Missing sig_data" in error

    def test_sig_data_mismatch_fails(self):
        """Tampered sig_data in response fails."""
        sender, receiver = _make_pair()
        tee_dict = create_tool_response_envelope(sender, {"content": []})
        tee_dict["sig_data"] = base64.b64encode(b"tampered" * 4).decode()

        _, valid, error = open_tool_response_envelope(receiver, tee_dict)

        assert not valid
        assert "sig_data mismatch" in error

    def test_stale_counter_rejected(self):
        """Replayed counter in response is rejected."""
        sender, receiver = _make_pair()

        tee1 = create_tool_response_envelope(sender, {"content": [], "n": 1})
        tee2 = create_tool_response_envelope(sender, {"content": [], "n": 2})

        # Verify tee2 first
        _, valid, _ = open_tool_response_envelope(receiver, tee2)
        assert valid

        # Try tee1 — stale
        _, valid, error = open_tool_response_envelope(receiver, tee1)
        assert not valid
        assert "Session binding failed" in error

    def test_wrong_session_key_fails(self):
        """Decryption fails with different session key."""
        sender, receiver = _make_pair()
        tee_dict = create_tool_response_envelope(sender, {"content": []})
        receiver.session_key = secrets.token_bytes(32)

        _, valid, error = open_tool_response_envelope(receiver, tee_dict)

        assert not valid
        assert "Decryption failed" in error


# =============================================================================
# Full round-trip integration tests
# =============================================================================


class TestToolEnvelopeIntegration:
    def test_bidirectional_communication(self):
        """Client sends request, server sends response — full round trip."""
        session_id = secrets.token_bytes(32)
        session_key = secrets.token_bytes(32)

        client = MockToolEndpoint(role="client")
        client.session_id = session_id
        client.session_key = session_key

        server = MockToolEndpoint(role="server")
        server.session_id = session_id
        server.session_key = session_key

        # Client → Server: tool request
        req_tee = create_tool_request_envelope(client, {
            "name": "add",
            "arguments": {"a": 1, "b": 2},
        })
        req_params, valid, error = open_tool_request_envelope(server, req_tee)
        assert valid is True
        assert req_params["name"] == "add"

        # Server → Client: tool response
        resp_tee = create_tool_response_envelope(server, {
            "content": [{"type": "text", "text": "3"}],
            "isError": False,
        })
        resp_result, valid, error = open_tool_response_envelope(client, resp_tee)
        assert valid is True
        assert resp_result["content"][0]["text"] == "3"

    def test_multiple_round_trips(self):
        """Multiple tool calls within the same session."""
        session_id = secrets.token_bytes(32)
        session_key = secrets.token_bytes(32)

        client = MockToolEndpoint(role="client")
        client.session_id = session_id
        client.session_key = session_key

        server = MockToolEndpoint(role="server")
        server.session_id = session_id
        server.session_key = session_key

        for i in range(5):
            req_tee = create_tool_request_envelope(client, {"name": f"tool_{i}"})
            req_params, valid, _ = open_tool_request_envelope(server, req_tee)
            assert valid
            assert req_params["name"] == f"tool_{i}"

            resp_tee = create_tool_response_envelope(server, {"content": [], "i": i})
            resp_result, valid, _ = open_tool_response_envelope(client, resp_tee)
            assert valid
            assert resp_result["i"] == i
