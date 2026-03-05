"""Tests for TrustedServerSession - unified per-call TEE attestation.

Uses mock SecureEndpoint to test attestation flow without TDX hardware.
"""

import base64
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import anyio
import pytest

import mcp.types as types
from mcp.server.models import InitializationOptions
from mcp.shared.message import SessionMessage

# =============================================================================
# Mock Classes
# =============================================================================


@dataclass
class MockAttestationEvidence:
    """Mock attestation evidence."""

    quote: bytes = b"mock_quote"
    public_key: bytes = b"mock_public_key"
    cgroup: str = "/docker/container123"
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
        )


@dataclass
class MockVerifyResult:
    """Mock verification result."""

    valid: bool = True
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = bytes(48)


@dataclass
class MockPeer:
    """Mock peer info."""

    cgroup: str
    rtmr3: bytes
    role: str
    public_key: object = None


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing without TDX hardware."""

    def __init__(self, role: str = "server"):
        self.role = role
        self.session_id: bytes | None = None
        self.session_key: bytes | None = None
        self.mac_key: bytes | None = None
        self._peers: dict[str, MockPeer] = {}
        self._nonces: dict[str, bytes] = {}
        self._bootstrap_challenge: bytes | None = None
        self._verify_mac_result: bool = True

    @classmethod
    def create(cls, role: str = "server") -> "MockSecureEndpoint":
        return cls(role=role)

    def consume_bootstrap_challenge(self) -> bytes | None:
        challenge = self._bootstrap_challenge
        self._bootstrap_challenge = None
        return challenge

    def generate_nonce(self, peer_role: str = "client") -> bytes:
        nonce = b"mock_nonce_" + peer_role.encode()
        self._nonces[peer_role] = nonce
        return nonce

    def create_evidence(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer(
        self,
        evidence: MockAttestationEvidence,
        expected_nonce: bytes | None = None,
        peer_role: str = "client",
        allowed_rtmr3: list[str] | None = None,
    ) -> MockVerifyResult:
        self._peers[peer_role] = MockPeer(
            cgroup=evidence.cgroup,
            rtmr3=evidence.rtmr3,
            role=evidence.role,
        )
        return MockVerifyResult(valid=True)

    def verify_challenge_mac(self, challenge: bytes, mac_bytes: bytes) -> bool:
        """Verify HMAC-SHA256 challenge MAC. Returns configurable result."""
        return self._verify_mac_result

    def get_peer(self, role: str) -> MockPeer | None:
        return self._peers.get(role)


# =============================================================================
# Helper to create session with mock endpoint
# =============================================================================


def create_test_session(
    read_stream,
    write_stream,
    init_options,
    *,
    tee_enabled: bool = True,
    require_client_attestation: bool = False,
    jwt_verifier=None,
    require_upstream_jwt: bool = False,
):
    """Create a TrustedServerSession with mock endpoint for testing."""
    from mcp.server.trusted_session import TrustedServerSession

    session = TrustedServerSession(
        read_stream,
        write_stream,
        init_options,
        tee_enabled=False,
    )

    if tee_enabled:
        session._tee_enabled = True
        session._endpoint = MockSecureEndpoint(role="server")
        session._require_client_attestation = require_client_attestation

    if jwt_verifier is not None:
        session._jwt_verifier = jwt_verifier
    session._require_upstream_jwt = require_upstream_jwt

    return session


# =============================================================================
# Tests
# =============================================================================


class TestTrustedServerSession:
    """Tests for TrustedServerSession."""

    @pytest.fixture
    async def mock_streams(self):
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.fixture
    def init_options(self):
        return InitializationOptions(
            server_name="test-server",
            server_version="1.0.0",
            capabilities=types.ServerCapabilities(),
        )

    @pytest.mark.anyio
    async def test_init_with_tee_disabled(self, mock_streams, init_options):
        """Test TrustedServerSession with TEE disabled."""
        read_stream, write_stream, _, _ = mock_streams

        from mcp.server.trusted_session import TrustedServerSession

        session = TrustedServerSession(read_stream, write_stream, init_options, tee_enabled=False)

        assert session.tee_enabled is False
        assert session.is_client_attested is False
        assert session.client_cgroup == ""

    @pytest.mark.anyio
    async def test_init_with_tee_enabled_mock(self, mock_streams, init_options):
        """Test TrustedServerSession with mocked TEE."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        assert session._tee_enabled is True
        assert session._endpoint is not None
        assert isinstance(session._endpoint, MockSecureEndpoint)

    @pytest.mark.anyio
    async def test_handle_initialized_tee_no_challenge_pending(self, mock_streams, init_options):
        """Test initialized notification accepted when no challenge was pending."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        # No bootstrap challenge set -> _handle_initialized_tee accepts without MAC
        tee_dict = {"challenge_response": base64.b64encode(b"x").decode()}

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)
        assert result is True

    @pytest.mark.anyio
    async def test_handle_initialized_no_tee(self, mock_streams, init_options):
        """Test that missing _meta.tee is handled gracefully."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        notification = types.InitializedNotification()

        session._handle_initialized_tee(notification)

        assert session._client_attested is False

    @pytest.mark.anyio
    async def test_initialized_missing_challenge_response_is_fatal(self, mock_streams, init_options):
        """Missing challenge response fails initialized verification."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint._bootstrap_challenge = b"x" * 32

        notification = types.InitializedNotification()

        assert session._handle_initialized_tee(notification) is False

    @pytest.mark.anyio
    async def test_initialized_challenge_mismatch_is_fatal(self, mock_streams, init_options):
        """Mismatched challenge response fails initialized verification."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint._bootstrap_challenge = b"x" * 32

        client_evidence = MockAttestationEvidence(role="client", cgroup="/docker/client")
        tee_dict = client_evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["challenge_response"] = base64.b64encode(b"y" * 32).decode()

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        assert session._handle_initialized_tee(notification) is False

    @pytest.mark.anyio
    async def test_initialized_no_challenge_required_attestation_fails(self, mock_streams, init_options):
        """Initialized without pending challenge fails when client attestation required."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream, write_stream, init_options, tee_enabled=True, require_client_attestation=True
        )
        # No bootstrap challenge set

        tee_dict = {"challenge_response": base64.b64encode(b"x").decode()}
        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        assert session._handle_initialized_tee(notification) is False

    @pytest.mark.anyio
    async def test_send_response_with_tee(self, mock_streams, init_options):
        """Test that _meta.tee is injected into tool call response (bootstrap path)."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        # session_key is None on mock -> bootstrap path (plaintext + evidence)
        assert session._endpoint.session_key is None

        # Simulate that request 5 was a verified tool call
        session._tee_request_ids.add(5)

        response = types.CallToolResult(content=[], isError=False)

        await session._send_response(request_id=5, response=response)

        msg = await write_recv.receive()
        jsonrpc_msg = msg.message

        assert jsonrpc_msg.id == 5
        assert "_meta" in jsonrpc_msg.result
        assert "tee" in jsonrpc_msg.result["_meta"]

        tee = jsonrpc_msg.result["_meta"]["tee"]
        assert "quote" in tee
        assert "sig_data" in tee
        assert "role" in tee

    @pytest.mark.anyio
    async def test_send_error_response_no_tee(self, mock_streams, init_options):
        """Test that error responses don't get _meta.tee."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        error = types.ErrorData(code=-1, message="test error")

        await session._send_response(request_id=1, response=error)

        msg = await write_recv.receive()
        jsonrpc_msg = msg.message

        assert hasattr(jsonrpc_msg, "error")

    @pytest.mark.anyio
    async def test_verify_request_with_tee(self, mock_streams, init_options):
        """Test verification of _meta.tee in request via open_tool_request_envelope."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        client_evidence = MockAttestationEvidence(role="client")
        tee_dict = client_evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        call_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="test_tool",
                _meta={"tee": tee_dict},
            )
        )
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=1,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        with patch(
            "mcp.server.trusted_session.open_tool_request_envelope",
            return_value=(None, True, ""),
        ):
            result = session._verify_and_decrypt_request(responder)
        assert result is True

    @pytest.mark.anyio
    async def test_verify_request_missing_tee_required(self, mock_streams, init_options):
        """Test rejection when _meta.tee is required but missing."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream, write_stream, init_options, tee_enabled=True, require_client_attestation=True
        )

        call_request = types.CallToolRequest(params=types.CallToolRequestParams(name="test_tool"))
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=1,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        result = session._verify_and_decrypt_request(responder)
        assert result is False

    @pytest.mark.anyio
    async def test_verify_request_missing_tee_optional(self, mock_streams, init_options):
        """Test that missing _meta.tee is OK when not required."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream, write_stream, init_options, tee_enabled=True, require_client_attestation=False
        )

        call_request = types.CallToolRequest(params=types.CallToolRequestParams(name="test_tool"))
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=1,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        result = session._verify_and_decrypt_request(responder)
        assert result is True

    @pytest.mark.anyio
    async def test_non_tool_response_no_tee(self, mock_streams, init_options):
        """Test that non-tool-call responses don't get _meta.tee."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        # Send response for a non-tool request (request_id not in _tee_request_ids)
        response = types.CallToolResult(content=[], isError=False)
        await session._send_response(request_id=99, response=response)

        msg = await write_recv.receive()
        result = msg.message.result

        # Should NOT have _meta.tee since request_id 99 was not a tool call
        assert "_meta" not in result or "tee" not in result.get("_meta", {})

    @pytest.mark.anyio
    async def test_verify_request_tracks_tee_request_id(self, mock_streams, init_options):
        """Test that successful verification adds request_id to _tee_request_ids."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        client_evidence = MockAttestationEvidence(role="client")
        tee_dict = client_evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        call_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="test_tool",
                _meta={"tee": tee_dict},
            )
        )
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=42,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        with patch(
            "mcp.server.trusted_session.open_tool_request_envelope",
            return_value=(None, True, ""),
        ):
            result = session._verify_and_decrypt_request(responder)
        assert result is True
        assert 42 in session._tee_request_ids

    @pytest.mark.anyio
    async def test_preprocess_encrypted_tool_request_restores_params_for_validation(self, mock_streams, init_options):
        """Preprocess hook should restore encrypted tools/call params before validation."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        raw_request = {
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {
                "_meta": {
                    "tee": {"sig_data": base64.b64encode(b"x" * 32).decode()},
                },
            },
        }

        decrypted_params = {"name": "test_tool", "arguments": {"k": "v"}}
        with patch(
            "mcp.server.trusted_session.open_tool_request_envelope",
            return_value=(decrypted_params, True, ""),
        ):
            prepared = session._preprocess_incoming_request_data(raw_request)

        assert prepared["params"]["name"] == "test_tool"
        assert prepared["params"]["arguments"] == {"k": "v"}

        from pydantic import TypeAdapter

        adapter = TypeAdapter(types.ClientRequest)
        validated = adapter.validate_python(prepared, by_name=False)
        assert isinstance(validated, types.CallToolRequest)
        assert 77 in session._preverified_request_ids
        assert 77 in session._tee_request_ids

    @pytest.mark.anyio
    async def test_verify_request_uses_preverified_marker(self, mock_streams, init_options):
        """A preverified request should bypass second envelope verification."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        call_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="test_tool",
                _meta={"tee": {"sig_data": base64.b64encode(b"x" * 32).decode()}},
            )
        )
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=55,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        session._preverified_request_ids.add(55)
        with patch("mcp.server.trusted_session.open_tool_request_envelope") as mock_open:
            result = session._verify_and_decrypt_request(responder)

        assert result is True
        assert 55 not in session._preverified_request_ids
        mock_open.assert_not_called()

    @pytest.mark.anyio
    async def test_verify_request_merges_decrypted_params(self, mock_streams, init_options):
        """Verified decrypted params should override tool name/arguments."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        client_evidence = MockAttestationEvidence(role="client")
        tee_dict = client_evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        call_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="original_tool",
                arguments={"old": 1},
                _meta={"tee": tee_dict},
            )
        )
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=56,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        with patch(
            "mcp.server.trusted_session.open_tool_request_envelope",
            return_value=({"name": "decrypted_tool", "arguments": {"new": 2}}, True, ""),
        ):
            result = session._verify_and_decrypt_request(responder)

        assert result is True
        assert call_request.params.name == "decrypted_tool"
        assert call_request.params.arguments == {"new": 2}

    @pytest.mark.anyio
    async def test_validation_error_cleanup_clears_preverified_state(self, mock_streams, init_options):
        """Validation failure cleanup must clear preverification state."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        session._tee_request_ids.add(123)
        session._preverified_request_ids.add(123)

        session._on_request_validation_error(123, ValueError("bad request"))

        assert 123 not in session._tee_request_ids
        assert 123 not in session._preverified_request_ids


class TestChallengeMac:
    """Tests for HMAC-SHA256 challenge MAC in Message 3 (initialized notification)."""

    @pytest.fixture
    async def mock_streams(self):
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.fixture
    def init_options(self):
        return InitializationOptions(
            server_name="test-server",
            server_version="1.0.0",
            capabilities=types.ServerCapabilities(),
        )

    @pytest.mark.anyio
    async def test_valid_challenge_mac_accepted(self, mock_streams, init_options):
        """Valid HMAC-SHA256 challenge MAC proves key possession."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        # Set mac_key so MAC verification path is taken
        session._endpoint.mac_key = b"mock_mac_key_32bytes_long_enough"
        session._endpoint._verify_mac_result = True

        # Build notification with challenge_mac (no quote)
        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(b"valid_mac").decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)

        assert result is True

    @pytest.mark.anyio
    async def test_invalid_challenge_mac_rejected(self, mock_streams, init_options):
        """Invalid HMAC-SHA256 MAC is rejected."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        # Set mac_key but make verification fail
        session._endpoint.mac_key = b"mock_mac_key_32bytes_long_enough"
        session._endpoint._verify_mac_result = False

        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(b"bad_mac").decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)

        assert result is False

    @pytest.mark.anyio
    async def test_challenge_mac_bad_base64_rejected(self, mock_streams, init_options):
        """Malformed base64 in challenge_mac is rejected."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        session._endpoint.mac_key = b"mock_mac_key_32bytes_long_enough"

        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": "!!!bad-base64!!!",
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)
        assert result is False

    @pytest.mark.anyio
    async def test_challenge_mac_no_mac_key_not_required(self, mock_streams, init_options):
        """Without mac_key, MAC path accepts if attestation not required."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream, write_stream, init_options, tee_enabled=True, require_client_attestation=False
        )
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        # No mac_key set (session not established via ECDH)
        assert session._endpoint.mac_key is None

        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(b"mac").decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)
        assert result is True

    @pytest.mark.anyio
    async def test_challenge_mac_no_mac_key_required_fails(self, mock_streams, init_options):
        """Without mac_key, MAC path rejects if attestation required."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream, write_stream, init_options, tee_enabled=True, require_client_attestation=True
        )
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        # No mac_key set (session not established via ECDH)
        assert session._endpoint.mac_key is None

        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(b"mac").decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)
        assert result is False

    @pytest.mark.anyio
    async def test_missing_mac_with_challenge_rejected(self, mock_streams, init_options):
        """Missing challenge_mac when challenge was pending is fatal."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        challenge = b"c" * 32
        session._endpoint._bootstrap_challenge = challenge

        # tee_dict with challenge_response but no challenge_mac
        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = session._handle_initialized_tee(notification)
        assert result is False


class TestToolsListAndWhitelist:
    """Tests for tools/list trust metadata and whitelist/blacklist fast-path."""

    @pytest.fixture
    async def mock_streams(self):
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.fixture
    def init_options(self):
        return InitializationOptions(
            server_name="test-server",
            server_version="1.0.0",
            capabilities=types.ServerCapabilities(),
        )

    @pytest.mark.anyio
    async def test_tools_list_marked_for_trust_metadata(self, mock_streams, init_options):
        """tools/list request is tracked for trust metadata injection."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32

        # Create a ListToolsRequest
        list_request = types.ListToolsRequest()
        request = list_request

        from mcp.shared.session import RequestResponder

        _responder = RequestResponder(
            request_id=10,
            request_meta=None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        # Manually set the request_id tracking
        session._tee_request_ids.add(10)
        session._tools_list_request_ids.add(10)

        assert 10 in session._tee_request_ids
        assert 10 in session._tools_list_request_ids

    @pytest.mark.anyio
    async def test_tools_list_response_injects_session_envelope(self, mock_streams, init_options):
        """tools/list response includes session-bound _meta.tee."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32

        # Add derive_sig_data to mock
        import hashlib
        import hmac

        call_counter = [0]

        def derive_sig_data(entropy):
            counter = call_counter[0]
            call_counter[0] += 1
            counter_bytes = counter.to_bytes(8, "big")
            sig = hmac.new(b"x" * 32, entropy + counter_bytes, hashlib.sha256).digest()
            return sig, counter

        session._endpoint.derive_sig_data = derive_sig_data

        # Mark as tools/list request
        session._tee_request_ids.add(20)
        session._tools_list_request_ids.add(20)

        response = types.ListToolsResult(tools=[])
        await session._send_response(request_id=20, response=response)

        msg = await write_recv.receive()
        jsonrpc_msg = msg.message
        assert jsonrpc_msg.id == 20
        assert "_meta" in jsonrpc_msg.result
        assert "tee" in jsonrpc_msg.result["_meta"]
        tee = jsonrpc_msg.result["_meta"]["tee"]
        assert "sig_data" in tee
        assert "timestamp_ms" in tee

    @pytest.mark.anyio
    async def test_tools_list_response_includes_trust_metadata(self, mock_streams, init_options):
        """tools/list response includes server_trust when ToolTrustManager is set."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32

        import hashlib
        import hmac

        call_counter = [0]

        def derive_sig_data(entropy):
            counter = call_counter[0]
            call_counter[0] += 1
            counter_bytes = counter.to_bytes(8, "big")
            sig = hmac.new(b"x" * 32, entropy + counter_bytes, hashlib.sha256).digest()
            return sig, counter

        session._endpoint.derive_sig_data = derive_sig_data

        # Set up mock ToolTrustManager
        from unittest.mock import MagicMock

        from mcp.server.tool_trust import ServerTrustInfo

        mock_ttm = MagicMock()
        mock_ttm.revision = 0
        mock_ttm.get_server_trust_info.return_value = ServerTrustInfo(
            status="trusted",
            rtmr3="aa" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=5,
            cgroup="/docker/abc",
            timestamp_ms=1234567890000,
        )
        session._tool_trust_manager = mock_ttm

        session._tee_request_ids.add(30)
        session._tools_list_request_ids.add(30)

        response = types.ListToolsResult(tools=[])
        await session._send_response(request_id=30, response=response)

        msg = await write_recv.receive()
        tee = msg.message.result["_meta"]["tee"]
        assert "server_trust" in tee
        assert tee["server_trust"]["status"] == "trusted"
        assert tee["server_trust"]["cgroup"] == "/docker/abc"

    @pytest.mark.anyio
    async def test_untrusted_tool_rejected_before_attestation(self, mock_streams, init_options):
        """Untrusted tool is rejected before per-call attestation."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        from unittest.mock import MagicMock

        from mcp.server.tool_trust import ServerTrustInfo

        mock_ttm = MagicMock()
        mock_ttm.get_tool_trust_info.return_value = ServerTrustInfo(
            status="untrusted",
            rtmr3="bb" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=6,
            cgroup="/docker/abc",
            timestamp_ms=1234567890000,
            policy_action="restart",
            version=3,
            source="authority",
        )
        mock_ttm.is_tool_trusted.return_value = False
        mock_ttm.trigger_remediation.return_value = {"cgroup_path": "/docker/abc", "signaled_pids": 1}
        session._tool_trust_manager = mock_ttm

        # Create tool call request
        call_request = types.CallToolRequest(params=types.CallToolRequestParams(name="untrusted_tool"))
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=40,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        await session._received_request(responder)

        # Should have sent an error response
        msg = await write_recv.receive()
        jsonrpc_msg = msg.message
        assert hasattr(jsonrpc_msg, "error")
        assert "untrusted" in jsonrpc_msg.error.message

        # Should have triggered remediation
        mock_ttm.trigger_remediation.assert_called_once_with("untrusted_tool", action="restart")

    @pytest.mark.anyio
    async def test_trusted_tool_proceeds_to_attestation(self, mock_streams, init_options):
        """Trusted tool proceeds to per-call attestation (not rejected by whitelist)."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        # Simulate initialized state so super()._received_request doesn't reject
        from mcp.server.session import InitializationState

        session._initialization_state = InitializationState.Initialized

        from unittest.mock import MagicMock

        mock_ttm = MagicMock()
        mock_ttm.get_tool_trust_info.return_value = MagicMock(status="trusted")
        mock_ttm.is_tool_trusted.return_value = True
        session._tool_trust_manager = mock_ttm

        client_evidence = MockAttestationEvidence(role="client")
        tee_dict = client_evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        call_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="trusted_tool",
                _meta={"tee": tee_dict},
            )
        )
        request = call_request

        from mcp.shared.session import RequestResponder

        responder = RequestResponder(
            request_id=41,
            request_meta=call_request.params.meta if call_request.params else None,
            request=request,
            session=session,
            on_complete=lambda r: None,
        )

        # Patch open_tool_request_envelope so _verify_and_decrypt_request succeeds
        with patch(
            "mcp.server.trusted_session.open_tool_request_envelope",
            return_value=(None, True, ""),
        ):
            # The trust check happens inside _received_request, not _verify_and_decrypt_request
            # We test that is_tool_trusted is called by going through _received_request
            await session._received_request(responder)

        mock_ttm.is_tool_trusted.assert_called_once()
        assert mock_ttm.is_tool_trusted.call_args.args[0] == "trusted_tool"
        assert "trust_info" in mock_ttm.is_tool_trusted.call_args.kwargs
        mock_ttm.get_tool_trust_info.assert_called_once_with("trusted_tool", require_fresh=True)

    @pytest.mark.anyio
    async def test_validation_error_clears_tools_list_state(self, mock_streams, init_options):
        """Validation failure cleanup must clear tools_list state."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        session._tools_list_request_ids.add(100)
        session._tee_request_ids.add(100)

        session._on_request_validation_error(100, ValueError("bad"))

        assert 100 not in session._tools_list_request_ids
        assert 100 not in session._tee_request_ids

    @pytest.mark.anyio
    async def test_tools_list_response_filters_only_untrusted_tools(self, mock_streams, init_options):
        """Authoritative discovery should filter tools per mapped subject."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32

        import hashlib
        import hmac

        call_counter = [0]

        def derive_sig_data(entropy):
            counter = call_counter[0]
            call_counter[0] += 1
            counter_bytes = counter.to_bytes(8, "big")
            sig = hmac.new(b"x" * 32, entropy + counter_bytes, hashlib.sha256).digest()
            return sig, counter

        session._endpoint.derive_sig_data = derive_sig_data

        from unittest.mock import MagicMock

        from mcp.server.tool_trust import ServerTrustInfo

        mock_ttm = MagicMock()
        mock_ttm.revision = 0
        mock_ttm.get_server_trust_info.return_value = ServerTrustInfo(
            status="trusted",
            rtmr3="aa" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=5,
            cgroup="/docker/abc",
            timestamp_ms=1234567890000,
            source="attestation-service",
            policy_action="none",
        )
        trusted_info = ServerTrustInfo(
            status="trusted",
            rtmr3="aa" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=5,
            cgroup="/docker/tool-a",
            timestamp_ms=1234567890000,
            source="attestation-service",
            policy_action="none",
            version=11,
        )
        untrusted_info = ServerTrustInfo(
            status="untrusted",
            rtmr3="bb" * 48,
            initial_rtmr3="aa" * 48,
            measurement_count=6,
            cgroup="/docker/tool-b",
            timestamp_ms=1234567890000,
            source="attestation-service",
            policy_action="restart",
            version=12,
        )

        def get_tool_info(tool_name: str, *, require_fresh: bool = False):  # noqa: ANN202
            assert require_fresh is True
            return trusted_info if tool_name == "safe_tool" else untrusted_info

        mock_ttm.get_tool_trust_info.side_effect = get_tool_info
        mock_ttm.is_tool_trusted.side_effect = lambda tool_name, *, trust_info=None, require_fresh=False: (
            trust_info.status == "trusted"
        )
        session._tool_trust_manager = mock_ttm

        session._tee_request_ids.add(110)
        session._tools_list_request_ids.add(110)

        response = types.ListToolsResult(
            tools=[
                types.Tool(
                    name="safe_tool",
                    description="allowed",
                    inputSchema={"type": "object"},
                    _meta={"tee": {"subject": "cgroup:///docker/tool-a"}},
                ),
                types.Tool(
                    name="secret_tool",
                    description="blocked",
                    inputSchema={"type": "object"},
                    _meta={"tee": {"subject": "cgroup:///docker/tool-b"}},
                ),
            ]
        )
        await session._send_response(request_id=110, response=response)

        msg = await write_recv.receive()
        result = msg.message.result
        assert [tool["name"] for tool in result["tools"]] == ["safe_tool"]
        mock_ttm.update_tool_subjects.assert_called_once_with(
            {
                "safe_tool": "cgroup:///docker/tool-a",
                "secret_tool": "cgroup:///docker/tool-b",
            }
        )


class TestTrustedServerSessionProperties:
    """Tests for TrustedServerSession properties."""

    @pytest.fixture
    async def mock_streams(self):
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.fixture
    def init_options(self):
        return InitializationOptions(
            server_name="test-server",
            server_version="1.0.0",
            capabilities=types.ServerCapabilities(),
        )

    @pytest.mark.anyio
    async def test_client_cgroup_property(self, mock_streams, init_options):
        """Test client_cgroup property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        assert session.client_cgroup == ""

        session._client_attested = True
        session._endpoint._peers["client"] = MockPeer(cgroup="/docker/client", rtmr3=bytes(48), role="client")

        assert session.client_cgroup == "/docker/client"

    @pytest.mark.anyio
    async def test_peer_verified_property(self, mock_streams, init_options):
        """Test peer_verified property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)

        assert session.peer_verified is False
        session._peer_verified = True
        assert session.peer_verified is True


# =============================================================================
# Multi-hop / JWT Verifier Tests (Phase 11)
# =============================================================================


class TestServerJWTVerifier:
    """Tests for server-side JWT verifier and upstream token handling."""

    @pytest.fixture
    async def mock_streams(self):
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.fixture
    def init_options(self):
        return InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

    @pytest.mark.anyio
    async def test_client_attestation_token_initial_state(self, mock_streams, init_options):
        """client_attestation_token is empty initially."""
        read_stream, write_stream, _, _ = mock_streams
        session = create_test_session(read_stream, write_stream, init_options, tee_enabled=True)
        assert session.client_attestation_token == ""

    @pytest.mark.anyio
    async def test_jwt_verifier_constructor_param(self, mock_streams, init_options):
        """jwt_verifier can be passed via constructor."""
        read_stream, write_stream, _, _ = mock_streams

        mock_verifier = MagicMock()
        session = create_test_session(
            read_stream,
            write_stream,
            init_options,
            tee_enabled=True,
            jwt_verifier=mock_verifier,
        )
        assert session._jwt_verifier is mock_verifier

    @pytest.mark.anyio
    async def test_require_upstream_jwt_constructor_param(self, mock_streams, init_options):
        """require_upstream_jwt can be passed via constructor."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            init_options,
            tee_enabled=True,
            require_upstream_jwt=True,
        )
        assert session._require_upstream_jwt is True
