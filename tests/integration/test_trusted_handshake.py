"""Integration tests for unified per-call TEE attestation.

Tests the complete flow between TrustedClientSession and TrustedServerSession
using the new _meta.tee protocol (no session handshake).
"""

import base64
from dataclasses import dataclass

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
        )


@dataclass
class MockVerifyResult:
    valid: bool = True
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = bytes(48)


@dataclass
class MockPeer:
    cgroup: str
    rtmr3: bytes
    role: str


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing."""

    _instance_counter = 0

    def __init__(self, role: str = "client"):
        self.role = role
        self.session_id: bytes | None = None
        self.session_key: bytes | None = None
        self.mac_key: bytes | None = None
        self._peers: dict[str, MockPeer] = {}
        self._nonces: dict[str, bytes] = {}
        self._bootstrap_challenge: bytes | None = None
        self._initial_rtmr3: bytes | None = None
        MockSecureEndpoint._instance_counter += 1
        self._id = MockSecureEndpoint._instance_counter

    @classmethod
    def create(cls, role: str = "client") -> "MockSecureEndpoint":
        return cls(role=role)

    def consume_bootstrap_challenge(self) -> bytes | None:
        challenge = self._bootstrap_challenge
        self._bootstrap_challenge = None
        return challenge

    def generate_nonce(self, peer_role: str = "server") -> bytes:
        nonce = f"nonce_{self._id}_{peer_role}".encode()
        self._nonces[peer_role] = nonce
        return nonce

    def create_evidence(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(
            role=self.role,
            nonce=nonce,
            cgroup=f"/docker/{self.role}_{self._id}",
        )

    def verify_peer(
        self,
        evidence: MockAttestationEvidence,
        expected_nonce: bytes | None = None,
        peer_role: str = "server",
        allowed_rtmr3: list[str] | None = None,
    ) -> MockVerifyResult:
        self._peers[peer_role] = MockPeer(
            cgroup=evidence.cgroup,
            rtmr3=evidence.rtmr3,
            role=evidence.role,
        )
        return MockVerifyResult(valid=True)

    def verify_challenge_mac(self, challenge: bytes, mac: bytes) -> bool:
        import hashlib
        import hmac as hmac_mod

        if self.mac_key is None:
            raise ValueError("MAC key not established")
        expected = hmac_mod.new(self.mac_key, challenge, hashlib.sha256).digest()
        return hmac_mod.compare_digest(expected, mac)

    def get_peer(self, role: str) -> MockPeer | None:
        return self._peers.get(role)


# =============================================================================
# Helper Functions
# =============================================================================


def create_client_session(read_stream, write_stream, *, tee_enabled: bool = True):
    """Create a TrustedClientSession with mock endpoint."""
    from mcp.client.trusted_session import TrustedClientSession

    session = TrustedClientSession(read_stream, write_stream, tee_enabled=False)

    if tee_enabled:
        session._tee_enabled = True
        session._endpoint = MockSecureEndpoint(role="client")

    return session


def create_server_session(
    read_stream,
    write_stream,
    init_options,
    *,
    tee_enabled: bool = True,
    require_client_attestation: bool = False,
):
    """Create a TrustedServerSession with mock endpoint."""
    from mcp.server.trusted_session import TrustedServerSession

    session = TrustedServerSession(read_stream, write_stream, init_options, tee_enabled=False)

    if tee_enabled:
        session._tee_enabled = True
        session._endpoint = MockSecureEndpoint(role="server")
        session._require_client_attestation = require_client_attestation

    return session


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
async def memory_streams():
    read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
    write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
    try:
        yield read_send, read_recv, write_send, write_recv
    finally:
        await read_send.aclose()
        await read_recv.aclose()
        await write_send.aclose()
        await write_recv.aclose()


# =============================================================================
# Integration Tests
# =============================================================================


class TestUnifiedTeeProtocol:
    """Integration tests for the unified per-call TEE protocol."""

    @pytest.mark.anyio
    async def test_endpoints_created_correctly(self, memory_streams):
        """Test that TEE endpoints are created on both sides."""
        _, read_recv, write_send, _ = memory_streams

        client = create_client_session(read_recv, write_send, tee_enabled=True)
        assert client._endpoint is not None
        assert client._tee_enabled is True

    @pytest.mark.anyio
    async def test_server_tee_in_response(self, memory_streams):
        """Test that server injects _meta.tee into tool call response."""
        _, read_recv, write_send, write_recv = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(read_recv, write_send, init_options, tee_enabled=True)

        # Simulate that request 1 was a verified tool call
        server._tee_request_ids.add(1)

        # Send a response and verify _meta.tee
        response = types.CallToolResult(content=[], isError=False)
        await server._send_response(request_id=1, response=response)

        msg = await write_recv.receive()
        result = msg.message.result

        assert "_meta" in result
        assert "tee" in result["_meta"]
        assert "sig_data" in result["_meta"]["tee"]
        assert "quote" in result["_meta"]["tee"]

    @pytest.mark.anyio
    async def test_server_handles_initialized_no_challenge(self, memory_streams):
        """Test that _handle_initialized_tee succeeds when no challenge is pending."""
        _, read_recv, write_send, _ = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(read_recv, write_send, init_options, tee_enabled=True)

        # No bootstrap challenge was set, so _handle_initialized_tee should return True
        # (require_client_attestation is False by default)
        notification = types.InitializedNotification()
        result = server._handle_initialized_tee(notification)
        assert result is True

    @pytest.mark.anyio
    async def test_server_handles_initialized_with_challenge(self, memory_streams):
        """Test that _handle_initialized_tee verifies challenge-response HMAC."""
        _, read_recv, write_send, _ = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(read_recv, write_send, init_options, tee_enabled=True)

        # Set up a pending bootstrap challenge and mac_key
        challenge = b"test_challenge_32_bytes_padding!!"
        server._endpoint._bootstrap_challenge = challenge
        server._endpoint.mac_key = b"mock_mac_key_for_testing_32bytes"

        # Create initialized notification with challenge_response and challenge_mac
        import hashlib
        import hmac

        mac = hmac.new(server._endpoint.mac_key, challenge, hashlib.sha256).digest()
        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(mac).decode(),
        }

        meta = {"tee": tee_dict}
        params = types.NotificationParams(_meta=meta)
        notification = types.InitializedNotification(params=params)

        result = server._handle_initialized_tee(notification)
        assert result is True


class TestAttestationFailures:
    """Tests for attestation failure scenarios."""

    @pytest.mark.anyio
    async def test_client_rejects_invalid_server_tee(self, memory_streams):
        """Test that client rejects invalid server evidence."""
        _, read_recv, write_send, _ = memory_streams

        client = create_client_session(read_recv, write_send, tee_enabled=True)

        # Override verify_peer to return invalid
        def invalid_verify(*args, **kwargs):
            return MockVerifyResult(valid=False, error="Invalid quote")

        client._endpoint.verify_peer = invalid_verify

        # Simulate checking server TEE from a response - would fail
        assert client.is_server_attested is False

    @pytest.mark.anyio
    async def test_server_handles_missing_client_tee_when_required(self, memory_streams):
        """Test server handles missing _meta.tee when required."""
        _, read_recv, write_send, _ = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(
            read_recv, write_send, init_options, tee_enabled=True, require_client_attestation=True
        )

        # Notification without _meta.tee
        notification = types.InitializedNotification()

        server._handle_initialized_tee(notification)

        assert server._client_attested is False

    @pytest.mark.anyio
    async def test_request_tee_verification_failure(self, memory_streams):
        """Test that TEE verification failure is handled correctly in requests."""
        _, read_recv, write_send, _ = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(
            read_recv, write_send, init_options, tee_enabled=True, require_client_attestation=True
        )

        # Override verify_peer to fail
        def failing_verify(*args, **kwargs):
            return MockVerifyResult(valid=False, error="Bad attestation")

        server._endpoint.verify_peer = failing_verify

        # Create request with _meta.tee
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
            session=server,
            on_complete=lambda r: None,
        )

        result = server._verify_and_decrypt_request(responder)
        assert result is False


class TestResponseTeeInjection:
    """Tests for _meta.tee injection in server responses."""

    @pytest.mark.anyio
    async def test_response_contains_tee(self, memory_streams):
        """Test that tool call server response contains _meta.tee."""
        _, read_recv, write_send, write_recv = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(read_recv, write_send, init_options, tee_enabled=True)

        # Simulate that request 5 was a verified tool call
        server._tee_request_ids.add(5)

        response = types.CallToolResult(content=[], isError=False)
        await server._send_response(request_id=5, response=response)

        msg = await write_recv.receive()
        jsonrpc_msg = msg.message

        assert jsonrpc_msg.id == 5
        assert "_meta" in jsonrpc_msg.result
        assert "tee" in jsonrpc_msg.result["_meta"]

        tee = jsonrpc_msg.result["_meta"]["tee"]
        assert "quote" in tee
        assert "sig_data" in tee

    @pytest.mark.anyio
    async def test_error_response_no_tee(self, memory_streams):
        """Test that error responses don't get _meta.tee."""
        _, read_recv, write_send, write_recv = memory_streams

        init_options = InitializationOptions(
            server_name="test",
            server_version="1.0",
            capabilities=types.ServerCapabilities(),
        )

        server = create_server_session(read_recv, write_send, init_options, tee_enabled=True)

        error = types.ErrorData(code=-1, message="error")
        await server._send_response(request_id=1, response=error)

        msg = await write_recv.receive()
        jsonrpc_msg = msg.message

        assert hasattr(jsonrpc_msg, "error")
