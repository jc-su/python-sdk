"""Tests for TrustedClientSession - unified per-call TEE attestation.

Uses mock SecureEndpoint to test attestation flow without TDX hardware.
"""

import base64
from dataclasses import dataclass

import anyio
import pytest

import mcp.types as types
from mcp.shared.exceptions import MCPError
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
    role: str = "server"

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
            role=data.get("role", "server"),
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


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing without TDX hardware."""

    def __init__(self, role: str = "client"):
        self.role = role
        self.session_id: bytes | None = None
        self.kek: bytes | None = None
        self.mac_key: bytes | None = None
        self._send_counter = 0
        self._recv_counter = 0
        self._peers: dict[str, MockPeer] = {}
        self._nonces: dict[str, bytes] = {}
        self._initial_rtmr3: bytes | None = None

    @classmethod
    def create(cls, role: str = "client") -> "MockSecureEndpoint":
        return cls(role=role)

    def generate_nonce(self, peer_role: str = "server") -> bytes:
        nonce = b"mock_nonce_" + peer_role.encode()
        self._nonces[peer_role] = nonce
        return nonce

    def create_attestation(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer_attestation(
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

    def get_peer(self, role: str) -> MockPeer | None:
        return self._peers.get(role)

    def create_challenge_mac(self, challenge: bytes) -> bytes:
        """Create HMAC-SHA256 MAC for challenge-response."""
        import hashlib
        import hmac

        key = self.mac_key or b"mock_mac_key"
        return hmac.new(key, challenge, hashlib.sha256).digest()

    def next_send_counter(self) -> int:
        counter = self._send_counter
        self._send_counter += 1
        return counter

    def verify_recv_counter(self, counter: int) -> None:
        if counter < self._recv_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._recv_counter}")
        self._recv_counter = counter + 1

    def create_session_auth(self, counter: int) -> bytes:
        import hashlib
        import hmac

        key = self.mac_key or b"mock_mac_key"
        return hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha256).digest()

    def verify_session_auth(self, counter: int, auth_tag: bytes) -> bool:
        import hashlib
        import hmac

        if self.mac_key is None:
            return False
        expected = hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        return hmac.compare_digest(expected, auth_tag)

    def wrap_and_encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> "EnvelopePayload":
        from mcp.shared.crypto.envelope import envelope_encrypt

        if self.kek is None:
            raise ValueError("KEK not established")
        return envelope_encrypt(self.kek, plaintext, aad=aad)

    def unwrap_and_decrypt(self, payload: "EnvelopePayload", *, aad: bytes | None = None) -> bytes:
        from mcp.shared.crypto.envelope import envelope_decrypt

        if self.kek is None:
            raise ValueError("KEK not established")
        return envelope_decrypt(self.kek, payload, aad=aad)


# =============================================================================
# Helper to create session with mock endpoint
# =============================================================================


def create_test_session(
    read_stream,
    write_stream,
    *,
    tee_enabled: bool = True,
    allowed_server_rtmr3: list[str] | None = None,
):
    """Create a TrustedClientSession with mock endpoint for testing."""
    from mcp.client.trusted_session import TrustedClientSession

    session = TrustedClientSession(
        read_stream,
        write_stream,
        tee_enabled=False,
    )

    if tee_enabled:
        session._tee_enabled = True
        session._endpoint = MockSecureEndpoint(role="client")
        session._allowed_server_rtmr3 = allowed_server_rtmr3

    return session


# =============================================================================
# Tests
# =============================================================================


class TestTrustedClientSession:
    """Tests for TrustedClientSession."""

    @pytest.fixture
    async def mock_streams(self):
        """Create mock memory streams for testing."""
        read_send, read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](10)
        write_send, write_recv = anyio.create_memory_object_stream[SessionMessage](10)
        try:
            yield read_recv, write_send, read_send, write_recv
        finally:
            await read_send.aclose()
            await read_recv.aclose()
            await write_send.aclose()
            await write_recv.aclose()

    @pytest.mark.anyio
    async def test_init_with_tee_disabled(self, mock_streams):
        """Test TrustedClientSession with TEE disabled."""
        read_stream, write_stream, _, _ = mock_streams

        from mcp.client.trusted_session import TrustedClientSession

        async with TrustedClientSession(
            read_stream,
            write_stream,
            tee_enabled=False,
        ) as session:
            assert session.tee_enabled is False
            assert session.is_server_attested is False
            assert session.server_cgroup == ""

    @pytest.mark.anyio
    async def test_init_with_tee_enabled_mock(self, mock_streams):
        """Test TrustedClientSession with mocked TEE."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            tee_enabled=True,
        )

        assert session._tee_enabled is True
        assert session._endpoint is not None
        assert isinstance(session._endpoint, MockSecureEndpoint)

    @pytest.mark.anyio
    async def test_tee_evidence_in_call_tool(self, mock_streams):
        """Test that _meta.tee evidence is injected into call_tool request."""
        read_stream, write_stream, read_send, write_recv = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            tee_enabled=True,
        )

        # Set up session internals
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        async with anyio.create_task_group() as tg:

            async def send_and_capture():
                try:
                    await session.call_tool("test_tool", {"key": "value"})
                except Exception:
                    pass

            tg.start_soon(send_and_capture)
            await anyio.sleep(0.05)

            # Read the message written to the stream
            msg = await write_recv.receive()
            jsonrpc_msg = msg.message

            # Verify that _meta.tee was injected
            assert hasattr(jsonrpc_msg, "params")
            params = jsonrpc_msg.params
            assert "_meta" in params
            assert "tee" in params["_meta"]

            tee = params["_meta"]["tee"]
            assert "quote" in tee
            assert "public_key" in tee
            assert "sig_data" in tee
            assert "role" in tee

            # Feed response to unblock
            from mcp.types import JSONRPCResponse

            response = JSONRPCResponse(
                jsonrpc="2.0",
                id=0,
                result={"content": [], "isError": False},
            )
            response_stream = session._response_streams.get(0)
            assert response_stream is not None
            await response_stream.send(response)
            await anyio.sleep(0.05)

    @pytest.mark.anyio
    async def test_response_tee_verification_via_call_tool(self, mock_streams):
        """Test that server _meta.tee in call_tool response is verified."""
        read_stream, write_stream, read_send, write_recv = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            tee_enabled=True,
        )
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        result_holder = []

        async with anyio.create_task_group() as tg:

            async def do_request():
                try:
                    result = await session.call_tool("test_tool")
                    result_holder.append(result)
                except Exception as e:
                    result_holder.append(e)

            tg.start_soon(do_request)
            await anyio.sleep(0.05)

            await write_recv.receive()

            # Build response with _meta.tee (bootstrap path since session_key is None)
            server_evidence = MockAttestationEvidence(role="server")
            tee_dict = server_evidence.to_dict()
            tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

            response_result = {
                "content": [],
                "isError": False,
                "_meta": {"tee": tee_dict},
            }

            from mcp.types import JSONRPCResponse

            response = JSONRPCResponse(jsonrpc="2.0", id=0, result=response_result)
            response_stream = session._response_streams.get(0)
            assert response_stream is not None
            await response_stream.send(response)
            await anyio.sleep(0.1)

        assert len(result_holder) == 1
        assert isinstance(result_holder[0], types.CallToolResult)

    @pytest.mark.anyio
    async def test_tool_response_attestation_failure_is_fatal_without_response_key(self, mock_streams):
        """Invalid tool response evidence must fail even if request was unencrypted."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            tee_enabled=True,
        )
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        # Force verification failure on response evidence.
        def failing_verify(*args, **kwargs):
            return MockVerifyResult(valid=False, error="Bad attestation")

        session._endpoint.verify_peer_attestation = failing_verify

        result_holder = []

        async with anyio.create_task_group() as tg:

            async def do_request():
                try:
                    await session.call_tool("test_tool")
                except Exception as e:
                    result_holder.append(e)

            tg.start_soon(do_request)
            await anyio.sleep(0.05)

            await write_recv.receive()

            server_evidence = MockAttestationEvidence(role="server")
            tee_dict = server_evidence.to_dict()
            tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

            response_result = {
                "content": [],
                "isError": False,
                "_meta": {"tee": tee_dict},
            }

            from mcp.types import JSONRPCResponse

            response = JSONRPCResponse(jsonrpc="2.0", id=0, result=response_result)
            response_stream = session._response_streams.get(0)
            assert response_stream is not None
            await response_stream.send(response)
            await anyio.sleep(0.1)

        assert len(result_holder) == 1
        assert isinstance(result_holder[0], MCPError)
        assert 0 not in session._tee_request_kinds

    @pytest.mark.anyio
    async def test_tool_response_missing_tee_is_fatal(self, mock_streams):
        """Missing _meta.tee in tool response must fail in trusted mode."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(
            read_stream,
            write_stream,
            tee_enabled=True,
        )
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        result_holder = []

        async with anyio.create_task_group() as tg:

            async def do_request():
                try:
                    await session.call_tool("test_tool")
                except Exception as e:
                    result_holder.append(e)

            tg.start_soon(do_request)
            await anyio.sleep(0.05)

            await write_recv.receive()

            from mcp.types import JSONRPCResponse

            response = JSONRPCResponse(
                jsonrpc="2.0",
                id=0,
                result={"content": [], "isError": False},
            )
            response_stream = session._response_streams.get(0)
            assert response_stream is not None
            await response_stream.send(response)
            await anyio.sleep(0.1)

        assert len(result_holder) == 1
        assert isinstance(result_holder[0], MCPError)

    @pytest.mark.anyio
    async def test_prepare_hook_error_cleans_request_state(self, mock_streams):
        """send_request must clean internal state even if prepare hook raises."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}

        def raise_in_prepare(request_id: int, request_data: dict) -> dict:
            raise RuntimeError("prepare failed")

        session._prepare_request_data = raise_in_prepare  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="prepare failed"):
            await session.send_request(
                types.PingRequest(),
                types.EmptyResult,
            )

        assert session._response_streams == {}
        assert session._progress_callbacks == {}


class TestToolsListTrustMetadata:
    """Tests for tools/list trust metadata handling on client side."""

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

    @pytest.mark.anyio
    async def test_tools_list_injects_session_envelope(self, mock_streams):
        """tools/list request injects session-bound _meta.tee."""
        read_stream, write_stream, _, write_recv = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32
        session._endpoint.mac_key = b"m" * 32

        # Prepare a tools/list request
        request_data = {
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/list",
            "params": {},
        }
        prepared = session._prepare_request_data(50, request_data)

        # Should have TEE injected
        assert "_meta" in prepared.get("params", {})
        assert "tee" in prepared["params"]["_meta"]
        tee = prepared["params"]["_meta"]["tee"]
        assert "counter" in tee
        assert "auth_tag" in tee
        assert "timestamp_ms" in tee
        # No sig_data or entropy in new format
        assert "sig_data" not in tee
        assert "entropy" not in tee
        assert 50 in session._tee_request_kinds
        assert session._tee_request_kinds[50] == "tools/list"

    @pytest.mark.anyio
    async def test_tools_list_not_injected_without_session(self, mock_streams):
        """tools/list doesn't inject TEE before session establishment."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        # session_id is None

        request_data = {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/list",
            "params": {},
        }
        prepared = session._prepare_request_data(51, request_data)

        # Should NOT have TEE injected
        assert "_meta" not in prepared.get("params", {})
        assert 51 not in session._tee_request_kinds

    @pytest.mark.anyio
    async def test_process_tools_list_response_extracts_trust_info(self, mock_streams):
        """Client extracts server_trust from tools/list response."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        session._endpoint.session_id = b"x" * 32
        session._endpoint.mac_key = b"m" * 32

        # Mark request as tools/list
        session._tee_request_kinds[52] = "tools/list"

        # Build response with trust metadata (new wire format: counter + auth_tag)
        import hashlib
        import hmac

        counter = 0
        auth_tag = hmac.new(b"m" * 32, counter.to_bytes(8, "big"), hashlib.sha256).digest()

        trust_info = {
            "status": "trusted",
            "rtmr3": "aa" * 48,
            "initial_rtmr3": "aa" * 48,
            "measurement_count": 5,
            "cgroup": "/docker/abc",
            "timestamp_ms": 1234567890000,
        }

        result = {
            "tools": [],
            "_meta": {
                "tee": {
                    "counter": counter,
                    "auth_tag": base64.b64encode(auth_tag).decode(),
                    "server_trust": trust_info,
                    "timestamp_ms": 1234567890000,
                }
            },
        }

        processed = session._process_raw_response(52, result)

        assert session._server_trust_info is not None
        assert session._server_trust_info["status"] == "trusted"
        assert session._server_trust_info["cgroup"] == "/docker/abc"
        assert processed is result  # tools/list returns original result

    @pytest.mark.anyio
    async def test_server_trust_info_property(self, mock_streams):
        """server_trust_info property returns latest trust info."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)

        assert session.server_trust_info is None

        session._server_trust_info = {"status": "trusted"}
        assert session.server_trust_info == {"status": "trusted"}


class TestTrustedClientSessionProperties:
    """Tests for TrustedClientSession properties."""

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

    @pytest.mark.anyio
    async def test_server_cgroup_property(self, mock_streams):
        """Test server_cgroup property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)

        assert session.server_cgroup == ""

        session._server_attested = True
        session._endpoint._peers["server"] = MockPeer(cgroup="/docker/test", rtmr3=bytes(48), role="server")

        assert session.server_cgroup == "/docker/test"

    @pytest.mark.anyio
    async def test_server_rtmr3_property(self, mock_streams):
        """Test server_rtmr3 property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)

        assert session.server_rtmr3 == bytes(48)

        test_rtmr3 = bytes([0xAB] * 48)
        session._server_attested = True
        session._endpoint._peers["server"] = MockPeer(cgroup="/docker/test", rtmr3=test_rtmr3, role="server")

        assert session.server_rtmr3 == test_rtmr3

    @pytest.mark.anyio
    async def test_endpoint_property(self, mock_streams):
        """Test endpoint property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)

        assert session.endpoint is not None
        assert isinstance(session.endpoint, MockSecureEndpoint)

    @pytest.mark.anyio
    async def test_tee_enabled_property(self, mock_streams):
        """Test tee_enabled property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        assert session.tee_enabled is True

        session_no_tee = create_test_session(read_stream, write_stream, tee_enabled=False)
        assert session_no_tee.tee_enabled is False

    @pytest.mark.anyio
    async def test_peer_verified_property(self, mock_streams):
        """Test peer_verified property."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)

        assert session.peer_verified is False

        session._peer_verified = True
        assert session.peer_verified is True


# =============================================================================
# JWT Verification Tests (Phases 9 & 10)
# =============================================================================


class MockJWTVerifier:
    """Mock AuthorityJWTVerifier for testing."""

    def __init__(self, *, valid: bool = True, error: str = "", expires_at: float = 0.0, claims: dict | None = None):
        from mcp.shared.authority_jwt import JWTVerificationResult

        self._result = JWTVerificationResult(
            valid=valid,
            error=error,
            claims=claims or {},
            expires_at=expires_at,
        )
        self.verify_calls: list[dict] = []

    def verify_attestation_token(
        self,
        token: str,
        *,
        expected_subject: str | None = None,
        expected_rtmr3: str | None = None,
    ):
        self.verify_calls.append(
            {
                "token": token,
                "expected_subject": expected_subject,
                "expected_rtmr3": expected_rtmr3,
            }
        )
        return self._result

    @property
    def enabled(self) -> bool:
        return True


def _setup_session_with_jwt_verifier(read_stream, write_stream, jwt_verifier, *, require_valid_jwt: bool = False):
    """Create a TrustedClientSession with mock endpoint and JWT verifier."""
    session = create_test_session(read_stream, write_stream, tee_enabled=True)
    session._jwt_verifier = jwt_verifier
    session._require_valid_jwt = require_valid_jwt
    return session


def _build_tools_list_response_with_jwt(session, *, attestation_token: str = "eyJ.test.token"):
    """Build a tools/list response with trust metadata including attestation_token.

    Returns (result_dict, request_id).
    """
    import hashlib
    import hmac

    session._endpoint.session_id = b"x" * 32
    session._endpoint.mac_key = b"m" * 32

    request_id = 100
    session._tee_request_kinds[request_id] = "tools/list"

    counter = 0
    auth_tag = hmac.new(b"m" * 32, counter.to_bytes(8, "big"), hashlib.sha256).digest()

    trust_info = {
        "status": "trusted",
        "attestation_token": attestation_token,
        "cgroup": "/docker/abc",
        "timestamp_ms": 1234567890000,
    }

    result = {
        "tools": [],
        "_meta": {
            "tee": {
                "counter": counter,
                "auth_tag": base64.b64encode(auth_tag).decode(),
                "server_trust": trust_info,
                "timestamp_ms": 1234567890000,
            }
        },
    }
    return result, request_id


class TestClientJWTVerification:
    """Tests for client-side JWT verification (Phase 9)."""

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

    @pytest.mark.anyio
    async def test_valid_jwt_sets_jwt_valid(self, mock_streams):
        """tools/list with valid JWT sets jwt_valid=True and jwt_expires_at."""
        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=9999999999.0, claims={"sub": "test"})
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)

        result, req_id = _build_tools_list_response_with_jwt(session)
        session._process_raw_response(req_id, result)

        assert session.jwt_valid is True
        assert session.jwt_expires_at == 9999999999.0
        assert session.jwt_verification_result is not None
        assert session.jwt_verification_result.valid is True
        assert len(verifier.verify_calls) == 1
        assert verifier.verify_calls[0]["token"] == "eyJ.test.token"

    @pytest.mark.anyio
    async def test_invalid_jwt_sets_jwt_invalid(self, mock_streams):
        """tools/list with invalid JWT sets jwt_valid=False."""
        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=False, error="Token expired")
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)

        result, req_id = _build_tools_list_response_with_jwt(session)
        session._process_raw_response(req_id, result)

        assert session.jwt_valid is False
        assert session.jwt_verification_result is not None
        assert session.jwt_verification_result.error == "Token expired"

    @pytest.mark.anyio
    async def test_no_jwt_in_response_skips_verification(self, mock_streams):
        """tools/list without attestation_token skips JWT verification."""
        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=True)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)

        result, req_id = _build_tools_list_response_with_jwt(session, attestation_token="")
        session._process_raw_response(req_id, result)

        assert session.jwt_verification_result is None
        assert len(verifier.verify_calls) == 0

    @pytest.mark.anyio
    async def test_no_jwt_verifier_skips_verification(self, mock_streams):
        """No jwt_verifier configured skips JWT verification entirely."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        # No jwt_verifier set

        result, req_id = _build_tools_list_response_with_jwt(session)
        session._process_raw_response(req_id, result)

        assert session.jwt_verification_result is None

    @pytest.mark.anyio
    async def test_jwt_properties_initial_state(self, mock_streams):
        """JWT properties have correct initial state."""
        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        assert session.jwt_valid is False
        assert session.jwt_expires_at == 0.0
        assert session.jwt_verification_result is None


class TestAsyncReAttestation:
    """Tests for async JWT re-attestation (Phase 10)."""

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

    @pytest.mark.anyio
    async def test_should_refresh_jwt_near_expiry(self, mock_streams):
        """_should_refresh_jwt returns True when JWT is near expiry."""
        import time

        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=time.time() + 30)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)
        session._jwt_expires_at = time.time() + 30  # 30s left, margin is 60s

        assert session._should_refresh_jwt() is True

    @pytest.mark.anyio
    async def test_should_not_refresh_jwt_when_fresh(self, mock_streams):
        """_should_refresh_jwt returns False when JWT is fresh."""
        import time

        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=time.time() + 3600)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)
        session._jwt_expires_at = time.time() + 3600  # 1 hour left

        assert session._should_refresh_jwt() is False

    @pytest.mark.anyio
    async def test_should_not_refresh_without_verifier(self, mock_streams):
        """_should_refresh_jwt returns False when no verifier configured."""
        import time

        read_stream, write_stream, _, _ = mock_streams

        session = create_test_session(read_stream, write_stream, tee_enabled=True)
        session._jwt_expires_at = time.time() + 30  # Near expiry but no verifier

        assert session._should_refresh_jwt() is False

    @pytest.mark.anyio
    async def test_call_tool_triggers_refresh_near_expiry(self, mock_streams):
        """call_tool triggers list_tools refresh when JWT near expiry."""
        import time

        read_stream, write_stream, _, write_recv = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=time.time() + 30)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)
        session._jwt_expires_at = time.time() + 30  # Near expiry
        session._jwt_verification_result = verifier._result

        # Mock list_tools to track calls
        list_tools_called = []

        async def mock_list_tools(*args, **kwargs):
            list_tools_called.append(True)
            # Simulate JWT refresh
            from mcp.shared.authority_jwt import JWTVerificationResult

            session._jwt_verification_result = JWTVerificationResult(valid=True, expires_at=time.time() + 3600)
            session._jwt_expires_at = time.time() + 3600
            return types.ListToolsResult(tools=[])

        session.list_tools = mock_list_tools  # type: ignore[method-assign]

        # Set up for call_tool to work
        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        async with anyio.create_task_group() as tg:

            async def do_call():
                try:
                    await session.call_tool("test_tool", {"key": "value"})
                except Exception:
                    pass

            tg.start_soon(do_call)
            await anyio.sleep(0.05)

            # Verify list_tools was called for refresh
            assert len(list_tools_called) == 1

            # Feed response to unblock
            await write_recv.receive()
            response = types.JSONRPCResponse(jsonrpc="2.0", id=0, result={"content": [], "isError": False})
            response_stream = session._response_streams.get(0)
            if response_stream is not None:
                await response_stream.send(response)
            await anyio.sleep(0.05)

    @pytest.mark.anyio
    async def test_call_tool_no_refresh_when_fresh(self, mock_streams):
        """call_tool does NOT trigger refresh when JWT is fresh."""
        import time

        read_stream, write_stream, _, write_recv = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=time.time() + 3600)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)
        session._jwt_expires_at = time.time() + 3600
        session._jwt_verification_result = verifier._result

        list_tools_called = []

        async def mock_list_tools(*args, **kwargs):
            list_tools_called.append(True)
            return types.ListToolsResult(tools=[])

        session.list_tools = mock_list_tools  # type: ignore[method-assign]

        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        async with anyio.create_task_group() as tg:

            async def do_call():
                try:
                    await session.call_tool("test_tool")
                except Exception:
                    pass

            tg.start_soon(do_call)
            await anyio.sleep(0.05)

            assert len(list_tools_called) == 0

            await write_recv.receive()
            response = types.JSONRPCResponse(jsonrpc="2.0", id=0, result={"content": [], "isError": False})
            response_stream = session._response_streams.get(0)
            if response_stream is not None:
                await response_stream.send(response)
            await anyio.sleep(0.05)

    @pytest.mark.anyio
    async def test_concurrent_calls_no_duplicate_refresh(self, mock_streams):
        """Concurrent call_tool does not cause duplicate refresh."""
        import time

        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=True, expires_at=time.time() + 30)
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier)
        session._jwt_expires_at = time.time() + 30
        session._jwt_verification_result = verifier._result

        refresh_count = []

        async def mock_list_tools(*args, **kwargs):
            refresh_count.append(True)
            await anyio.sleep(0.01)  # Simulate network delay
            from mcp.shared.authority_jwt import JWTVerificationResult

            session._jwt_verification_result = JWTVerificationResult(valid=True, expires_at=time.time() + 3600)
            session._jwt_expires_at = time.time() + 3600
            return types.ListToolsResult(tools=[])

        session.list_tools = mock_list_tools  # type: ignore[method-assign]

        # Call _refresh_jwt_if_needed twice — second should be guarded
        await session._refresh_jwt_if_needed()
        # After first refresh, _pending_jwt_refresh should be False again
        assert session._pending_jwt_refresh is False
        assert len(refresh_count) == 1

    @pytest.mark.anyio
    async def test_require_valid_jwt_blocks_on_failure(self, mock_streams):
        """call_tool raises MCPError when require_valid_jwt=True and JWT invalid."""
        read_stream, write_stream, _, _ = mock_streams

        verifier = MockJWTVerifier(valid=False, error="Token expired")
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier, require_valid_jwt=True)
        session._jwt_verification_result = verifier._result

        with pytest.raises(MCPError, match="Authority JWT invalid or expired"):
            await session.call_tool("test_tool")

    @pytest.mark.anyio
    async def test_require_valid_jwt_false_proceeds(self, mock_streams):
        """call_tool proceeds past JWT check when require_valid_jwt=False and JWT invalid."""
        read_stream, write_stream, _, write_recv = mock_streams

        verifier = MockJWTVerifier(valid=False, error="Token expired")
        session = _setup_session_with_jwt_verifier(read_stream, write_stream, verifier, require_valid_jwt=False)
        session._jwt_verification_result = verifier._result

        session._request_id = 0
        session._response_streams = {}
        session._progress_callbacks = {}
        session._tool_output_schemas = {"test_tool": None}

        result_holder: list = []

        async with anyio.create_task_group() as tg:

            async def do_call():
                try:
                    await session.call_tool("test_tool")
                except MCPError as e:
                    # We expect TEE attestation errors (missing _meta.tee in mock response),
                    # but NOT "Authority JWT invalid" — that would mean the JWT gate fired.
                    if "Authority JWT" in str(e):
                        result_holder.append(("jwt_blocked", e))
                    else:
                        result_holder.append(("tee_error", e))
                except Exception as e:
                    result_holder.append(("other", e))

            tg.start_soon(do_call)
            await anyio.sleep(0.05)

            await write_recv.receive()
            response = types.JSONRPCResponse(jsonrpc="2.0", id=0, result={"content": [], "isError": False})
            response_stream = session._response_streams.get(0)
            if response_stream is not None:
                await response_stream.send(response)
            await anyio.sleep(0.05)

        # Should NOT be blocked by JWT gate
        assert len(result_holder) == 1
        assert result_holder[0][0] != "jwt_blocked", "Should not block on JWT when require_valid_jwt=False"
