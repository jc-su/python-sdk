"""TrustedClientSession - MCP ClientSession with per-call TEE attestation on tool calls.

Bootstrap (key exchange via X25519 ECDH):
1. initialize request  — plaintext + evidence (client sends X25519 public key)
2. initialize response — plaintext + evidence (server sends X25519 public key + challenge)
3. initialized notif   — HMAC challenge-response (key possession proof)

Post-bootstrap tool calls (session-key encryption, no TDX quotes):
4+ tools/call only     — encrypted with session_key (AES-256-GCM)

Usage:
    async with TrustedClientSession(read_stream, write_stream) as session:
        result = await session.initialize()
        if session.is_server_attested:
            print(f"Server verified: {session.server_cgroup}")
"""

from __future__ import annotations

import base64
import logging
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.shared.authority_jwt import AuthorityJWTVerifier, JWTVerificationResult

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

import mcp.types as types
from mcp.client.experimental.task_handlers import ExperimentalTaskHandlers
from mcp.client.session import (
    ClientSession,
    ElicitationFnT,
    ListRootsFnT,
    LoggingFnT,
    MessageHandlerFnT,
    SamplingFnT,
)
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage
from mcp.shared.tee_envelope import (
    create_request_envelope,
    create_session_envelope,
    create_tool_request_envelope,
    open_response_envelope,
    open_tool_response_envelope,
    verify_session_envelope,
)
from mcp.shared.tee_helpers import extract_tee_from_result, inject_tee
from mcp.types import JSONRPCNotification

logger = logging.getLogger(__name__)

# Import SecureEndpoint and AttestationEvidence at module level for easier testing
try:
    from mcp.shared.secure_channel import AttestationEvidence, SecureEndpoint

    _TEE_AVAILABLE = True
except ImportError:
    SecureEndpoint = None  # type: ignore
    AttestationEvidence = None  # type: ignore
    _TEE_AVAILABLE = False


class TrustedClientSession(ClientSession):
    """MCP ClientSession with unified per-call TEE attestation.

    The initialize exchange bootstraps key exchange (plaintext + evidence).
    Post-bootstrap tools/call uses session-key AES-256-GCM encryption.

    TEE injection/verification is handled by _prepare_request_data and
    _process_raw_response hooks (overrides of BaseSession), so call_tool()
    works transparently via the parent class.
    """

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        read_timeout_seconds: timedelta | None = None,
        sampling_callback: SamplingFnT | None = None,
        elicitation_callback: ElicitationFnT | None = None,
        list_roots_callback: ListRootsFnT | None = None,
        logging_callback: LoggingFnT | None = None,
        message_handler: MessageHandlerFnT | None = None,
        client_info: types.Implementation | None = None,
        *,
        sampling_capabilities: types.SamplingCapability | None = None,
        experimental_task_handlers: ExperimentalTaskHandlers | None = None,
        # TEE-specific options
        tee_enabled: bool = True,
        allowed_server_rtmr3: list[str] | None = None,
        workload_id: str | None = None,
        # JWT verification
        jwt_verifier: AuthorityJWTVerifier | None = None,
        require_valid_jwt: bool = False,
        # Multi-hop propagation
        upstream_tokens: list[dict[str, str]] | None = None,
    ) -> None:
        super().__init__(
            read_stream,
            write_stream,
            read_timeout_seconds=read_timeout_seconds,
            sampling_callback=sampling_callback,
            elicitation_callback=elicitation_callback,
            list_roots_callback=list_roots_callback,
            logging_callback=logging_callback,
            message_handler=message_handler,
            client_info=client_info,
            sampling_capabilities=sampling_capabilities,
            experimental_task_handlers=experimental_task_handlers,
        )

        # TEE settings
        self._tee_enabled = tee_enabled
        self._allowed_server_rtmr3 = allowed_server_rtmr3
        self._workload_id = workload_id

        # TEE state
        self._endpoint: Any = None
        self._server_attested = False
        self._peer_verified = False

        # Per-request TEE request state
        self._tee_request_kinds: dict[int, str] = {}
        # Per-request init sig_data for session binding
        self._init_sig_data_by_request: dict[int, bytes] = {}
        self._pending_challenge: bytes | None = None
        # Latest server trust info from tools/list response
        self._server_trust_info: dict[str, Any] | None = None

        # JWT verification state
        self._jwt_verifier: AuthorityJWTVerifier | None = jwt_verifier
        self._require_valid_jwt = require_valid_jwt
        self._jwt_verification_result: JWTVerificationResult | None = None
        self._jwt_expires_at: float = 0.0
        self._jwt_refresh_margin_s: float = 60.0
        self._pending_jwt_refresh: bool = False

        # Multi-hop propagation
        self._upstream_tokens: list[dict[str, str]] = upstream_tokens or []

        # Initialize endpoint if TEE enabled
        if self._tee_enabled:
            if _TEE_AVAILABLE and SecureEndpoint is not None:
                self._endpoint = SecureEndpoint.create(
                    role="client",
                )
            else:
                logger.warning("TEE dependencies not available, disabling TEE")
                self._tee_enabled = False

    # =========================================================================
    # Overrides
    # =========================================================================

    async def initialize(self) -> types.InitializeResult:
        """Initialize MCP session with unified per-call TEE attestation.

        1. Sends initialize request with _meta.tee evidence (plaintext, no encryption)
        2. Verifies server's _meta.tee evidence in response (via _process_raw_response hook)
        3. Sends initialized notification with optional HMAC challenge response
        """
        from mcp.client.session import (
            _default_elicitation_callback,
            _default_list_roots_callback,
            _default_sampling_callback,
        )
        from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

        sampling = (
            (self._sampling_capabilities or types.SamplingCapability())
            if self._sampling_callback is not _default_sampling_callback
            else None
        )
        elicitation = (
            types.ElicitationCapability(
                form=types.FormElicitationCapability(),
                url=types.UrlElicitationCapability(),
            )
            if self._elicitation_callback is not _default_elicitation_callback
            else None
        )
        roots = (
            types.RootsCapability(listChanged=True)
            if self._list_roots_callback is not _default_list_roots_callback
            else None
        )

        # send_request → _prepare_request_data injects _meta.tee
        #               → _process_raw_response verifies server's _meta.tee
        result = await self.send_request(
            types.InitializeRequest(
                params=types.InitializeRequestParams(
                    protocolVersion=types.LATEST_PROTOCOL_VERSION,
                    capabilities=types.ClientCapabilities(
                        sampling=sampling,
                        elicitation=elicitation,
                        roots=roots,
                        tasks=self._task_handlers.build_capability(),
                    ),
                    clientInfo=self._client_info,
                ),
            ),
            types.InitializeResult,
        )

        if result.protocolVersion not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RuntimeError(f"Unsupported protocol version: {result.protocolVersion}")

        self._server_capabilities = result.capabilities

        # Send initialized notification with optional HMAC challenge response
        if self._pending_challenge is not None and self._tee_enabled and self._endpoint is not None:
            await self._send_initialized_with_challenge(self._pending_challenge)
            self._pending_challenge = None
        else:
            await self.send_notification(types.InitializedNotification())

        return result

    # =========================================================================
    # Hook overrides (called by BaseSession.send_request)
    # =========================================================================

    def _prepare_request_data(self, request_id: int, request_data: Any) -> Any:
        """Inject _meta.tee evidence into outgoing requests."""
        if not self._tee_enabled or self._endpoint is None:
            return request_data

        method = request_data.get("method", "")
        params_dict = request_data.get("params", {})

        if method == "initialize":
            self._tee_request_kinds[request_id] = "initialize"
            # Plaintext evidence only — don't know server key yet
            tee_dict, _ = create_request_envelope(
                self._endpoint,
                params_dict,
                peer_role="server",
                workload_id=self._workload_id,
            )
            inject_tee(request_data, tee_dict, params_level=True)
            # Save our sig_data for session binding in _process_raw_response
            self._init_sig_data_by_request[request_id] = base64.b64decode(tee_dict["sig_data"])
            logger.info("Added TEE evidence to initialize request")

        elif method == "tools/list":
            if self._endpoint is not None and self._endpoint.session_id is not None:
                self._tee_request_kinds[request_id] = "tools/list"
                tee_dict = create_session_envelope(self._endpoint)
                inject_tee(request_data, tee_dict, params_level=True)

        elif method == "tools/call":
            self._tee_request_kinds[request_id] = "tools/call"
            # Post-bootstrap: encrypt with session_key
            if self._endpoint.session_key is not None:
                tee_dict = create_tool_request_envelope(
                    self._endpoint,
                    params_dict,
                    upstream_tokens=self._upstream_tokens or None,
                )
                inject_tee(request_data, tee_dict, params_level=True)
                # Strip plaintext params, keep only _meta
                request_data["params"] = {"_meta": params_dict["_meta"]}
            else:
                # Fallback: plaintext evidence (pre-session)
                tee_dict, _ = create_request_envelope(
                    self._endpoint,
                    params_dict,
                    peer_role="server",
                )
                inject_tee(request_data, tee_dict, params_level=True)

        return request_data

    def _process_raw_response(self, request_id: int, result: Any) -> Any:
        """Verify server's _meta.tee and decrypt response if encrypted."""
        if not self._tee_enabled or self._endpoint is None or not isinstance(result, dict) or not result:
            return result

        request_kind = self._tee_request_kinds.get(request_id)
        if request_kind not in ("initialize", "tools/call", "tools/list"):
            return result

        if request_kind == "tools/list":
            server_tee = extract_tee_from_result(result)
            if server_tee:
                valid, error = verify_session_envelope(self._endpoint, server_tee)
                if valid:
                    self._server_trust_info = server_tee.get("server_trust")
                    self._verify_authority_jwt()
                else:
                    logger.warning("tools/list session envelope verification failed: %s", error)
            return result

        server_tee = extract_tee_from_result(result)
        is_tool_call = request_kind == "tools/call"

        if not server_tee:
            if is_tool_call:
                raise MCPError(
                    code=types.INVALID_PARAMS,
                    message="Server per-call attestation missing in tool response",
                )
            return result

        if is_tool_call and self._endpoint.session_key is not None:
            # Post-bootstrap: decrypt with session_key
            decrypted, valid, error = open_tool_response_envelope(
                self._endpoint,
                server_tee,
            )
            if not valid:
                logger.error("Server per-call attestation failed: %s", error)
                raise MCPError(
                    code=types.INVALID_PARAMS,
                    message=f"Server per-call attestation failed: {error}",
                )
            if decrypted is not None:
                result = {**result, **decrypted}
        elif is_tool_call:
            # Pre-session tool call (shouldn't normally happen)
            decrypted, valid, error = open_response_envelope(
                self._endpoint,
                server_tee,
                peer_role="server",
                allowed_rtmr3=self._allowed_server_rtmr3,
            )
            if not valid:
                logger.error("Server per-call attestation failed: %s", error)
                raise MCPError(
                    code=types.INVALID_PARAMS,
                    message=f"Server per-call attestation failed: {error}",
                )
        else:
            # Initialize response: verify evidence and establish session
            decrypted, valid, error = open_response_envelope(
                self._endpoint,
                server_tee,
                peer_role="server",
                allowed_rtmr3=self._allowed_server_rtmr3,
            )
            if valid:
                self._server_attested = True
                self._peer_verified = True
                logger.info("Server attested via initialize response")

                server_init_sig_data = base64.b64decode(server_tee["sig_data"])
                server_pubkey_raw = base64.b64decode(server_tee["public_key"])

                # Extract bootstrap challenge if present
                challenge_b64 = server_tee.get("challenge")
                if challenge_b64:
                    self._pending_challenge = base64.b64decode(challenge_b64)

                # Establish session binding (ECDH + HKDF)
                init_sig_data = self._init_sig_data_by_request.get(request_id)
                if init_sig_data is not None:
                    self._endpoint.establish_session(server_pubkey_raw, init_sig_data, server_init_sig_data)
            else:
                logger.error("Server attestation failed: %s", error)

        return result

    def _finalize_request(self, request_id: int) -> None:
        """Clean up per-request TEE state."""
        self._tee_request_kinds.pop(request_id, None)
        self._init_sig_data_by_request.pop(request_id, None)

    # =========================================================================
    # Internal helpers
    # =========================================================================

    async def _send_initialized_with_challenge(self, challenge: bytes) -> None:
        """Send initialized notification with HMAC-SHA256 challenge MAC.

        Proves the client derived the same session keys via ECDH (~100ms saved
        vs TDX quote). The client's TEE identity was already proven in
        Message 1's quote; Message 3 proves shared key derivation by MACing
        the server's challenge with mac_key.
        """
        challenge_mac = self._endpoint.create_challenge_mac(challenge)

        tee_dict = {
            "challenge_response": base64.b64encode(challenge).decode(),
            "challenge_mac": base64.b64encode(challenge_mac).decode(),
        }

        # Build notification with _meta.tee
        notif = types.InitializedNotification(params=types.NotificationParams(_meta={}))
        notif_data = notif.model_dump(by_alias=True, mode="json", exclude_none=True)
        inject_tee(notif_data, tee_dict, params_level=True)

        jsonrpc_notif = JSONRPCNotification(jsonrpc="2.0", **notif_data)
        await self._write_stream.send(SessionMessage(message=jsonrpc_notif))
        logger.info("Sent initialized with challenge MAC")

    def add_upstream_token(self, token: str, role: str, subject: str) -> None:
        """Add an upstream attestation JWT for multi-hop propagation."""
        self._upstream_tokens.append({"token": token, "role": role, "subject": subject})

    def _verify_authority_jwt(self) -> None:
        """Verify attestation_token JWT from server_trust_info."""
        if self._jwt_verifier is None or self._server_trust_info is None:
            return
        token = self._server_trust_info.get("attestation_token", "")
        if not token:
            return
        result = self._jwt_verifier.verify_attestation_token(
            token,
            expected_subject=self.server_cgroup if self.server_cgroup else None,
            expected_rtmr3=self.server_rtmr3.hex() if self.server_rtmr3 != bytes(48) else None,
        )
        self._jwt_verification_result = result
        self._jwt_expires_at = result.expires_at
        if not result.valid:
            logger.warning("Authority JWT verification failed: %s", result.error)

    def _should_refresh_jwt(self) -> bool:
        """Check if the authority JWT needs refreshing."""
        if self._jwt_expires_at <= 0 or self._jwt_verifier is None:
            return False
        remaining = self._jwt_expires_at - time.time()
        return remaining < self._jwt_refresh_margin_s

    async def _refresh_jwt_if_needed(self) -> None:
        """Refresh the authority JWT if nearing expiry via tools/list round-trip."""
        if not self._should_refresh_jwt() or self._pending_jwt_refresh:
            return
        self._pending_jwt_refresh = True
        try:
            await self.list_tools()  # round-trip: server re-queries authority → fresh JWT
        finally:
            self._pending_jwt_refresh = False

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
        progress_callback: Any = None,
        *,
        meta: dict[str, Any] | None = None,
    ) -> types.CallToolResult:
        """Send a tools/call request with JWT expiry check and re-attestation."""
        if self._tee_enabled and self._jwt_verifier is not None:
            await self._refresh_jwt_if_needed()
            if self._require_valid_jwt and not self.jwt_valid:
                raise MCPError(
                    code=types.INVALID_REQUEST,
                    message="Authority JWT invalid or expired; re-attestation failed",
                )
        return await super().call_tool(name, arguments, read_timeout_seconds, progress_callback, meta=meta)

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def jwt_verification_result(self) -> JWTVerificationResult | None:
        """Latest JWT verification result."""
        return self._jwt_verification_result

    @property
    def jwt_expires_at(self) -> float:
        """Expiry time of the current authority JWT (epoch seconds)."""
        return self._jwt_expires_at

    @property
    def jwt_valid(self) -> bool:
        """Whether the current authority JWT is verified and valid."""
        return self._jwt_verification_result is not None and self._jwt_verification_result.valid

    @property
    def tee_enabled(self) -> bool:
        """Check if TEE is enabled."""
        return self._tee_enabled

    @property
    def is_server_attested(self) -> bool:
        """Check if server attestation succeeded."""
        return self._server_attested

    @property
    def peer_verified(self) -> bool:
        """Check if peer has been verified via _meta.tee."""
        return self._peer_verified

    @property
    def server_cgroup(self) -> str:
        """Get attested server's cgroup path."""
        if not self._server_attested or self._endpoint is None:
            return ""
        peer = self._endpoint.get_peer("server")
        return peer.cgroup if peer else ""

    @property
    def server_rtmr3(self) -> bytes:
        """Get attested server's RTMR3 value."""
        if not self._server_attested or self._endpoint is None:
            return bytes(48)
        peer = self._endpoint.get_peer("server")
        return peer.rtmr3 if peer else bytes(48)

    @property
    def server_trust_info(self) -> dict[str, Any] | None:
        """Latest trust info from tools/list response."""
        return self._server_trust_info

    @property
    def endpoint(self) -> Any:
        """Get the SecureEndpoint for advanced operations."""
        return self._endpoint
