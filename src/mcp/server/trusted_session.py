"""TrustedServerSession - MCP ServerSession with per-call TEE attestation on tool calls.

Bootstrap (key exchange via X25519 ECDH):
1. initialize request  — plaintext + evidence (client sends X25519 public key)
2. initialize response — plaintext + evidence (server sends X25519 public key + challenge)
3. initialized notif   — HMAC challenge-response (key possession proof)

Post-bootstrap tool calls (session-key encryption, no TDX quotes):
4+ tools/call only     — envelope encryption (AES Key Wrap + AES-256-GCM)

Usage:
    # Usually created internally by TrustedMCP, but can be used directly:
    session = TrustedServerSession(read_stream, write_stream, init_options)
    if session.is_client_attested:
        print(f"Client verified: {session.client_cgroup}")
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp.server.authorization import AuthorizationManager
    from mcp.server.tool_trust import ToolTrustManager
    from mcp.shared.attestation_policy import AttestationPolicy, PolicyRegistry
    from mcp.shared.authority_jwt import AuthorityJWTVerifier

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

import mcp.types as types
from mcp.server.models import InitializationOptions
from mcp.server.session import InitializationState, ServerSession
from mcp.shared.message import MessageMetadata, SessionMessage
from mcp.shared.session import RequestResponder
from mcp.shared.tee_envelope import (
    create_bootstrap_envelope,
    create_encrypted_envelope,
    create_session_envelope,
    extract_tee,
    inject_tee,
    verify_bootstrap_envelope,
    verify_encrypted_envelope,
)
from mcp.types import (
    INVALID_REQUEST,
    ErrorData,
    JSONRPCResponse,
    RequestId,
)

logger = logging.getLogger(__name__)

try:
    from mcp.shared.secure_channel import SecureEndpoint
except ImportError:
    SecureEndpoint = None  # type: ignore


def _extract_tool_subject(tool_data: dict[str, Any]) -> str:
    """Extract authority subject hint from tool _meta."""
    meta = tool_data.get("_meta")
    if not isinstance(meta, dict):
        return ""

    tee_meta = meta.get("tee")
    if isinstance(tee_meta, dict):
        for key in ("subject", "authority_subject", "tool_subject"):
            value = tee_meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    attestation_meta = meta.get("attestation")
    if isinstance(attestation_meta, dict):
        value = attestation_meta.get("subject")
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in ("subject", "authority_subject", "tool_subject", "attestation_subject", "cgroup", "cgroup_path"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def _build_tool_subject_map(tools: list[dict[str, Any]]) -> dict[str, str]:
    """Build tool_name->subject map from tools/list payload."""
    tool_subjects: dict[str, str] = {}
    for tool in tools:
        tool_name = tool.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            continue
        subject = _extract_tool_subject(tool)
        if subject:
            tool_subjects[tool_name] = subject
    return tool_subjects


class TrustedServerSession(ServerSession):
    """MCP ServerSession with per-call TEE attestation on tool calls.

    The initialize exchange bootstraps key exchange (plaintext + evidence).
    Post-bootstrap tools/call uses session-key AES-256-GCM encryption.
    """

    def __init__(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        init_options: InitializationOptions,
        stateless: bool = False,
        *,
        # TEE-specific options
        tee_enabled: bool = True,
        require_client_attestation: bool = False,
        allowed_client_rtmr3: list[str] | None = None,
        rtmr3_transition_policy: str = "log_and_accept",
        policy_registry: PolicyRegistry | None = None,
        quote_mode: str = "session",
        authority_enabled: bool = True,
        tool_trust_manager: ToolTrustManager | None = None,
        # JWT verification for upstream tokens
        jwt_verifier: AuthorityJWTVerifier | None = None,
        require_upstream_jwt: bool = False,
        # Semantic authorization
        authorization_manager: AuthorizationManager | None = None,
    ) -> None:
        super().__init__(read_stream, write_stream, init_options, stateless)

        # Env-var overrides for ablation studies. See mcp.server.tee_config.
        # Import here to keep module-load order clean.
        from mcp.server.tee_config import resolve_from_env

        _resolved = resolve_from_env(
            tee_enabled=tee_enabled,
            require_client_attestation=require_client_attestation,
            quote_mode=quote_mode,
            authority_enabled=authority_enabled,
            rtmr3_transition_policy=rtmr3_transition_policy,
            policy_registry=policy_registry,
            allowed_client_rtmr3=allowed_client_rtmr3,
        )

        # TEE settings
        self._tee_enabled = _resolved["tee_enabled"]
        self._require_client_attestation = _resolved["require_client_attestation"]
        self._allowed_client_rtmr3 = _resolved["allowed_client_rtmr3"]
        self._rtmr3_transition_policy = _resolved["rtmr3_transition_policy"]
        self._policy_registry = _resolved["policy_registry"]
        self._quote_mode = _resolved["quote_mode"]
        self._authority_enabled = _resolved["authority_enabled"]

        self._active_policy: AttestationPolicy | None = None
        self._tool_trust_manager: ToolTrustManager | None = tool_trust_manager
        self._jwt_verifier: AuthorityJWTVerifier | None = jwt_verifier
        self._require_upstream_jwt = require_upstream_jwt
        self._authorization_manager: AuthorizationManager | None = authorization_manager

        # Per-tool RTMR3 cache for quote_mode in {per_tool_first, per_tool_every}.
        # Key: tool_name; value: last-verified RTMR3 hex (96 chars). Used to
        # detect drift between the session-init quote and subsequent tool
        # dispatches without regenerating a full TDX quote each time.
        self._tool_rtmr3_cache: dict[str, str] = {}

        # TEE state
        self._endpoint: SecureEndpoint | None = None
        self._client_attested = False
        self._peer_verified = False
        self._client_attestation_token: str = ""

        # Track which request IDs need TEE in the response
        self._tee_request_ids: set[RequestId] = set()
        # Track which request IDs are tools/list for trust metadata injection
        self._tools_list_request_ids: set[RequestId] = set()
        # Requests already verified/decrypted during preprocess hook
        self._preverified_request_ids: set[RequestId] = set()
        # Track visible tool set for list_changed notifications
        self._visible_tools_snapshot: frozenset[str] | None = None
        self._last_notified_trust_revision: int = 0

        # Initialize endpoint if TEE enabled
        if self._tee_enabled:
            if SecureEndpoint is not None:
                from mcp.shared.secure_channel import RTMR3TransitionPolicy

                policy_map = {
                    "accept": RTMR3TransitionPolicy.ACCEPT,
                    "reject": RTMR3TransitionPolicy.REJECT,
                    "log_and_accept": RTMR3TransitionPolicy.LOG_AND_ACCEPT,
                }
                self._endpoint = SecureEndpoint.create(
                    role="server",
                )
                self._endpoint.rtmr3_transition_policy = policy_map.get(
                    rtmr3_transition_policy, RTMR3TransitionPolicy.LOG_AND_ACCEPT
                )

                # Capture initial RTMR3 for self-check before decrypt
                try:
                    from mcp.shared.tdx import get_container_rtmr3

                    initial = get_container_rtmr3()
                    if initial != bytes(48):
                        self._endpoint._initial_rtmr3 = initial
                        logger.debug("Captured initial RTMR3 for self-check")
                except Exception:
                    logger.debug("Could not capture initial RTMR3", exc_info=True)
            else:
                logger.warning("TEE dependencies not available, disabling TEE")
                self._tee_enabled = False

    def _current_allowed_rtmr3(self) -> list[str] | None:
        """Resolve active RTMR3 allowlist with policy override."""
        allowed_rtmr3 = self._allowed_client_rtmr3
        if self._active_policy is not None and self._active_policy.allowed_rtmr3 is not None:
            allowed_rtmr3 = self._active_policy.allowed_rtmr3
        return allowed_rtmr3

    def _preprocess_incoming_request_data(
        self,
        request_data: dict,
        message_metadata: MessageMetadata = None,
    ) -> dict:
        """Preprocess encrypted tools/call before schema validation.

        Post-bootstrap tools/call encrypts params with envelope encryption. This hook
        decrypts and restores params early so normal validation and routing work.
        """
        if not self._tee_enabled or self._endpoint is None:
            return request_data

        if request_data.get("method") != "tools/call":
            return request_data

        params = request_data.get("params")
        if not isinstance(params, dict):
            return request_data

        # Plaintext tools/call already has schema-required fields.
        if "name" in params:
            return request_data

        meta = params.get("_meta")
        tee_dict = meta.get("tee") if isinstance(meta, dict) else None
        if not isinstance(tee_dict, dict):
            return request_data

        # Use tool envelope (session-key decryption, no TDX quote)
        decrypted_params, valid, error = verify_encrypted_envelope(
            self._endpoint,
            tee_dict,
            self_check_rtmr3=True,
        )
        if not valid:
            logger.error("Client TEE verification failed before request validation: %s", error)
            return request_data

        if not isinstance(decrypted_params, dict):
            logger.error("Encrypted tools/call did not contain decryptable params")
            return request_data

        tool_name = decrypted_params.get("name")
        if not isinstance(tool_name, str) or tool_name == "":
            logger.error("Encrypted tools/call missing valid tool name")
            return request_data

        # Restore plaintext fields needed for schema validation/dispatch.
        params.update(decrypted_params)

        request_id = request_data.get("id")
        if request_id is not None:
            self._tee_request_ids.add(request_id)
            self._preverified_request_ids.add(request_id)

        return request_data

    async def _received_request(self, responder: RequestResponder[types.ClientRequest, types.ServerResult]) -> None:
        """Handle incoming requests with TEE attestation on tool calls only."""
        await self._notify_trust_change()

        match responder.request:
            case types.InitializeRequest(params=params):
                await self._handle_initialize_request(responder, params)

            case types.ListToolsRequest():
                # Mark for trust metadata injection in response
                if self._tee_enabled and self._endpoint is not None and self._endpoint.session_id is not None:
                    self._tee_request_ids.add(responder.request_id)
                    self._tools_list_request_ids.add(responder.request_id)
                await super()._received_request(responder)

            case types.CallToolRequest():
                tool_name = getattr(responder.request.params, "name", "")

                # Fast-path 1: check tool trust BEFORE expensive attestation
                if self._tee_enabled and self._endpoint is not None and self._tool_trust_manager is not None:
                    trust_info = self._tool_trust_manager.get_tool_trust_state(
                        tool_name,
                        require_fresh=True,
                    )
                    if not self._tool_trust_manager.is_tool_trusted(tool_name, trust_info=trust_info):
                        logger.error(
                            "Tool '%s' blocked by trust policy: status=%s policy_action=%s version=%s source=%s",
                            tool_name,
                            trust_info.status,
                            trust_info.policy_action,
                            trust_info.version,
                            trust_info.source,
                        )
                        self._tool_trust_manager.trigger_remediation(
                            tool_name,
                            action=trust_info.policy_action,
                        )
                        with responder:
                            await responder.respond(
                                ErrorData(
                                    code=INVALID_REQUEST,
                                    message=(
                                        f"Tool '{tool_name}' blocked by trust policy: "
                                        f"status={trust_info.status}, "
                                        f"policy_action={trust_info.policy_action}, "
                                        f"version={trust_info.version}"
                                    ),
                                )
                            )
                        return

                # Fast-path 2: semantic authorization check
                if self._authorization_manager is not None and tool_name:
                    client_subject = self._client_subject()
                    tool_arguments = None
                    params = responder.request.params
                    if params is not None:
                        raw_args = getattr(params, "arguments", None)
                        if isinstance(raw_args, dict):
                            tool_arguments = raw_args
                    auth_decision = self._authorization_manager.authorize(
                        client_subject, tool_name, arguments=tool_arguments
                    )
                    if not auth_decision.authorized:
                        logger.warning(
                            "Tool '%s' blocked by authorization: %s (rule=%s, subject=%s)",
                            tool_name,
                            auth_decision.reason,
                            auth_decision.matched_rule,
                            client_subject,
                        )
                        with responder:
                            await responder.respond(
                                ErrorData(
                                    code=INVALID_REQUEST,
                                    message=f"Authorization denied for tool '{tool_name}': {auth_decision.reason}",
                                )
                            )
                        return

                # quote_mode per-tool policy: snapshot/verify RTMR3 via trustd.
                # This runs BEFORE the encrypted-envelope decrypt below so an
                # RTMR3-reject short-circuits before we pay AES-GCM cost.
                if self._tee_enabled and self._quote_mode in ("per_tool_first", "per_tool_every"):
                    ok, err = self._check_tool_rtmr3_policy(tool_name)
                    if not ok:
                        logger.error("Tool '%s' blocked by quote_mode=%s: %s",
                                     tool_name, self._quote_mode, err)
                        with responder:
                            await responder.respond(
                                ErrorData(
                                    code=INVALID_REQUEST,
                                    message=f"RTMR3 policy violation for tool '{tool_name}': {err}",
                                )
                            )
                        return

                # Tool calls get per-call TEE attestation + encryption
                if self._tee_enabled and self._endpoint is not None:
                    if not self._verify_and_decrypt_request(responder):
                        return
                await super()._received_request(responder)

            case _:
                # All other requests pass through without TEE
                await super()._received_request(responder)

    def _check_tool_rtmr3_policy(self, tool_name: str) -> tuple[bool, str | None]:
        """Enforce quote_mode per-tool RTMR3 check via trustd.

        Only called when self._quote_mode ∈ {per_tool_first, per_tool_every}.
        Behaviour:

          - per_tool_first: on first call per tool, snapshot current RTMR3
            into self._tool_rtmr3_cache. Subsequent calls skip the RPC.
          - per_tool_every: on every call, RPC to trustd.VerifyRtmr3 against
            the cached (first-call) RTMR3. Mismatch goes through
            self._rtmr3_transition_policy (accept / reject / log_and_accept).

        Returns (ok, err_msg). `ok=False` blocks the tool call.

        Graceful degradation: if trustd socket is unreachable or the
        workload id isn't set (non-TD environments), the check is a
        passthrough — we don't block the request; the ablation just
        measures "no-op overhead" in that case.
        """
        # Soft import — avoids pulling trustd client at module load time.
        import os

        from mcp.shared.trustd_client import get_trustd_client

        client = get_trustd_client()
        if client is None:
            return True, None  # no trustd socket — can't check, passthrough
        workload_id = os.environ.get("TEE_MCP_WORKLOAD_ID", "")
        if not workload_id:
            return True, None  # not running under trustd — passthrough

        cached = self._tool_rtmr3_cache.get(tool_name)

        # per_tool_first short-circuits as soon as we have a snapshot.
        if self._quote_mode == "per_tool_first" and cached:
            return True, None

        # Need an RPC. If we don't have a cached "expected" yet, use a
        # sentinel of all-zeros so trustd's response `current_rtmr3_hex`
        # becomes our snapshot. Subsequent per_tool_every calls then
        # verify against that cached value.
        expected = cached if cached else "0" * 96

        try:
            result = client.verify_rtmr3(workload_id, expected)
        except Exception as exc:  # noqa: BLE001 — transport errors shouldn't block the request
            logger.warning("verify_rtmr3 failed for %s: %s", tool_name, exc)
            return True, None

        current = result.get("current_rtmr3_hex", "")

        # First-call snapshot: record and accept.
        if not cached:
            if current:
                self._tool_rtmr3_cache[tool_name] = current
            return True, None

        # Subsequent call: compare.
        if result.get("match", False):
            return True, None

        policy = self._rtmr3_transition_policy
        msg = (
            f"RTMR3 drift (tool={tool_name}): "
            f"expected={expected[:16]}..., current={current[:16]}..."
        )
        if policy == "reject":
            return False, msg
        # accept / log_and_accept: permit the call; update cache so repeated
        # drifts of the same magnitude don't spam logs.
        if policy == "log_and_accept":
            logger.warning(msg)
        if current:
            self._tool_rtmr3_cache[tool_name] = current
        return True, None

    def _verify_and_decrypt_request(self, responder: RequestResponder[types.ClientRequest, types.ServerResult]) -> bool:
        """Verify client's _meta.tee from request and optionally decrypt params.

        Returns True if verification passed (or not present and not required).
        """
        if responder.request_id in self._preverified_request_ids:
            self._preverified_request_ids.discard(responder.request_id)
            return True

        params = responder.request.params
        tee_dict = extract_tee(params)

        if tee_dict is None:
            if self._require_client_attestation:
                logger.error("TEE evidence required but not provided in request")
                return False
            return True

        # Use tool envelope (session-key decryption, no TDX quote)
        decrypted_params, valid, error = verify_encrypted_envelope(
            self._endpoint,
            tee_dict,
            self_check_rtmr3=True,
        )

        if not valid:
            logger.error("Client TEE verification failed: %s", error)
            return not self._require_client_attestation

        # Merge decrypted params (if present) into validated request params.
        if isinstance(decrypted_params, dict) and params is not None:
            if "name" in decrypted_params:
                params.name = decrypted_params["name"]
            if "arguments" in decrypted_params:
                params.arguments = decrypted_params["arguments"]

        # Verify upstream tokens (multi-hop propagation)
        upstream_tokens = tee_dict.get("upstream_tokens")
        if upstream_tokens and isinstance(upstream_tokens, list) and self._jwt_verifier is not None:
            for upstream_token in upstream_tokens:
                if not isinstance(upstream_token, dict):
                    continue
                token_str = upstream_token.get("token", "")
                if token_str:
                    jwt_result = self._jwt_verifier.verify_attestation_token(token_str)
                    if not jwt_result.valid:
                        logger.warning(
                            "Upstream token invalid for role=%s: %s",
                            upstream_token.get("role"),
                            jwt_result.error,
                        )
                        if self._require_upstream_jwt:
                            return False

        # Mark this request for TEE response
        self._tee_request_ids.add(responder.request_id)

        return True

    def _on_request_validation_error(self, request_id: RequestId, error: Exception) -> None:
        """Clear per-request TEE state when validation fails before dispatch."""
        self._tee_request_ids.discard(request_id)
        self._tools_list_request_ids.discard(request_id)
        self._preverified_request_ids.discard(request_id)

    def _supports_tool_list_changed(self) -> bool:
        tools_cap = getattr(self._init_options.capabilities, "tools", None)
        return bool(getattr(tools_cap, "listChanged", False))

    async def _notify_trust_change(self) -> None:
        """Send tools/list_changed when trust revision changes after initial discovery."""
        if self._tool_trust_manager is None:
            return
        if self._initialization_state != InitializationState.Initialized:
            return
        if not self._supports_tool_list_changed():
            return
        if self._visible_tools_snapshot is None:
            return

        revision = int(getattr(self._tool_trust_manager, "revision", 0))
        if revision <= self._last_notified_trust_revision:
            return
        self._last_notified_trust_revision = revision
        await self.send_tool_list_changed()

    async def _notify_visibility_change(self, visible_tools: set[str]) -> None:
        """Notify client when tool visibility has changed."""
        snapshot = frozenset(visible_tools)
        previous = self._visible_tools_snapshot
        self._visible_tools_snapshot = snapshot

        if previous is None:
            return
        if snapshot == previous:
            return
        if self._initialization_state != InitializationState.Initialized:
            return
        if not self._supports_tool_list_changed():
            return

        await self.send_tool_list_changed()

    async def _send_response(self, request_id: RequestId, response: types.ServerResult | ErrorData) -> None:
        """Send response with _meta.tee evidence only for tool call responses."""
        is_tee_request = request_id in self._tee_request_ids
        is_tools_list = request_id in self._tools_list_request_ids
        self._tee_request_ids.discard(request_id)
        self._tools_list_request_ids.discard(request_id)

        if is_tools_list and self._endpoint is not None and not isinstance(response, ErrorData):
            # tools/list: inject session-bound envelope with trust metadata
            result_dict = response.model_dump(by_alias=True, mode="json", exclude_none=True)

            trust_metadata = None
            visible_tool_names: set[str] | None = None

            # Tools are pre-registered via register_verified_tool() at server startup
            # (after Pysa offline analysis). We do NOT register here via keyword analysis.
            tools_payload = result_dict.get("tools")

            if self._tool_trust_manager is not None:
                trust_info = self._tool_trust_manager.get_server_trust_state(require_fresh=True)
                trust_metadata = trust_info.to_dict()
                if isinstance(tools_payload, list):
                    typed_tools = [tool for tool in tools_payload if isinstance(tool, dict)]
                    tool_subjects = _build_tool_subject_map(typed_tools)
                    self._tool_trust_manager.update_tool_subjects(tool_subjects)

                    filtered_tools: list[dict[str, Any]] = []
                    visible_tool_names = set()
                    for tool in typed_tools:
                        tool_name = tool.get("name")
                        if not isinstance(tool_name, str) or not tool_name:
                            continue
                        tool_trust_info = self._tool_trust_manager.get_tool_trust_state(
                            tool_name,
                            require_fresh=True,
                        )
                        if self._tool_trust_manager.is_tool_trusted(tool_name, trust_info=tool_trust_info):
                            filtered_tools.append(tool)
                            visible_tool_names.add(tool_name)
                        else:
                            logger.warning(
                                "Hiding tool '%s' due to trust policy: status=%s policy_action=%s version=%s source=%s",
                                tool_name,
                                tool_trust_info.status,
                                tool_trust_info.policy_action,
                                tool_trust_info.version,
                                tool_trust_info.source,
                            )
                    result_dict["tools"] = filtered_tools

            # Authorization filtering: hide tools the client is not authorized to call
            if self._authorization_manager is not None:
                client_subject = self._client_subject()
                if client_subject:
                    current_tools = result_dict.get("tools")
                    if isinstance(current_tools, list):
                        auth_filtered: list[dict[str, Any]] = []
                        if visible_tool_names is None:
                            visible_tool_names = set()
                        for tool in current_tools:
                            if not isinstance(tool, dict):
                                continue
                            name = tool.get("name")
                            if not isinstance(name, str) or not name:
                                continue
                            if self._authorization_manager.is_authorized(client_subject, name):
                                auth_filtered.append(tool)
                                visible_tool_names.add(name)
                            else:
                                visible_tool_names.discard(name)
                                logger.debug("Hiding tool '%s' from client '%s': not authorized", name, client_subject)
                        result_dict["tools"] = auth_filtered

            tee_dict = create_session_envelope(self._endpoint, trust_metadata=trust_metadata)
            inject_tee(result_dict, tee_dict)

            jsonrpc_response = JSONRPCResponse(
                jsonrpc="2.0",
                id=request_id,
                result=result_dict,
            )
            await self._write_stream.send(SessionMessage(message=jsonrpc_response))
            if self._tool_trust_manager is not None:
                self._last_notified_trust_revision = int(getattr(self._tool_trust_manager, "revision", 0))
            if visible_tool_names is not None:
                await self._notify_visibility_change(visible_tool_names)
        elif is_tee_request and self._endpoint is not None and not isinstance(response, ErrorData):
            result_dict = response.model_dump(by_alias=True, mode="json", exclude_none=True)

            # Post-bootstrap: encrypt response with envelope encryption
            if self._endpoint.kek is not None:
                tee_dict = create_encrypted_envelope(self._endpoint, result_dict)
                result_dict = {"_meta": {"tee": tee_dict}}
            else:
                # Bootstrap response (no KEK yet — plaintext + evidence)
                tee_dict = create_bootstrap_envelope(self._endpoint)
                inject_tee(result_dict, tee_dict)

            jsonrpc_response = JSONRPCResponse(
                jsonrpc="2.0",
                id=request_id,
                result=result_dict,
            )
            await self._write_stream.send(SessionMessage(message=jsonrpc_response))
        else:
            await super()._send_response(request_id, response)

    async def _handle_initialize_request(
        self,
        responder: RequestResponder[types.ClientRequest, types.ServerResult],
        params: types.InitializeRequestParams,
    ) -> None:
        """Handle initialize request with TEE attestation via _meta.tee."""
        from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS

        requested_version = params.protocol_version
        self._initialization_state = InitializationState.Initializing
        self._client_params = params

        # Verify client TEE and extract binding material
        client_binding = self._verify_client_bootstrap(params)

        # Build result
        server_capabilities = self._init_options.capabilities
        result_dict = types.InitializeResult(
            protocolVersion=(
                requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else types.LATEST_PROTOCOL_VERSION
            ),
            capabilities=server_capabilities,
            serverInfo=types.Implementation(
                name=self._init_options.server_name,
                version=self._init_options.server_version,
                websiteUrl=self._init_options.website_url,
                icons=self._init_options.icons,
            ),
            instructions=self._init_options.instructions,
        )

        # Inject _meta.tee into result (plaintext — client may not know us yet)
        if self._tee_enabled and self._endpoint is not None:
            result_data = result_dict.model_dump(by_alias=True, mode="json", exclude_none=True)
            self._build_server_bootstrap(result_data, client_binding)

            # Send manually with _meta.tee injected
            with responder:
                jsonrpc_response = JSONRPCResponse(
                    jsonrpc="2.0",
                    id=responder.request_id,
                    result=result_data,
                )
                await self._write_stream.send(SessionMessage(message=jsonrpc_response))
                responder._completed = True
        else:
            with responder:
                await responder.respond(result_dict)

    def _verify_client_bootstrap(self, params: types.InitializeRequestParams) -> tuple[bytes, bytes] | None:
        """Verify client's _meta.tee from initialize request.

        Returns (client_init_nonce, client_pubkey_raw) when the client carried
        valid bootstrap material that we can derive a session key from. We
        still return the binding when authority verification of the client
        fails as long as `require_client_attestation` is False — otherwise the
        server's session KEK never gets established and every subsequent
        encrypted tools/call decrypt fails. The strict-attestation check is
        enforced separately via `_client_attested` on the InitializedNotification.
        """
        if not self._tee_enabled or self._endpoint is None:
            return None

        tee_dict = extract_tee(params)
        if not tee_dict:
            return None

        # Extract workload_id and resolve policy
        workload_id = tee_dict.get("workload_id")
        if workload_id and self._policy_registry is not None:
            self._active_policy = self._policy_registry.resolve(workload_id)
            logger.info("Resolved policy '%s' for workload '%s'", self._active_policy.name, workload_id)

        # Use policy-specific RTMR3 allowlist if available
        allowed_rtmr3 = self._allowed_client_rtmr3
        if self._active_policy is not None and self._active_policy.allowed_rtmr3 is not None:
            allowed_rtmr3 = self._active_policy.allowed_rtmr3

        valid, error = verify_bootstrap_envelope(
            self._endpoint,
            tee_dict,
            peer_role="client",
            allowed_rtmr3=allowed_rtmr3,
            authority_enabled=self._authority_enabled,
        )
        if valid:
            self._client_attested = True
            self._peer_verified = True
            logger.info("Client attested via initialize request")
        else:
            logger.warning("Client TEE verification failed in initialize: %s", error)
            if self._require_client_attestation:
                return None

        try:
            client_init_nonce = base64.b64decode(tee_dict["sig_data"])
            client_pubkey_raw = base64.b64decode(tee_dict["public_key"])
        except (KeyError, ValueError, TypeError) as binding_err:
            logger.warning("Cannot extract client binding from tee_dict: %s", binding_err)
            return None
        return (client_init_nonce, client_pubkey_raw)

    def _build_server_bootstrap(self, result_data: dict, client_binding: tuple[bytes, bytes] | None) -> None:
        """Create server TEE evidence, generate challenge, establish session.

        Mutates result_data to inject _meta.tee.
        """
        # Generate bootstrap challenge for Background-Check Model
        bootstrap_challenge = self._endpoint.generate_bootstrap_challenge()

        tee_dict = create_bootstrap_envelope(
            self._endpoint,
            challenge=bootstrap_challenge,
        )

        # Establish session binding if client was attested (ECDH + HKDF)
        if client_binding is not None:
            client_init_nonce, client_pubkey_raw = client_binding
            server_init_nonce = base64.b64decode(tee_dict["sig_data"])
            self._endpoint.establish_session(client_pubkey_raw, client_init_nonce, server_init_nonce)

        inject_tee(result_data, tee_dict)

    async def _received_notification(self, notification: types.ClientNotification) -> None:
        """Handle notifications with TEE attestation support."""
        match notification:
            case types.InitializedNotification():
                # Verify client's _meta.tee from initialized notification
                if self._tee_enabled and self._endpoint is not None:
                    if not self._verify_challenge_response(notification):
                        raise RuntimeError("Client bootstrap challenge/attestation verification failed")

                # Enforce attestation requirements
                if self._require_client_attestation and not self._client_attested:
                    await self.send_log_message(
                        level="error",
                        data="Client attestation required but not verified",
                        logger="mcp.server.attestation",
                    )
                    raise RuntimeError("Client attestation required but not verified")

                # Mark as initialized
                self._initialization_state = InitializationState.Initialized

            case _:
                await super()._received_notification(notification)

    def _verify_challenge_response(self, notification: types.ClientNotification) -> bool:
        """Verify client's _meta.tee from initialized notification.

        Message 3 uses HMAC-SHA256 for key possession proof.
        The client's TEE identity was already proven in Message 1's TDX quote;
        Message 3 proves the client derived the same session keys via ECDH
        by MACing the server's challenge with the shared mac_key.
        """
        params = notification.params
        tee_dict = extract_tee(params) if params is not None else None

        if params is None:
            logger.warning("No params in initialized notification")
            return self._endpoint.consume_bootstrap_challenge() is None

        if tee_dict is None:
            logger.warning("No _meta in initialized notification")
            return self._endpoint.consume_bootstrap_challenge() is None

        # Verify bootstrap challenge response if we sent one.
        # Challenge mismatch is ALWAYS fatal.
        challenge = self._endpoint.consume_bootstrap_challenge()
        if challenge is not None:
            if not tee_dict:
                logger.error("Bootstrap challenge response missing from initialized notification")
                return False

            challenge_response_b64 = tee_dict.get("challenge_response")
            if challenge_response_b64 is None:
                logger.error("Bootstrap challenge response missing from initialized notification")
                return False
            else:
                try:
                    response_bytes = base64.b64decode(challenge_response_b64)
                except Exception:
                    logger.error("Bootstrap challenge response has invalid base64 encoding")
                    return False
                if response_bytes != challenge:
                    logger.error("Bootstrap challenge response mismatch")
                    return False

            # HMAC-SHA256: proves client derived same session keys via ECDH
            challenge_mac_b64 = tee_dict.get("challenge_mac")
            if challenge_mac_b64 is None:
                logger.error("Challenge MAC missing from initialized notification")
                return False
            return self._verify_challenge_mac(challenge, challenge_mac_b64)

        # No challenge was pending — accept if no attestation required
        if self._require_client_attestation:
            logger.error("TEE evidence required but no challenge was pending")
            return False
        return True

    def _verify_challenge_mac(self, challenge: bytes, mac_b64: str) -> bool:
        """Verify HMAC-SHA256 challenge MAC from initialized notification.

        Args:
            challenge: The original challenge bytes (already echo-verified).
            mac_b64: Base64-encoded HMAC-SHA256(mac_key, challenge).

        Returns:
            True if MAC is valid, False otherwise.
        """
        import binascii

        if self._endpoint.mac_key is None:
            # Session not established — cannot verify MAC
            if self._require_client_attestation:
                logger.error("Session not established — cannot verify challenge MAC")
                return False
            logger.warning("No mac_key for MAC verification, accepting challenge echo only")
            return True

        try:
            mac_bytes = base64.b64decode(mac_b64)
        except (binascii.Error, TypeError):
            logger.error("Invalid base64 in challenge_mac")
            return False

        if not self._endpoint.verify_challenge_mac(challenge, mac_bytes):
            logger.error("Challenge MAC verification failed")
            return False

        logger.info("Client key possession verified via challenge MAC")
        return True

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def tee_enabled(self) -> bool:
        """Check if TEE is enabled."""
        return self._tee_enabled

    @property
    def is_client_attested(self) -> bool:
        """Check if client attestation succeeded."""
        return self._client_attested

    @property
    def peer_verified(self) -> bool:
        """Check if peer has been verified via _meta.tee."""
        return self._peer_verified

    @property
    def client_cgroup(self) -> str:
        """Get attested client's cgroup path."""
        if not self._client_attested or self._endpoint is None:
            return ""
        peer = self._endpoint.get_peer("client")
        return peer.cgroup if peer else ""

    @property
    def client_rtmr3(self) -> bytes:
        """Get attested client's RTMR3 value."""
        if not self._client_attested or self._endpoint is None:
            return bytes(48)
        peer = self._endpoint.get_peer("client")
        return peer.rtmr3 if peer else bytes(48)

    @property
    def client_attestation_token(self) -> str:
        """JWT issued by authority for the attested client (for multi-hop propagation)."""
        return self._client_attestation_token

    @property
    def endpoint(self) -> Any:
        """Get the SecureEndpoint for advanced operations."""
        return self._endpoint

    def _client_subject(self) -> str:
        """Resolve the client's identity for authorization decisions.

        Returns the authority subject or cgroup path of the connected client.
        Used by the authorization manager to match access rules.
        """
        # Prefer attestation token subject if available
        if self._client_attestation_token:
            return self._client_attestation_token
        # Fall back to attested cgroup
        cgroup = self.client_cgroup
        if cgroup:
            from mcp.server.tool_trust import subject_for_cgroup

            return subject_for_cgroup(cgroup)
        return ""
