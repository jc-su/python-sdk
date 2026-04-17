"""TrustedMCP Server - MCP server with TEE attestation at session layer.

Extends MCPServer with hardware-attested communication support using
TrustedServerSession for two-party mutual attestation during the
MCP initialize handshake and session-bound protection on tool calls.

Usage:
    from mcp.server.trusted_mcp import TrustedMCP

    # With TEE enabled (default)
    mcp = TrustedMCP("my-server", tee_enabled=True)

    # Without TEE (behaves like MCPServer)
    mcp = TrustedMCP("my-server", tee_enabled=False)

    @mcp.tool()
    def my_tool(param: str) -> str:
        return f"Result: {param}"

    mcp.run(transport="streamable-http")
"""

import logging
from typing import Any

from mcp.server.mcpserver.server import MCPServer

logger = logging.getLogger(__name__)


class TrustedMCP(MCPServer):
    """MCP Server with TEE attestation at session layer.

    Extends MCPServer with hardware attestation support. When tee_enabled=True,
    uses TrustedServerSession for attestation during the MCP initialize handshake.

    Attestation uses MCP's experimental capabilities mechanism for clean integration.
    """

    def __init__(
        self,
        name: str | None = None,
        instructions: str | None = None,
        *,
        tee_enabled: bool = True,
        require_client_attestation: bool = False,
        allowed_client_rtmr3: list[str] | None = None,
        rtmr3_transition_policy: str = "log_and_accept",
        policy_registry: Any = None,
        authority_subject: str | None = None,
        authorization_manager: Any = None,
        **kwargs: Any,
    ):
        """Create TrustedMCP server.

        Args:
            name: Server name
            instructions: Optional instructions
            tee_enabled: Enable TEE attestation (default: True).
                         If False, behaves exactly like MCPServer.
            require_client_attestation: Require MCP Client attestation
            allowed_client_rtmr3: Allowed RTMR3 patterns for MCP Client
            rtmr3_transition_policy: Policy for RTMR3 changes: accept/reject/log_and_accept
            policy_registry: PolicyRegistry for per-workload attestation policies
            authority_subject: Override attestation authority subject (default: workload://<workload_id> if set, else cgroup://<cgroup>)
            authorization_manager: AuthorizationManager for semantic tool authorization
            **kwargs: Additional MCPServer arguments
        """
        # Store TEE settings before calling super().__init__
        self._tee_enabled = tee_enabled
        self._require_client_attestation = require_client_attestation
        self._allowed_client_rtmr3 = allowed_client_rtmr3
        self._rtmr3_transition_policy = rtmr3_transition_policy
        self._policy_registry = policy_registry

        self._authority_subject = authority_subject
        self._authorization_manager = authorization_manager

        # Call parent init
        super().__init__(name=name, instructions=instructions, **kwargs)

        # If TEE enabled, replace _lowlevel_server with TrustedServer
        if self._tee_enabled:
            self._setup_trusted_server()

    def _setup_trusted_server(self) -> None:
        """Replace lowlevel Server with TrustedServer for TEE support."""
        try:
            from mcp.server.trusted_server import TrustedServer
            from mcp.server.trusted_session import TrustedServerSession

            # Create ToolTrustManager for whitelist/blacklist fast-path
            tool_trust_manager = self._create_tool_trust_manager()

            # Create JWT verifier for upstream token verification
            from mcp.shared.authority_jwt import get_default_jwt_verifier

            jwt_verifier = get_default_jwt_verifier()

            # Create TrustedServer with TrustedServerSession
            session_kwargs = {
                "tee_enabled": self._tee_enabled,
                "require_client_attestation": self._require_client_attestation,
                "allowed_client_rtmr3": self._allowed_client_rtmr3,
                "rtmr3_transition_policy": self._rtmr3_transition_policy,
                "policy_registry": self._policy_registry,
                "tool_trust_manager": tool_trust_manager,
                "jwt_verifier": jwt_verifier,
                "authorization_manager": self._authorization_manager,
            }

            old_server = self._lowlevel_server
            self._lowlevel_server = TrustedServer(
                name=old_server.name,
                version=old_server.version,
                instructions=old_server.instructions,
                website_url=old_server.website_url,
                icons=old_server.icons,
                lifespan=old_server.lifespan,
                session_class=TrustedServerSession,
                session_kwargs=session_kwargs,
                # Re-register the same handlers MCPServer set up
                on_list_tools=self._handle_list_tools,
                on_call_tool=self._handle_call_tool,
                on_list_resources=self._handle_list_resources,
                on_read_resource=self._handle_read_resource,
                on_list_resource_templates=self._handle_list_resource_templates,
                on_list_prompts=self._handle_list_prompts,
                on_get_prompt=self._handle_get_prompt,
            )

            logger.info("TrustedServer initialized with TrustedServerSession")

        except ImportError:
            logger.warning("TEE dependencies not available, using standard server")
            self._tee_enabled = False
        except RuntimeError:
            logger.exception("TrustedServer initialization failed in authority mode")
            raise
        except Exception:
            logger.exception("Failed to create TrustedServer in authority mode")
            raise

    def _create_tool_trust_manager(self) -> Any:
        """Create ToolTrustManager for tool trust management."""
        try:
            from mcp.server.tool_trust import ToolTrustManager
            from mcp.shared.tdx import get_container_rtmr3, get_current_cgroup

            cgroup = get_current_cgroup()
            initial_rtmr3: bytes | None
            try:
                maybe_rtmr3 = get_container_rtmr3()
                initial_rtmr3 = None if maybe_rtmr3 == bytes(48) else maybe_rtmr3
            except Exception:
                initial_rtmr3 = None
                logger.debug("Could not read initial RTMR3; continuing with authority trust path", exc_info=True)

            manager = ToolTrustManager(
                initial_rtmr3=initial_rtmr3,
                cgroup=cgroup,
                authority_subject=self._authority_subject,
            )
            if manager.configuration_error:
                raise RuntimeError(manager.configuration_error)
            logger.info(
                "ToolTrustManager initialized: cgroup=%s subject=%s authority=%s",
                cgroup,
                getattr(manager, "authority_subject", ""),
                getattr(manager, "authority_available", False),
            )
            return manager
        except RuntimeError:
            raise
        except Exception:
            logger.exception("Could not create ToolTrustManager in authority mode")
            raise

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def tee_enabled(self) -> bool:
        """Check if TEE is enabled."""
        return self._tee_enabled
