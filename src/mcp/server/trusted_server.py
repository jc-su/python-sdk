"""TrustedServer - MCP Server with customizable session class for TEE support.

Extends the lowlevel Server to allow injecting TrustedServerSession
for TEE attestation at the session layer.
"""

import logging
from contextlib import AsyncExitStack
from typing import Any

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

import mcp.types as types
from mcp.server.lowlevel.server import LifespanResultT, NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.session import ServerSession
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

logger = logging.getLogger(__name__)


class TrustedServer(Server[LifespanResultT]):
    """MCP Server with customizable session class.

    Allows injecting TrustedServerSession for TEE attestation support.
    """

    def __init__(
        self,
        name: str,
        *,
        version: str | None = None,
        instructions: str | None = None,
        session_class: type[ServerSession] | None = None,
        session_kwargs: dict[str, Any] | None = None,
        **server_kwargs: Any,
    ):
        super().__init__(name, version=version, instructions=instructions, **server_kwargs)
        self._session_class = session_class or ServerSession
        self._session_kwargs = session_kwargs or {}

    async def run(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        initialization_options: InitializationOptions,
        raise_exceptions: bool = False,
        stateless: bool = False,
    ):
        """Run the server using the custom session class."""
        await self.run_streams(
            read_stream,
            write_stream,
            initialization_options,
            raise_exceptions=raise_exceptions,
            stateless=stateless,
        )

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        """Enable tools/list_changed advertisement for trusted sessions by default."""
        if notification_options is None:
            notification_options = NotificationOptions(tools_changed=True)
        return super().create_initialization_options(notification_options, experimental_capabilities)

    async def run_streams(
        self,
        read_stream: MemoryObjectReceiveStream[SessionMessage | Exception],
        write_stream: MemoryObjectSendStream[SessionMessage],
        initialization_options: InitializationOptions,
        raise_exceptions: bool = False,
        # If stateless, don't track state between requests. this enables use cases
        # like horizontal scaling with a load balancer, where different requests from the same
        # client could go to different instances. In this mode initialization is still required for
        # correct protocol operation (both sides need each other's capabilities), but
        # clients can perform initialization with any node.
        stateless: bool = False,
    ):
        """Run the server with custom session class support."""
        async with AsyncExitStack() as stack:
            lifespan_context = await stack.enter_async_context(self.lifespan(self))

            # Create session using custom session class
            session = await stack.enter_async_context(
                self._session_class(
                    read_stream,
                    write_stream,
                    initialization_options,
                    stateless=stateless,
                    **self._session_kwargs,
                )
            )

            # Configure task support for this session if enabled
            task_support = self._experimental_handlers.task_support if self._experimental_handlers else None
            if task_support is not None:
                task_support.configure_session(session)
                await stack.enter_async_context(task_support.run())

            async with anyio.create_task_group() as tg:
                async for message in session.incoming_messages:
                    logger.debug("Received message: %s", message)

                    tg.start_soon(
                        self._handle_message,
                        message,
                        session,
                        lifespan_context,
                        raise_exceptions,
                    )

    async def _handle_message(
        self,
        message: RequestResponder[types.ClientRequest, types.ServerResult] | types.ClientNotification | Exception,
        session: ServerSession,
        lifespan_context: LifespanResultT,
        raise_exceptions: bool = False,
    ):
        """Handle incoming messages - delegate to parent."""
        await super()._handle_message(message, session, lifespan_context, raise_exceptions)
