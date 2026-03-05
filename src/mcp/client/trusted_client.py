"""
TrustedMCP Client - MCP client with TEE attestation at session layer.

Provides TrustedClientSession which extends ClientSession with TEE support.
Attestation happens automatically during session.initialize() using MCP's
experimental capabilities mechanism.

Trust Model (per MCP terminology):
- Model Service (MS): LLM inference, protects model weights
- MCP Client (this): Orchestrates agent, connects to MS and Server
- MCP Server: Provides tools, handles sensitive operations

Usage:
    from mcp.client.trusted_client import TrustedClientSession
    from mcp.client.streamable_http import streamable_http_client

    # Session-layer TEE (recommended)
    async with streamable_http_client("http://server:8000/mcp") as streams:
        read_stream, write_stream, get_session_id = streams
        async with TrustedClientSession(
            read_stream, write_stream,
            tee_enabled=True,
            allowed_server_rtmr3=["abc123*"],
        ) as session:
            await session.initialize()
            if session.is_server_attested:
                print(f"Server verified: {session.server_cgroup}")

    # Without TEE (same as standard ClientSession)
    async with streamable_http_client("http://server:8000/mcp") as streams:
        read_stream, write_stream, get_session_id = streams
        async with TrustedClientSession(
            read_stream, write_stream,
            tee_enabled=False,
        ) as session:
            await session.initialize()
"""

import logging
from datetime import timedelta
from typing import Any, Optional

from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

import mcp.types as types
from mcp.client.session import (
    ClientSession,
    SamplingFnT,
    ElicitationFnT,
    ListRootsFnT,
    LoggingFnT,
    MessageHandlerFnT,
)
from mcp.client.experimental.task_handlers import ExperimentalTaskHandlers
from mcp.shared.message import SessionMessage

logger = logging.getLogger(__name__)

# Re-export TrustedClientSession from trusted_session
from mcp.client.trusted_session import TrustedClientSession

# =============================================================================
# Model Service Client (for MS-Client attestation)
# =============================================================================

try:
    from mcp.shared.trusted_service import TrustedServiceClient
except ImportError:
    TrustedServiceClient = None  # type: ignore


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "TrustedClientSession",
]

if TrustedServiceClient is not None:
    __all__.append("TrustedServiceClient")
