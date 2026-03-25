"""TrustedMCP Client — re-exports TrustedClientSession for convenience.

Usage:
    from mcp.client.trusted_client import TrustedClientSession
"""

from mcp.client.trusted_session import TrustedClientSession

__all__ = ["TrustedClientSession"]
