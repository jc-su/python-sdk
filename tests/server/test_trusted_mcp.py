"""Tests for TrustedMCP authority configuration."""

import pytest

from mcp.server.trusted_mcp import TrustedMCP
from mcp.server.trusted_server import TrustedServer


def test_rejects_removed_trust_mode_kwarg():
    with pytest.raises(TypeError):
        TrustedMCP("test", tee_enabled=False, trust_mode="authority_only")  # type: ignore[call-arg]


def test_rejects_removed_trust_fail_open_kwarg():
    with pytest.raises(TypeError):
        TrustedMCP("test", tee_enabled=False, trust_fail_open=True)  # type: ignore[call-arg]


def test_default_config_works_without_compatibility_kwargs():
    server = TrustedMCP("test", tee_enabled=False)
    assert server.tee_enabled is False


def test_trusted_server_enables_tools_list_changed_by_default():
    async def _list_tools(ctx, params):  # pragma: no cover
        return []

    server = TrustedServer("test", on_list_tools=_list_tools)

    options = server.create_initialization_options()
    assert options.capabilities.tools is not None
    assert options.capabilities.tools.list_changed is True
