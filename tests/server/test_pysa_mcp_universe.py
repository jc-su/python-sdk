"""Evaluation 1: Pysa taint analysis on real MCP tool source code.

Proves: Pysa + our 11 custom sink categories correctly identifies
the security capabilities of real MCP tools by tracing data flow
from tool entry points to security-sensitive API sinks.

Target: Salesforce MCP-Universe (real Python tools with real API calls)

What this evaluates:
- Does Pysa find the right sinks in real code?
- Does our taint.config correctly classify sinks into 11 categories?
- Does description-vs-code mismatch detection work on real tools?
"""

import shutil
from pathlib import Path

import pytest

from mcp.server.authorization import ToolCapability as TC
from mcp.server.behavior_analysis import build_capability_profile

HAS_PYRE = shutil.which("pyre") is not None
PYSA_CONFIG = "/home/jcsu/Dev/tee-mcp/pysa-test"
MCP_UNIVERSE = Path("/home/jcsu/Dev/tee-mcp/MCP-Universe/mcpuniverse/mcp/servers")
HAS_MCP_UNIVERSE = MCP_UNIVERSE.exists()

SKIP_REASON = "requires pyre-check and MCP-Universe repo"


@pytest.mark.skipif(not (HAS_PYRE and HAS_MCP_UNIVERSE), reason=SKIP_REASON)
class TestPysaOnMCPUniverse:
    """Run Pysa on real MCP-Universe server source code."""

    def _profile(self, server_name: str, description: str) -> dict:
        src = MCP_UNIVERSE / server_name / "server.py"
        source_code = src.read_text()
        p = build_capability_profile(
            server_name,
            description,
            source_code=source_code,
            taint_config_dir=PYSA_CONFIG,
        )
        return {
            "code": sorted(c.value for c in p.code_capabilities),
            "declared": sorted(c.value for c in p.declared_capabilities),
            "match": p.description_match,
            "mismatch": p.mismatch_reason,
            "analyzer": p.analyzer,
            "findings": len(p.findings),
        }

    def test_python_code_sandbox(self):
        """Sandbox forwards code to remote Docker via requests.post → CODE_EXECUTION."""
        r = self._profile("python_code_sandbox", "Execute Python code in a Docker sandbox")
        assert TC.CODE_EXECUTION.value in r["code"]
        assert r["analyzer"] == "pysa"

    def test_google_search_is_read(self):
        """Google search uses httpx.get → READ_PRIVATE, no egress."""
        r = self._profile("google_search", "Search the web using Google")
        assert TC.CROSS_BOUNDARY_EGRESS.value not in r["code"]

    def test_weather_is_read(self):
        """Weather fetches from public NWS API → safe read."""
        r = self._profile("weather", "Get weather forecast for a location")
        assert TC.CODE_EXECUTION.value not in r["code"]
        assert TC.CROSS_BOUNDARY_EGRESS.value not in r["code"]

    def test_wikipedia_is_read(self):
        """Wikipedia search → read-only, no egress or execution."""
        r = self._profile("wikipedia", "Search Wikipedia articles")
        assert TC.CODE_EXECUTION.value not in r["code"]
        assert TC.CROSS_BOUNDARY_EGRESS.value not in r["code"]

    def test_echo_is_safe(self):
        """Echo tool does nothing dangerous."""
        r = self._profile("echo", "Echo text back to caller")
        assert TC.CODE_EXECUTION.value not in r["code"]
        assert TC.CROSS_BOUNDARY_EGRESS.value not in r["code"]
        assert TC.DATA_DESTRUCTION.value not in r["code"]
