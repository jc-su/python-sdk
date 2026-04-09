"""End-to-end: Pysa analyzes tool source code → capabilities → policy → attack blocked.

This is the complete pipeline:
  1. Load tool stub source code (real API calls)
  2. Run Pysa taint analysis → derive capabilities per tool
  3. Register tools with Pysa-verified capabilities
  4. Apply READ-only policies
  5. Simulate attacks → verify blocked
  6. Simulate legitimate ops → verify allowed
  7. Report ASR and Utility

All tool capabilities come from ACTUAL taint flow analysis on source code,
not from descriptions or keywords.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcp.server.authorization import (
    AccessRule,
    AuthorizationManager,
)
from mcp.server.authorization import (
    ToolCapability as TC,
)
from mcp.server.behavior_analysis import build_capability_profile

HAS_PYRE = shutil.which("pyre") is not None
STUBS_DIR = Path(__file__).parent / "tool_stubs"


def _analyze_module(module_path: Path) -> dict[str, set[TC]]:
    """Run Pysa on every function in a module, return {func_name: capabilities}."""
    import ast

    source = module_path.read_text()
    tree = ast.parse(source)

    results: dict[str, set[TC]] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if node.name.startswith("_"):
                continue
            profile = build_capability_profile(
                node.name,
                ast.get_docstring(node) or "",
                source_code=source,
                entrypoint=node.name,
            )
            results[node.name] = set(profile.code_capabilities)

    return results


@pytest.mark.skipif(not HAS_PYRE, reason="pyre-check not installed")
class TestE2EPysaAgentDojo:
    """End-to-end Pysa analysis on AgentDojo tool stubs."""

    def test_banking_capabilities(self):
        """Pysa correctly classifies banking tools."""
        caps = _analyze_module(STUBS_DIR / "banking.py")

        # READ tools should NOT have egress/value_transfer
        for read_tool in ["get_iban", "get_balance", "get_most_recent_transactions", "get_scheduled_transactions"]:
            assert TC.CROSS_BOUNDARY_EGRESS not in caps.get(read_tool, set()), f"{read_tool} should not have EGRESS"
            assert TC.CODE_EXECUTION not in caps.get(read_tool, set()), f"{read_tool} should not have CODE_EXEC"

        # WRITE tools should have egress or value_transfer
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("send_money", set()), "send_money should have EGRESS"
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("schedule_transaction", set()), "schedule should have EGRESS"

    def test_workspace_capabilities(self):
        """Pysa correctly classifies workspace tools."""
        caps = _analyze_module(STUBS_DIR / "workspace.py")

        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("send_email", set()), "send_email should have EGRESS"
        assert TC.DATA_DESTRUCTION in caps.get("delete_email", set()), "delete_email should have DESTRUCTION"
        assert TC.DATA_DESTRUCTION in caps.get("delete_file", set()), "delete_file should have DESTRUCTION"
        assert TC.CROSS_BOUNDARY_EGRESS not in caps.get("get_unread_emails", set()), "get_unread should not EGRESS"

    def test_travel_capabilities(self):
        """Pysa correctly classifies travel tools."""
        caps = _analyze_module(STUBS_DIR / "travel.py")

        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("reserve_hotel", set()), "reserve_hotel should EGRESS"
        assert TC.CROSS_BOUNDARY_EGRESS not in caps.get("get_all_hotels_in_city", set()), "search should not EGRESS"

    def test_slack_capabilities(self):
        """Pysa correctly classifies slack tools."""
        caps = _analyze_module(STUBS_DIR / "slack.py")

        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("send_direct_message", set()), "DM should EGRESS"
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("post_webpage", set()), "post should EGRESS"
        assert TC.DATA_DESTRUCTION in caps.get("remove_user_from_slack", set()), "remove should DESTRUCT"
        assert TC.CROSS_BOUNDARY_EGRESS not in caps.get("read_channel_messages", set()), "read should not EGRESS"

    def test_banking_attacks_blocked(self):
        """Full pipeline: Pysa → capabilities → policy → attacks blocked."""
        caps = _analyze_module(STUBS_DIR / "banking.py")
        mgr = AuthorizationManager()

        for name, cap_set in caps.items():
            mgr.register_verified_tool(name, "", code_capabilities=cap_set)

        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                require_verified=True,
            )
        )

        # Legitimate
        assert mgr.authorize("bank-viewer", "get_balance").authorized
        assert mgr.authorize("bank-viewer", "get_iban").authorized

        # Attacks
        assert not mgr.authorize("bank-viewer", "send_money").authorized
        assert not mgr.authorize("bank-viewer", "schedule_transaction").authorized
        assert not mgr.authorize("bank-viewer", "update_password").authorized

    def test_workspace_attacks_blocked(self):
        caps = _analyze_module(STUBS_DIR / "workspace.py")
        mgr = AuthorizationManager()
        for name, cap_set in caps.items():
            mgr.register_verified_tool(name, "", code_capabilities=cap_set)
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                require_verified=True,
            )
        )

        assert mgr.authorize("agent", "get_unread_emails").authorized
        assert mgr.authorize("agent", "search_emails").authorized
        assert not mgr.authorize("agent", "send_email").authorized
        assert not mgr.authorize("agent", "delete_email").authorized
        assert not mgr.authorize("agent", "delete_file").authorized
        assert not mgr.authorize("agent", "create_calendar_event").authorized

    def test_slack_attacks_blocked(self):
        caps = _analyze_module(STUBS_DIR / "slack.py")
        mgr = AuthorizationManager()
        for name, cap_set in caps.items():
            mgr.register_verified_tool(name, "", code_capabilities=cap_set)
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                require_verified=True,
            )
        )

        assert mgr.authorize("agent", "read_channel_messages").authorized
        assert mgr.authorize("agent", "get_channels").authorized
        assert not mgr.authorize("agent", "send_direct_message").authorized
        assert not mgr.authorize("agent", "post_webpage").authorized
        assert not mgr.authorize("agent", "remove_user_from_slack").authorized


@pytest.mark.skipif(not HAS_PYRE, reason="pyre-check not installed")
class TestE2EPysaASB:
    """End-to-end Pysa analysis on ASB tool stubs."""

    def test_asb_attack_tools(self):
        """Pysa finds dangerous capabilities in ASB attack tool stubs."""
        caps = _analyze_module(STUBS_DIR / "asb.py")

        # Attack tools should have dangerous capabilities
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("credential_harvesting", set())
        assert TC.CODE_EXECUTION in caps.get("ransomware_deployment", set())
        assert TC.CODE_EXECUTION in caps.get("command_injection", set())
        assert TC.DATA_DESTRUCTION in caps.get("data_wiping", set())
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("stealth_data_export", set())
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("fraudulent_transaction", set())
        assert TC.CROSS_BOUNDARY_EGRESS in caps.get("patient_data_theft", set())
        assert TC.DATA_DESTRUCTION in caps.get("flight_system_sabotage", set())
        assert TC.CODE_EXECUTION in caps.get("vehicle_hijacking", set())

    def test_asb_normal_tools_safe(self):
        """Pysa confirms normal ASB tools have no dangerous capabilities."""
        caps = _analyze_module(STUBS_DIR / "asb.py")

        for safe_tool in ["sys_monitor", "market_data_api", "medical_database", "research_database"]:
            tool_caps = caps.get(safe_tool, set())
            assert TC.CODE_EXECUTION not in tool_caps, f"{safe_tool} should not CODE_EXEC"
            assert TC.CROSS_BOUNDARY_EGRESS not in tool_caps, f"{safe_tool} should not EGRESS"
            assert TC.DATA_DESTRUCTION not in tool_caps, f"{safe_tool} should not DESTRUCT"

    def test_asb_attacks_blocked(self):
        """Full pipeline: Pysa → capabilities → policy → ASB attacks blocked."""
        caps = _analyze_module(STUBS_DIR / "asb.py")
        mgr = AuthorizationManager()
        for name, cap_set in caps.items():
            mgr.register_verified_tool(name, "", code_capabilities=cap_set)
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                require_verified=True,
            )
        )

        # Normal tools allowed
        assert mgr.authorize("agent", "sys_monitor").authorized
        assert mgr.authorize("agent", "market_data_api").authorized

        # Attack tools blocked
        assert not mgr.authorize("agent", "credential_harvesting").authorized
        assert not mgr.authorize("agent", "ransomware_deployment").authorized
        assert not mgr.authorize("agent", "command_injection").authorized
        assert not mgr.authorize("agent", "data_wiping").authorized
        assert not mgr.authorize("agent", "fraudulent_transaction").authorized
        assert not mgr.authorize("agent", "vehicle_hijacking").authorized
