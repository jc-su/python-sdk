"""Tests for AuthorizationManager - semantic tool authorization.

Tests cover:
- Tool registration and capability analysis (KeywordToolAnalyzer)
- Access rule matching (glob patterns, explicit allow/deny)
- Capability-based authorization enforcement
- Rate limiting
- Fail-closed behavior
- AgentDojo attack prevention scenarios
- Metadata export
"""

import time

import pytest

from mcp.server.authorization import (
    AccessRule,
    AuthorizationDecision,
    AuthorizationManager,
    KeywordToolAnalyzer,
    ToolAnalyzer,
    ToolCapability,
    ToolScope,
)

# ---------------------------------------------------------------------------
# KeywordToolAnalyzer tests
# ---------------------------------------------------------------------------


class TestKeywordToolAnalyzer:
    def setup_method(self):
        self.analyzer = KeywordToolAnalyzer()

    def test_read_tool(self):
        caps = self.analyzer.analyze("get_emails", "Retrieve emails from inbox")
        assert ToolCapability.READ in caps

    def test_write_tool(self):
        caps = self.analyzer.analyze("create_event", "Create a new calendar event")
        assert ToolCapability.WRITE in caps

    def test_send_tool(self):
        caps = self.analyzer.analyze("send_email", "Send an email to a recipient")
        assert ToolCapability.SEND in caps

    def test_financial_tool(self):
        caps = self.analyzer.analyze("transfer_money", "Transfer funds between accounts")
        assert ToolCapability.FINANCIAL in caps

    def test_delete_tool(self):
        caps = self.analyzer.analyze("delete_email", "Delete an email from inbox")
        assert ToolCapability.DELETE in caps

    def test_execute_tool(self):
        caps = self.analyzer.analyze("run_script", "Execute a shell script on the server")
        assert ToolCapability.EXECUTE in caps

    def test_admin_tool(self):
        caps = self.analyzer.analyze("manage_users", "Configure user permissions and roles")
        assert ToolCapability.ADMIN in caps

    def test_multi_capability_tool(self):
        caps = self.analyzer.analyze("send_payment", "Send a payment transaction to recipient")
        assert ToolCapability.SEND in caps
        assert ToolCapability.FINANCIAL in caps

    def test_unknown_defaults_to_read(self):
        caps = self.analyzer.analyze("foobar", "does something mysterious")
        assert caps == {ToolCapability.READ}

    def test_name_contributes_to_analysis(self):
        # Tool name "read_data" should trigger READ even with empty description
        caps = self.analyzer.analyze("read_data", "")
        assert ToolCapability.READ in caps

    def test_case_insensitive(self):
        caps = self.analyzer.analyze("SendEmail", "SEND an EMAIL to recipient")
        assert ToolCapability.SEND in caps

    def test_booking_is_financial(self):
        caps = self.analyzer.analyze("book_hotel", "Book a hotel room for the given dates")
        assert ToolCapability.FINANCIAL in caps

    def test_slack_is_send(self):
        caps = self.analyzer.analyze("post_slack", "Post a message to a Slack channel")
        assert ToolCapability.SEND in caps


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def setup_method(self):
        self.mgr = AuthorizationManager()

    def test_register_tool_auto_analysis(self):
        scope = self.mgr.register_tool("read_email", "Read emails from inbox")
        assert scope.tool_name == "read_email"
        assert ToolCapability.READ in scope.capabilities
        assert scope.description_hash  # non-empty SHA-384

    def test_register_tool_with_override(self):
        scope = self.mgr.register_tool(
            "custom_tool",
            "Does custom things",
            capabilities_override={ToolCapability.ADMIN, ToolCapability.WRITE},
        )
        assert scope.capabilities == frozenset({ToolCapability.ADMIN, ToolCapability.WRITE})

    def test_get_tool_scope(self):
        self.mgr.register_tool("t1", "Read data")
        assert self.mgr.get_tool_scope("t1") is not None
        assert self.mgr.get_tool_scope("nonexistent") is None

    def test_registered_tools(self):
        self.mgr.register_tool("a", "Read data")
        self.mgr.register_tool("b", "Write data")
        tools = self.mgr.registered_tools()
        assert "a" in tools
        assert "b" in tools

    def test_reregister_updates_scope(self):
        self.mgr.register_tool("t", "Read data")
        assert ToolCapability.READ in self.mgr.get_tool_scope("t").capabilities
        self.mgr.register_tool("t", "Send email to recipient")
        assert ToolCapability.SEND in self.mgr.get_tool_scope("t").capabilities

    def test_description_hash_integrity(self):
        scope1 = self.mgr.register_tool("t", "Read data")
        scope2 = self.mgr.register_tool("t2", "Read data")
        scope3 = self.mgr.register_tool("t3", "Different description")
        assert scope1.description_hash == scope2.description_hash
        assert scope1.description_hash != scope3.description_hash


# ---------------------------------------------------------------------------
# Authorization decision tests
# ---------------------------------------------------------------------------


class TestAuthorization:
    def setup_method(self):
        self.mgr = AuthorizationManager()
        self.mgr.register_tool("read_email", "Read emails from inbox")
        self.mgr.register_tool("send_email", "Send an email to a recipient")
        self.mgr.register_tool("transfer_money", "Transfer funds to another account")
        self.mgr.register_tool("get_calendar", "Get calendar events for a day")
        self.mgr.register_tool("delete_email", "Delete an email from inbox")

    def test_fail_closed_no_rule(self):
        """No matching rule -> denied (fail-closed)."""
        decision = self.mgr.authorize("cgroup:///unknown", "read_email")
        assert not decision.authorized
        assert "no authorization rule" in decision.reason

    def test_fail_closed_unregistered_tool(self):
        """Unregistered tool -> denied."""
        self.mgr.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=frozenset(ToolCapability)))
        decision = self.mgr.authorize("cgroup:///test", "nonexistent_tool")
        assert not decision.authorized
        assert "not registered" in decision.reason

    def test_read_only_rule(self):
        """READ-only rule blocks SEND and FINANCIAL tools."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/reader.scope",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        subject = "cgroup:///kubepods/reader.scope"

        assert self.mgr.authorize(subject, "read_email").authorized
        assert self.mgr.authorize(subject, "get_calendar").authorized
        assert not self.mgr.authorize(subject, "send_email").authorized
        assert not self.mgr.authorize(subject, "transfer_money").authorized
        assert not self.mgr.authorize(subject, "delete_email").authorized

    def test_read_write_rule(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/editor.scope",
                allowed_capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE}),
            )
        )
        subject = "cgroup:///kubepods/editor.scope"

        assert self.mgr.authorize(subject, "read_email").authorized
        assert not self.mgr.authorize(subject, "send_email").authorized
        assert not self.mgr.authorize(subject, "transfer_money").authorized

    def test_full_access_rule(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/admin.scope",
                allowed_capabilities=frozenset(ToolCapability),
            )
        )
        subject = "cgroup:///kubepods/admin.scope"

        for tool in ["read_email", "send_email", "transfer_money", "delete_email"]:
            assert self.mgr.authorize(subject, tool).authorized

    def test_explicit_deny_list(self):
        """Deny list overrides capability match."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(ToolCapability),
                denied_tools=frozenset({"transfer_money"}),
            )
        )
        assert self.mgr.authorize("any", "read_email").authorized
        assert not self.mgr.authorize("any", "transfer_money").authorized
        assert "deny list" in self.mgr.authorize("any", "transfer_money").reason

    def test_explicit_allow_list(self):
        """Allow list restricts to specific tools even if capabilities match."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(ToolCapability),
                allowed_tools=frozenset({"read_email", "get_calendar"}),
            )
        )
        assert self.mgr.authorize("any", "read_email").authorized
        assert self.mgr.authorize("any", "get_calendar").authorized
        assert not self.mgr.authorize("any", "send_email").authorized
        assert "not in allow list" in self.mgr.authorize("any", "send_email").reason

    def test_first_matching_rule_wins(self):
        """Rules are evaluated in order; first match wins."""
        # Specific rule: agent-reader -> READ only
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/agent-reader*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        # Broad rule: everything else -> full access
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(ToolCapability),
            )
        )

        # agent-reader matches the first (restrictive) rule
        assert self.mgr.authorize("cgroup:///kubepods/agent-reader.scope", "read_email").authorized
        assert not self.mgr.authorize("cgroup:///kubepods/agent-reader.scope", "send_email").authorized

        # other subjects match the second (permissive) rule
        assert self.mgr.authorize("cgroup:///kubepods/admin.scope", "send_email").authorized

    def test_default_rule_fallback(self):
        """Default rule used when no pattern matches."""
        self.mgr.set_default_rule(
            AccessRule(
                subject_pattern="<default>",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        # No rules added — default should kick in
        assert self.mgr.authorize("unknown-subject", "read_email").authorized
        assert not self.mgr.authorize("unknown-subject", "send_email").authorized

    def test_denied_capabilities_in_decision(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        decision = self.mgr.authorize("any", "send_email")
        assert not decision.authorized
        assert ToolCapability.SEND in decision.denied_capabilities

    def test_matched_rule_in_decision(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/agent-*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        decision = self.mgr.authorize("cgroup:///kubepods/agent-foo", "read_email")
        assert decision.matched_rule == "cgroup://*/agent-*"

    def test_get_authorized_tools(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        authorized = self.mgr.get_authorized_tools("any")
        assert "read_email" in authorized
        assert "get_calendar" in authorized
        assert "send_email" not in authorized
        assert "transfer_money" not in authorized

    def test_is_authorized_convenience(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        assert self.mgr.is_authorized("any", "read_email")
        assert not self.mgr.is_authorized("any", "send_email")


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_rate_limit_blocks(self):
        mgr = AuthorizationManager()
        mgr.register_tool("read_email", "Read emails from inbox")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                max_calls_per_minute=3,
            )
        )

        assert mgr.authorize("user", "read_email").authorized
        assert mgr.authorize("user", "read_email").authorized
        assert mgr.authorize("user", "read_email").authorized
        decision = mgr.authorize("user", "read_email")
        assert not decision.authorized
        assert "rate limit" in decision.reason

    def test_rate_limit_per_subject_tool(self):
        """Rate limits are per (subject, tool) pair."""
        mgr = AuthorizationManager()
        mgr.register_tool("t1", "Read data")
        mgr.register_tool("t2", "Get items")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                max_calls_per_minute=1,
            )
        )

        assert mgr.authorize("user-a", "t1").authorized
        assert not mgr.authorize("user-a", "t1").authorized  # limit hit
        assert mgr.authorize("user-a", "t2").authorized  # different tool
        assert mgr.authorize("user-b", "t1").authorized  # different subject

    def test_rate_limit_window_expires(self):
        """Rate limit window slides — old entries expire."""
        mgr = AuthorizationManager()
        mgr.register_tool("t", "Read data")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                max_calls_per_minute=1,
            )
        )

        assert mgr.authorize("u", "t").authorized
        assert not mgr.authorize("u", "t").authorized

        # Simulate time passing (monkey-patch the rate window)
        key = ("u", "t")
        mgr._rate_windows[key].timestamps = [time.monotonic() - 61.0]
        assert mgr.authorize("u", "t").authorized

    def test_zero_rate_means_unlimited(self):
        mgr = AuthorizationManager()
        mgr.register_tool("t", "Read data")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                max_calls_per_minute=0,
            )
        )

        for _ in range(100):
            assert mgr.authorize("u", "t").authorized


# ---------------------------------------------------------------------------
# AgentDojo attack prevention scenarios
# ---------------------------------------------------------------------------


class TestAgentDojoAttackPrevention:
    """Test that authorization prevents AgentDojo-style attacks.

    These tests model the key attack scenarios from the AgentDojo benchmark
    (NeurIPS 2024) and verify that TEE-MCP authorization blocks them.
    """

    def setup_method(self):
        self.mgr = AuthorizationManager()
        # Register tools matching AgentDojo's Workspace environment
        self.mgr.register_tool("read_email", "Read emails from inbox")
        self.mgr.register_tool("send_email", "Send an email to a recipient")
        self.mgr.register_tool("get_calendar", "Get calendar events for a given day")
        self.mgr.register_tool("create_event", "Create a new calendar event")
        self.mgr.register_tool("search_files", "Search files in cloud drive")

        # Register tools matching AgentDojo's Banking environment
        self.mgr.register_tool("get_balance", "Get current account balance")
        self.mgr.register_tool("get_transactions", "List recent transactions")
        self.mgr.register_tool("transfer_money", "Transfer funds to another account")

        # Register tools matching AgentDojo's Slack environment
        self.mgr.register_tool("read_channel", "Read messages from a Slack channel")
        self.mgr.register_tool("send_message", "Send a message to a Slack channel")
        self.mgr.register_tool("invite_user", "Invite a user to a Slack channel")

    def test_workspace_privilege_escalation(self):
        """AgentDojo: 'Summarize emails' task, attack tries to send_email.

        ImportantInstructionsAttack injects 'send 2FA code to attacker@evil.com'.
        With READ-only scope, send_email is blocked at MCP Server level.
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/email-summarizer.scope",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        subject = "cgroup:///kubepods/email-summarizer.scope"

        # Legitimate task: reading emails works
        assert self.mgr.authorize(subject, "read_email").authorized
        assert self.mgr.authorize(subject, "get_calendar").authorized

        # Attack: prompt injection tries to send email — BLOCKED
        decision = self.mgr.authorize(subject, "send_email")
        assert not decision.authorized
        assert ToolCapability.SEND in decision.denied_capabilities

    def test_banking_privilege_escalation(self):
        """AgentDojo: 'Show bank statement' task, attack tries to transfer_money.

        ToolKnowledgeAttack knows the transfer_money API and crafts exact args.
        Even with full API knowledge, scope enforcement blocks the call.

        get_balance/get_transactions have both READ and FINANCIAL capabilities
        (they read financial data), so the rule allows both. transfer_money is
        explicitly denied regardless of capabilities.
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/bank-viewer.scope",
                allowed_capabilities=frozenset({ToolCapability.READ, ToolCapability.FINANCIAL}),
                denied_tools=frozenset({"transfer_money"}),
            )
        )
        subject = "cgroup:///kubepods/bank-viewer.scope"

        assert self.mgr.authorize(subject, "get_balance").authorized
        assert self.mgr.authorize(subject, "get_transactions").authorized

        decision = self.mgr.authorize(subject, "transfer_money")
        assert not decision.authorized
        assert "deny list" in decision.reason

    def test_slack_cross_tool_chaining(self):
        """AgentDojo: 'Post meeting notes' task, attack chains read_channel -> send phishing link.

        SystemMessageAttack disguises injection as system directive to send phishing URL.
        With scoped access, send_message to other channels is blocked.
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/slack-reader.scope",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )
        subject = "cgroup:///kubepods/slack-reader.scope"

        assert self.mgr.authorize(subject, "read_channel").authorized
        assert not self.mgr.authorize(subject, "send_message").authorized
        assert not self.mgr.authorize(subject, "invite_user").authorized

    def test_dos_via_tool_abuse(self):
        """Rate limiting prevents DoS-style tool abuse.

        DoSAttack tries rapid-fire tool calls to exhaust resources.
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                max_calls_per_minute=5,
            )
        )

        for _ in range(5):
            assert self.mgr.authorize("user", "read_email").authorized

        # 6th call blocked by rate limit
        assert not self.mgr.authorize("user", "read_email").authorized

    def test_tool_allowlist_defense(self):
        """Equivalent to AgentDojo's Tool Filter defense, but hardware-enforced.

        AgentDojo shows tool filtering drops ASR from 57.7% -> 6.84%.
        TEE-MCP does this at MCP Server level (can't be bypassed by LLM).
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(ToolCapability),
                allowed_tools=frozenset({"read_email", "get_calendar", "search_files"}),
            )
        )

        assert self.mgr.authorize("any", "read_email").authorized
        assert self.mgr.authorize("any", "get_calendar").authorized
        assert self.mgr.authorize("any", "search_files").authorized
        # All write/send tools blocked even though capabilities allow them
        assert not self.mgr.authorize("any", "send_email").authorized
        assert not self.mgr.authorize("any", "transfer_money").authorized
        assert not self.mgr.authorize("any", "send_message").authorized

    def test_deny_list_for_sensitive_tools(self):
        """Explicit deny list for high-risk tools (financial, admin).

        Even with broad capabilities, specific dangerous tools are blocked.
        """
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(ToolCapability),
                denied_tools=frozenset({"transfer_money", "invite_user"}),
            )
        )

        assert self.mgr.authorize("any", "read_email").authorized
        assert self.mgr.authorize("any", "send_email").authorized
        # Explicitly denied
        assert not self.mgr.authorize("any", "transfer_money").authorized
        assert not self.mgr.authorize("any", "invite_user").authorized


# ---------------------------------------------------------------------------
# Custom analyzer tests
# ---------------------------------------------------------------------------


class TestCustomAnalyzer:
    def test_custom_analyzer_protocol(self):
        class MyAnalyzer:
            def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
                return {ToolCapability.ADMIN}  # Everything is admin

        mgr = AuthorizationManager(analyzer=MyAnalyzer())
        scope = mgr.register_tool("anything", "whatever")
        assert scope.capabilities == frozenset({ToolCapability.ADMIN})

    def test_protocol_check(self):
        assert isinstance(KeywordToolAnalyzer(), ToolAnalyzer)


# ---------------------------------------------------------------------------
# Metadata export tests
# ---------------------------------------------------------------------------


class TestMetadataExport:
    def test_to_metadata(self):
        mgr = AuthorizationManager()
        mgr.register_tool("read_email", "Read emails from inbox")
        mgr.register_tool("send_email", "Send an email")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )

        meta = mgr.to_metadata("user")
        assert "authorization" in meta
        assert meta["authorization"]["subject"] == "user"
        tools = meta["authorization"]["tools"]
        assert len(tools) == 2

        by_name = {t["tool"]: t for t in tools}
        assert by_name["read_email"]["authorized"] is True
        assert by_name["send_email"]["authorized"] is False
        assert by_name["send_email"]["reason"]  # non-empty reason for denied


# ---------------------------------------------------------------------------
# ToolScope frozen dataclass tests
# ---------------------------------------------------------------------------


class TestToolScope:
    def test_frozen(self):
        scope = ToolScope(
            tool_name="t",
            capabilities=frozenset({ToolCapability.READ}),
            description_hash="abc",
        )
        with pytest.raises(AttributeError):
            scope.tool_name = "modified"  # type: ignore[misc]

    def test_verified_default_false(self):
        scope = ToolScope(tool_name="t", capabilities=frozenset(), description_hash="x")
        assert scope.verified is False


class TestAccessRule:
    def test_frozen(self):
        rule = AccessRule(subject_pattern="*")
        with pytest.raises(AttributeError):
            rule.subject_pattern = "modified"  # type: ignore[misc]

    def test_defaults(self):
        rule = AccessRule(subject_pattern="*")
        assert rule.allowed_capabilities == frozenset()
        assert rule.denied_tools == frozenset()
        assert rule.allowed_tools is None
        assert rule.max_calls_per_minute == 0


class TestAuthorizationDecision:
    def test_frozen(self):
        d = AuthorizationDecision(authorized=True, reason="ok")
        with pytest.raises(AttributeError):
            d.authorized = False  # type: ignore[misc]
