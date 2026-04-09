"""Tests for AuthorizationManager with 11 security capability classes.

Tests cover:
- KeywordToolAnalyzer with security-consequence categories
- Access rule matching (glob patterns, explicit allow/deny)
- Capability-based authorization enforcement
- Rate limiting and fail-closed behavior
- AgentDojo + ASB attack prevention scenarios
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

TC = ToolCapability  # shorthand


# ---------------------------------------------------------------------------
# KeywordToolAnalyzer tests
# ---------------------------------------------------------------------------


class TestKeywordToolAnalyzer:
    def setup_method(self):
        self.analyzer = KeywordToolAnalyzer()

    # LOW risk
    def test_public_data(self):
        caps = self.analyzer.analyze("get_weather", "Get weather forecast for a city")
        assert TC.READ_PUBLIC in caps

    def test_external_ingestion(self):
        caps = self.analyzer.analyze("scrape_url", "Scrape a webpage and return content")
        assert TC.EXTERNAL_INGESTION in caps

    # MEDIUM risk
    def test_read_private(self):
        caps = self.analyzer.analyze("get_emails", "Retrieve emails from inbox")
        assert TC.READ_PRIVATE in caps

    def test_write_mutate(self):
        caps = self.analyzer.analyze("create_event", "Create a new calendar event")
        assert TC.WRITE_MUTATE in caps

    # HIGH risk
    def test_read_identity(self):
        caps = self.analyzer.analyze("get_personal_info", "Get user personal identity and contact details")
        assert TC.READ_IDENTITY in caps

    def test_data_destruction(self):
        caps = self.analyzer.analyze("delete_email", "Delete an email from inbox")
        assert TC.DATA_DESTRUCTION in caps

    def test_cross_boundary_egress(self):
        caps = self.analyzer.analyze("send_email", "Send an email to a recipient")
        assert TC.CROSS_BOUNDARY_EGRESS in caps

    def test_value_transfer(self):
        caps = self.analyzer.analyze("transfer_money", "Transfer funds between accounts")
        assert TC.VALUE_TRANSFER in caps

    # CRITICAL risk
    def test_credential_access(self):
        caps = self.analyzer.analyze("get_api_token", "Retrieve the API token for authentication")
        assert TC.CREDENTIAL_ACCESS in caps

    def test_identity_admin(self):
        caps = self.analyzer.analyze("manage_roles", "Manage user roles and permissions")
        assert TC.IDENTITY_ADMIN in caps

    def test_code_execution(self):
        caps = self.analyzer.analyze("run_script", "Execute a shell script on the server")
        assert TC.CODE_EXECUTION in caps

    # Multi-capability
    def test_multi_capability(self):
        caps = self.analyzer.analyze("send_payment", "Send a payment transaction to recipient")
        assert TC.CROSS_BOUNDARY_EGRESS in caps
        assert TC.VALUE_TRANSFER in caps

    # Fallback
    def test_unknown_defaults_to_read_private(self):
        caps = self.analyzer.analyze("foobar", "does something mysterious")
        assert caps == {TC.READ_PRIVATE}

    def test_case_insensitive(self):
        caps = self.analyzer.analyze("SendEmail", "SEND an email")
        assert TC.CROSS_BOUNDARY_EGRESS in caps

    def test_booking_is_value_transfer(self):
        caps = self.analyzer.analyze("book_hotel", "Book a hotel room for the given dates")
        assert TC.VALUE_TRANSFER in caps


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def setup_method(self):
        self.mgr = AuthorizationManager()

    def test_register_tool_auto_analysis(self):
        scope = self.mgr.register_tool("read_email", "Read emails from inbox")
        assert scope.tool_name == "read_email"
        assert TC.READ_PRIVATE in scope.capabilities
        assert scope.description_hash

    def test_register_tool_with_override(self):
        scope = self.mgr.register_tool(
            "custom_tool",
            "Does custom things",
            capabilities_override={TC.IDENTITY_ADMIN, TC.WRITE_MUTATE},
        )
        assert scope.capabilities == frozenset({TC.IDENTITY_ADMIN, TC.WRITE_MUTATE})

    def test_get_tool_scope(self):
        self.mgr.register_tool("t1", "Read data from files")
        assert self.mgr.get_tool_scope("t1") is not None
        assert self.mgr.get_tool_scope("nonexistent") is None

    def test_registered_tools(self):
        self.mgr.register_tool("a", "Read data from files")
        self.mgr.register_tool("b", "Write data to files")
        assert "a" in self.mgr.registered_tools()
        assert "b" in self.mgr.registered_tools()

    def test_description_hash_integrity(self):
        s1 = self.mgr.register_tool("t1", "Read data")
        s2 = self.mgr.register_tool("t2", "Read data")
        s3 = self.mgr.register_tool("t3", "Different")
        assert s1.description_hash == s2.description_hash
        assert s1.description_hash != s3.description_hash


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
        self.mgr.register_tool("run_script", "Execute a shell script")
        self.mgr.register_tool("get_weather", "Get weather forecast")

    def test_fail_closed_no_rule(self):
        decision = self.mgr.authorize("cgroup:///unknown", "read_email")
        assert not decision.authorized
        assert "no authorization rule" in decision.reason

    def test_fail_closed_unregistered_tool(self):
        self.mgr.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=frozenset(TC)))
        decision = self.mgr.authorize("any", "nonexistent_tool")
        assert not decision.authorized
        assert "not registered" in decision.reason

    def test_read_private_only_rule(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/reader*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        subject = "cgroup:///kubepods/reader.scope"
        assert self.mgr.authorize(subject, "read_email").authorized
        assert self.mgr.authorize(subject, "get_calendar").authorized
        assert self.mgr.authorize(subject, "get_weather").authorized
        assert not self.mgr.authorize(subject, "send_email").authorized
        assert not self.mgr.authorize(subject, "transfer_money").authorized
        assert not self.mgr.authorize(subject, "delete_email").authorized
        assert not self.mgr.authorize(subject, "run_script").authorized

    def test_full_access_rule(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/admin*",
                allowed_capabilities=frozenset(TC),
            )
        )
        subject = "cgroup:///kubepods/admin.scope"
        for tool in ["read_email", "send_email", "transfer_money", "delete_email", "run_script"]:
            assert self.mgr.authorize(subject, tool).authorized

    def test_explicit_deny_list(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(TC),
                denied_tools=frozenset({"transfer_money"}),
            )
        )
        assert self.mgr.authorize("any", "read_email").authorized
        assert not self.mgr.authorize("any", "transfer_money").authorized

    def test_explicit_allow_list(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(TC),
                allowed_tools=frozenset({"read_email", "get_calendar"}),
            )
        )
        assert self.mgr.authorize("any", "read_email").authorized
        assert not self.mgr.authorize("any", "send_email").authorized

    def test_first_matching_rule_wins(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/agent-reader*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset(TC),
            )
        )
        assert self.mgr.authorize("cgroup:///kubepods/agent-reader.scope", "read_email").authorized
        assert not self.mgr.authorize("cgroup:///kubepods/agent-reader.scope", "send_email").authorized
        assert self.mgr.authorize("cgroup:///kubepods/admin.scope", "send_email").authorized

    def test_default_rule_fallback(self):
        self.mgr.set_default_rule(
            AccessRule(
                subject_pattern="<default>",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        assert self.mgr.authorize("unknown", "read_email").authorized
        assert not self.mgr.authorize("unknown", "send_email").authorized

    def test_denied_capabilities_in_decision(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
            )
        )
        decision = self.mgr.authorize("any", "send_email")
        assert not decision.authorized
        assert TC.CROSS_BOUNDARY_EGRESS in decision.denied_capabilities

    def test_get_authorized_tools(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        authorized = self.mgr.get_authorized_tools("any")
        assert "read_email" in authorized
        assert "get_weather" in authorized
        assert "send_email" not in authorized


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
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                max_calls_per_minute=3,
            )
        )
        assert mgr.authorize("user", "read_email").authorized
        assert mgr.authorize("user", "read_email").authorized
        assert mgr.authorize("user", "read_email").authorized
        assert not mgr.authorize("user", "read_email").authorized

    def test_rate_limit_per_subject_tool(self):
        mgr = AuthorizationManager()
        mgr.register_tool("t1", "Read data from files")
        mgr.register_tool("t2", "Get items from list")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                max_calls_per_minute=1,
            )
        )
        assert mgr.authorize("a", "t1").authorized
        assert not mgr.authorize("a", "t1").authorized
        assert mgr.authorize("a", "t2").authorized
        assert mgr.authorize("b", "t1").authorized

    def test_rate_limit_window_expires(self):
        mgr = AuthorizationManager()
        mgr.register_tool("t", "Read data from files")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                max_calls_per_minute=1,
            )
        )
        assert mgr.authorize("u", "t").authorized
        assert not mgr.authorize("u", "t").authorized
        mgr._rate_windows[("u", "t")].timestamps = [time.monotonic() - 61.0]
        assert mgr.authorize("u", "t").authorized

    def test_zero_rate_means_unlimited(self):
        mgr = AuthorizationManager()
        mgr.register_tool("t", "Read data from files")
        mgr.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=frozenset({TC.READ_PRIVATE})))
        for _ in range(100):
            assert mgr.authorize("u", "t").authorized


# ---------------------------------------------------------------------------
# AgentDojo + ASB attack prevention scenarios
# ---------------------------------------------------------------------------


class TestAttackPrevention:
    """Verify authorization blocks real attack patterns from AgentDojo and ASB."""

    def setup_method(self):
        self.mgr = AuthorizationManager()
        # AgentDojo tools
        self.mgr.register_tool("read_email", "Read emails from inbox")
        self.mgr.register_tool("send_email", "Send an email to a recipient")
        self.mgr.register_tool("transfer_money", "Transfer funds to another account")
        self.mgr.register_tool("delete_email", "Delete an email from inbox")
        self.mgr.register_tool("get_calendar", "Get calendar events for a day")
        self.mgr.register_tool("create_event", "Create a new calendar event and send invites")
        self.mgr.register_tool("reserve_hotel", "Book a hotel reservation")
        self.mgr.register_tool("read_channel", "Read messages from a Slack channel")
        self.mgr.register_tool("send_message", "Send a direct message to a user")
        self.mgr.register_tool("remove_user", "Remove a user from the workspace")
        self.mgr.register_tool("update_password", "Update the user account password")

    def test_agentdojo_workspace_exfiltration(self):
        """Agent reads emails, injection tries to send them to attacker."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/email-reader*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        subject = "cgroup:///kubepods/email-reader.scope"
        assert self.mgr.authorize(subject, "read_email").authorized
        assert not self.mgr.authorize(subject, "send_email").authorized
        assert not self.mgr.authorize(subject, "delete_email").authorized

    def test_agentdojo_banking_theft(self):
        """Agent views balance, injection tries to transfer money."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/bank-viewer*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                denied_tools=frozenset({"transfer_money"}),
            )
        )
        subject = "cgroup:///kubepods/bank-viewer.scope"
        assert not self.mgr.authorize(subject, "transfer_money").authorized

    def test_agentdojo_travel_fake_booking(self):
        """Agent searches hotels, injection tries to book + create fake events."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/travel-searcher*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC}),
            )
        )
        subject = "cgroup:///kubepods/travel-searcher.scope"
        assert not self.mgr.authorize(subject, "reserve_hotel").authorized
        assert not self.mgr.authorize(subject, "create_event").authorized

    def test_agentdojo_slack_phishing(self):
        """Agent reads channels, injection tries to send phishing message."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/slack-reader*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        subject = "cgroup:///kubepods/slack-reader.scope"
        assert self.mgr.authorize(subject, "read_channel").authorized
        assert not self.mgr.authorize(subject, "send_message").authorized
        assert not self.mgr.authorize(subject, "remove_user").authorized

    def test_asb_credential_theft(self):
        """ASB IT scenario: injection tries to harvest credentials."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/monitor*",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )
        subject = "cgroup:///kubepods/monitor.scope"
        assert not self.mgr.authorize(subject, "update_password").authorized

    def test_evidence_destruction_cover_up(self):
        """AgentDojo multi-step: exfil emails, then delete originals to cover tracks."""
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup://*/email-reader*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
            )
        )
        subject = "cgroup:///kubepods/email-reader.scope"
        assert not self.mgr.authorize(subject, "send_email").authorized
        assert not self.mgr.authorize(subject, "delete_email").authorized

    def test_rate_limit_dos(self):
        self.mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                max_calls_per_minute=5,
            )
        )
        for _ in range(5):
            assert self.mgr.authorize("user", "read_email").authorized
        assert not self.mgr.authorize("user", "read_email").authorized


# ---------------------------------------------------------------------------
# Verified tool tests
# ---------------------------------------------------------------------------


class TestVerifiedTools:
    def test_require_verified_blocks_unverified(self):
        mgr = AuthorizationManager()
        mgr.register_tool("t", "Read data from files")
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                require_verified=True,
            )
        )
        assert not mgr.authorize("u", "t").authorized
        assert "behavior verification" in mgr.authorize("u", "t").reason

    def test_require_verified_allows_verified(self):
        mgr = AuthorizationManager()
        mgr.register_verified_tool("t", "Read data", code_capabilities={TC.READ_PRIVATE})
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({TC.READ_PRIVATE}),
                require_verified=True,
            )
        )
        assert mgr.authorize("u", "t").authorized


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_tool_scope_frozen(self):
        scope = ToolScope(tool_name="t", capabilities=frozenset({TC.READ_PRIVATE}), description_hash="abc")
        with pytest.raises(AttributeError):
            scope.tool_name = "x"  # type: ignore[misc]

    def test_tool_scope_verified_default(self):
        scope = ToolScope(tool_name="t", capabilities=frozenset(), description_hash="x")
        assert scope.verified is False

    def test_access_rule_frozen(self):
        rule = AccessRule(subject_pattern="*")
        with pytest.raises(AttributeError):
            rule.subject_pattern = "x"  # type: ignore[misc]

    def test_access_rule_defaults(self):
        rule = AccessRule(subject_pattern="*")
        assert rule.allowed_capabilities == frozenset()
        assert rule.allowed_tools is None
        assert rule.max_calls_per_minute == 0
        assert rule.require_verified is False

    def test_decision_frozen(self):
        d = AuthorizationDecision(authorized=True, reason="ok")
        with pytest.raises(AttributeError):
            d.authorized = False  # type: ignore[misc]

    def test_custom_analyzer_protocol(self):
        class MyAnalyzer:
            def analyze(self, tool_name: str, description: str) -> set[ToolCapability]:
                return {TC.CODE_EXECUTION}

        mgr = AuthorizationManager(analyzer=MyAnalyzer())
        scope = mgr.register_tool("anything", "whatever")
        assert scope.capabilities == frozenset({TC.CODE_EXECUTION})

    def test_protocol_check(self):
        assert isinstance(KeywordToolAnalyzer(), ToolAnalyzer)

    def test_to_metadata(self):
        mgr = AuthorizationManager()
        mgr.register_tool("read_email", "Read emails from inbox")
        mgr.register_tool("send_email", "Send an email")
        mgr.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=frozenset({TC.READ_PRIVATE})))

        meta = mgr.to_metadata("user")
        assert "authorization" in meta
        tools = meta["authorization"]["tools"]
        by_name = {t["tool"]: t for t in tools}
        assert by_name["read_email"]["authorized"] is True
        assert by_name["send_email"]["authorized"] is False
