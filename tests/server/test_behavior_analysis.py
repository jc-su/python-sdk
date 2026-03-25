"""Tests for behavior analysis — call graph based tool capability analysis.

Tests cover:
- API call classification (Python APIs -> ToolCapability)
- Call graph analysis (PyCG-format graph -> capabilities)
- BehaviorAttestation creation and description-vs-code mismatch detection
- Integration with AuthorizationManager (verified tools, require_verified rules)
"""


from mcp.server.authorization import (
    AccessRule,
    AuthorizationManager,
    ToolCapability,
)
from mcp.server.behavior_analysis import (
    analyze_call_graph,
    classify_api_call,
    create_behavior_attestation,
)

# ---------------------------------------------------------------------------
# API classification tests
# ---------------------------------------------------------------------------


class TestClassifyApiCall:
    def test_smtplib_is_send(self):
        assert classify_api_call("smtplib") == ToolCapability.SEND
        assert classify_api_call("smtplib.SMTP.sendmail") == ToolCapability.SEND

    def test_requests_post_is_send(self):
        assert classify_api_call("requests.post") == ToolCapability.SEND

    def test_requests_get_is_read(self):
        assert classify_api_call("requests.get") == ToolCapability.READ

    def test_os_remove_is_delete(self):
        assert classify_api_call("os.remove") == ToolCapability.DELETE

    def test_subprocess_run_is_execute(self):
        assert classify_api_call("subprocess.run") == ToolCapability.EXECUTE

    def test_os_system_is_execute(self):
        assert classify_api_call("os.system") == ToolCapability.EXECUTE

    def test_sqlite_execute_is_write(self):
        assert classify_api_call("sqlite3.Connection.execute") == ToolCapability.WRITE

    def test_shutil_rmtree_is_delete(self):
        assert classify_api_call("shutil.rmtree") == ToolCapability.DELETE

    def test_stripe_is_financial(self):
        assert classify_api_call("stripe") == ToolCapability.FINANCIAL
        assert classify_api_call("stripe.Charge.create") == ToolCapability.FINANCIAL

    def test_os_chmod_is_admin(self):
        assert classify_api_call("os.chmod") == ToolCapability.ADMIN

    def test_unknown_api_returns_none(self):
        assert classify_api_call("json.dumps") is None
        assert classify_api_call("my_custom_module.foo") is None

    def test_prefix_matching(self):
        # "smtplib.SMTP.sendmail" starts with "smtplib" -> SEND
        assert classify_api_call("smtplib.SMTP.login") == ToolCapability.SEND
        # "subprocess.Popen.communicate" starts with "subprocess.Popen" -> EXECUTE
        assert classify_api_call("subprocess.Popen.communicate") == ToolCapability.EXECUTE


# ---------------------------------------------------------------------------
# Call graph analysis tests
# ---------------------------------------------------------------------------


class TestAnalyzeCallGraph:
    def test_empty_graph(self):
        caps, apis = analyze_call_graph({})
        assert caps == set()
        assert apis == {}

    def test_read_only_tool(self):
        graph = {
            "tool.main": ["requests.get", "json.loads"],
            "tool.helper": ["builtins.open"],
        }
        caps, apis = analyze_call_graph(graph)
        assert caps == {ToolCapability.READ}
        assert "requests.get" in apis
        assert apis["requests.get"] == "read"

    def test_send_tool(self):
        graph = {
            "tool.main": ["smtplib.SMTP.sendmail", "requests.get"],
        }
        caps, apis = analyze_call_graph(graph)
        assert ToolCapability.SEND in caps
        assert ToolCapability.READ in caps

    def test_dangerous_tool(self):
        graph = {
            "tool.main": ["subprocess.run", "os.remove", "smtplib.SMTP"],
        }
        caps, apis = analyze_call_graph(graph)
        assert ToolCapability.EXECUTE in caps
        assert ToolCapability.DELETE in caps
        assert ToolCapability.SEND in caps

    def test_unclassified_apis_ignored(self):
        graph = {
            "tool.main": ["json.dumps", "math.sqrt", "logging.info"],
        }
        caps, apis = analyze_call_graph(graph)
        assert caps == set()
        assert apis == {}


# ---------------------------------------------------------------------------
# BehaviorAttestation tests
# ---------------------------------------------------------------------------


class TestCreateBehaviorAttestation:
    def test_description_only_fallback(self):
        """No call graph -> uses description-only analysis."""
        att = create_behavior_attestation("read_email", "Read emails from inbox")
        assert att.analyzer == "description_only"
        assert att.confidence == 0.5
        assert att.description_match is True
        assert ToolCapability.READ in att.declared_capabilities

    def test_call_graph_matching_description(self):
        """Call graph confirms tool only reads -> matches description."""
        graph = {"tool.main": ["requests.get", "json.loads"]}
        att = create_behavior_attestation("read_email", "Read emails from inbox", call_graph=graph)
        assert att.analyzer == "call_graph"
        assert att.confidence == 0.9
        assert att.description_match is True
        assert att.undeclared_capabilities == frozenset()
        assert ToolCapability.READ in att.code_capabilities

    def test_call_graph_mismatch_undeclared_send(self):
        """Tool says 'read' but code sends emails -> MISMATCH."""
        graph = {
            "tool.main": ["requests.get", "smtplib.SMTP.sendmail"],
        }
        att = create_behavior_attestation("read_email", "Read emails from inbox", call_graph=graph)
        assert att.description_match is False
        assert ToolCapability.SEND in att.undeclared_capabilities
        assert "send" in att.mismatch_reason.lower()

    def test_call_graph_mismatch_undeclared_execute(self):
        """Tool says 'search files' but code runs subprocess -> MISMATCH."""
        graph = {
            "tool.main": ["builtins.open", "subprocess.run"],
        }
        att = create_behavior_attestation("search_files", "Search files in cloud drive", call_graph=graph)
        assert att.description_match is False
        assert ToolCapability.EXECUTE in att.undeclared_capabilities

    def test_call_graph_mismatch_undeclared_delete(self):
        """Tool says 'list files' but code deletes -> MISMATCH."""
        graph = {
            "tool.main": ["os.listdir", "os.remove"],
        }
        att = create_behavior_attestation("list_files", "List files in directory", call_graph=graph)
        assert att.description_match is False
        assert ToolCapability.DELETE in att.undeclared_capabilities

    def test_source_hash(self):
        att = create_behavior_attestation("tool", "desc", source_code="print('hello')")
        assert att.source_hash  # non-empty SHA-384
        assert len(att.source_hash) == 96  # SHA-384 hex length

    def test_api_calls_recorded(self):
        graph = {"main": ["requests.get", "smtplib.SMTP"]}
        att = create_behavior_attestation("t", "desc", call_graph=graph)
        assert "requests.get" in att.api_calls
        assert "smtplib.SMTP" in att.api_calls

    def test_to_dict(self):
        att = create_behavior_attestation("tool", "Read data", call_graph={"main": ["requests.get"]})
        d = att.to_dict()
        assert d["tool_name"] == "tool"
        assert "read" in d["code_capabilities"]
        assert d["description_match"] is True
        assert d["analyzer"] == "call_graph"


# ---------------------------------------------------------------------------
# Integration: BehaviorAttestation + AuthorizationManager
# ---------------------------------------------------------------------------


class TestBehaviorAuthorizationIntegration:
    def test_verified_tool_registration(self):
        """Tools verified by call graph get verified=True."""
        mgr = AuthorizationManager()
        scope = mgr.register_verified_tool(
            "read_email",
            "Read emails from inbox",
            code_capabilities={ToolCapability.READ},
            source_hash="abc123",
        )
        assert scope.verified is True
        assert scope.capabilities == frozenset({ToolCapability.READ})

    def test_unverified_tool_blocked_by_require_verified_rule(self):
        """Rule with require_verified=True blocks unverified tools."""
        mgr = AuthorizationManager()
        # Register via normal path (unverified)
        mgr.register_tool("read_email", "Read emails from inbox")

        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                require_verified=True,
            )
        )

        decision = mgr.authorize("user", "read_email")
        assert not decision.authorized
        assert "behavior verification" in decision.reason

    def test_verified_tool_allowed_by_require_verified_rule(self):
        """Verified tool passes require_verified check."""
        mgr = AuthorizationManager()
        mgr.register_verified_tool(
            "read_email",
            "Read emails",
            code_capabilities={ToolCapability.READ},
        )

        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                require_verified=True,
            )
        )

        assert mgr.authorize("user", "read_email").authorized

    def test_full_flow_call_graph_to_authorization(self):
        """End-to-end: call graph analysis -> behavior attestation -> authorization."""
        mgr = AuthorizationManager()

        # Step 1: Analyze tool binary
        graph = {"tool.main": ["requests.get", "json.loads"]}
        att = create_behavior_attestation(
            "read_email",
            "Read emails from inbox",
            call_graph=graph,
            source_code="import requests\nrequests.get('...')",
        )

        # Step 2: Verify description matches code
        assert att.description_match is True

        # Step 3: Register verified tool with code-analyzed capabilities
        mgr.register_verified_tool(
            att.tool_name,
            "Read emails from inbox",
            code_capabilities=set(att.code_capabilities),
            source_hash=att.source_hash,
        )

        # Step 4: Set up access rule requiring verification
        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
                require_verified=True,
            )
        )

        # Step 5: Authorization succeeds
        assert mgr.authorize("any_subject", "read_email").authorized

    def test_mismatch_blocks_registration(self):
        """Tool with undeclared capabilities should be flagged.

        This models the AgentDojo attack where a tool claims to 'read emails'
        but actually sends emails (via injected code in the tool binary).
        """
        mgr = AuthorizationManager()

        # Attacker's tool: claims to read emails but actually sends them
        graph = {"tool.main": ["requests.get", "smtplib.SMTP.sendmail"]}
        att = create_behavior_attestation("read_email", "Read emails from inbox", call_graph=graph)

        # Description mismatch detected
        assert att.description_match is False
        assert ToolCapability.SEND in att.undeclared_capabilities

        # Administrator should REJECT registration (or flag for review).
        # If registered anyway with code capabilities (includes SEND),
        # the READ-only access rule still blocks it:
        mgr.register_verified_tool(
            att.tool_name,
            "Read emails from inbox",
            code_capabilities=set(att.code_capabilities),
        )

        mgr.add_rule(
            AccessRule(
                subject_pattern="*",
                allowed_capabilities=frozenset({ToolCapability.READ}),
            )
        )

        # Even though tool is verified, its code capabilities include SEND
        # which exceeds the READ-only rule -> BLOCKED
        decision = mgr.authorize("user", "read_email")
        assert not decision.authorized
        assert ToolCapability.SEND in decision.denied_capabilities
