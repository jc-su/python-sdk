"""Tests for attestation policy framework (Part D)."""

import base64

from mcp.shared.attestation_policy import AttestationPolicy, PolicyRegistry
from mcp.shared.tee_envelope import create_request_envelope


# =============================================================================
# Mock classes (reused from test_tee_envelope)
# =============================================================================


class MockAttestationEvidence:
    def __init__(self, role="client", nonce=b"\x00" * 32):
        self.quote = b"mock_quote"
        self.public_key = b"mock_pubkey"
        self.nonce = nonce
        self.cgroup = "/docker/container"
        self.rtmr3 = bytes(48)
        self.timestamp_ms = 9999999999999
        self.role = role

    def to_dict(self):
        return {
            "quote": base64.b64encode(self.quote).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "cgroup": self.cgroup,
            "rtmr3": self.rtmr3.hex(),
            "timestamp_ms": self.timestamp_ms,
            "role": self.role,
        }


class MockSecureEndpoint:
    def __init__(self, role="client"):
        self.role = role
        self.peers = {}
        self.session_id = None

    def create_evidence(self, nonce):
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def get_peer(self, role):
        return self.peers.get(role)


# =============================================================================
# PolicyRegistry tests
# =============================================================================


class TestAttestationPolicy:
    def test_default_values(self):
        policy = AttestationPolicy(name="test")
        assert policy.require_attestation is True
        assert policy.require_encryption is True
        assert policy.allowed_rtmr3 is None
        assert policy.max_evidence_age_ms == 300_000
        assert policy.rtmr3_transition_policy == "log_and_accept"

    def test_custom_values(self):
        policy = AttestationPolicy(
            name="strict",
            require_attestation=True,
            require_encryption=True,
            allowed_rtmr3=["abc*", "def*"],
            allowed_cgroups=["/docker/*"],
            max_evidence_age_ms=60_000,
            rtmr3_transition_policy="reject",
        )
        assert policy.name == "strict"
        assert policy.allowed_rtmr3 == ["abc*", "def*"]
        assert policy.allowed_cgroups == ["/docker/*"]
        assert policy.max_evidence_age_ms == 60_000

    def test_frozen(self):
        policy = AttestationPolicy(name="test")
        try:
            policy.name = "changed"  # type: ignore[misc]
            assert False, "Should raise"
        except AttributeError:
            pass


class TestPolicyRegistry:
    def test_register_and_resolve(self):
        reg = PolicyRegistry()
        agent_policy = AttestationPolicy(name="agents", max_evidence_age_ms=60_000)
        reg.register("mcp://agent-*", agent_policy)

        resolved = reg.resolve("mcp://agent-orchestrator.example.com")
        assert resolved.name == "agents"
        assert resolved.max_evidence_age_ms == 60_000

    def test_default_for_unknown(self):
        reg = PolicyRegistry()
        resolved = reg.resolve("mcp://unknown-service")
        assert resolved.name == "default"

    def test_set_default(self):
        reg = PolicyRegistry()
        custom_default = AttestationPolicy(name="custom_default", require_encryption=False)
        reg.set_default(custom_default)

        resolved = reg.resolve("mcp://unknown")
        assert resolved.name == "custom_default"
        assert resolved.require_encryption is False

    def test_first_match_wins(self):
        reg = PolicyRegistry()
        reg.register("mcp://agent-*", AttestationPolicy(name="agents"))
        reg.register("mcp://*", AttestationPolicy(name="all"))

        resolved = reg.resolve("mcp://agent-foo")
        assert resolved.name == "agents"

    def test_glob_matching(self):
        reg = PolicyRegistry()
        reg.register("mcp://tool-provider-*", AttestationPolicy(name="tools"))
        reg.register("mcp://llm-*", AttestationPolicy(name="llm"))

        assert reg.resolve("mcp://tool-provider-alpha").name == "tools"
        assert reg.resolve("mcp://llm-inference").name == "llm"
        assert reg.resolve("mcp://other").name == "default"

    def test_exact_match(self):
        reg = PolicyRegistry()
        reg.register("mcp://specific-service", AttestationPolicy(name="specific"))

        assert reg.resolve("mcp://specific-service").name == "specific"
        assert reg.resolve("mcp://specific-service-extra").name == "default"

    def test_patterns_property(self):
        reg = PolicyRegistry()
        p1 = AttestationPolicy(name="p1")
        p2 = AttestationPolicy(name="p2")
        reg.register("a*", p1)
        reg.register("b*", p2)

        patterns = reg.patterns
        assert len(patterns) == 2
        assert patterns[0] == ("a*", p1)
        assert patterns[1] == ("b*", p2)


class TestWorkloadIdInEnvelope:
    def test_workload_id_included_in_envelope(self):
        endpoint = MockSecureEndpoint(role="client")
        params = {"name": "tool", "arguments": {}}

        tee_dict, _ = create_request_envelope(endpoint, params, peer_role="server", workload_id="mcp://my-agent")

        assert tee_dict["workload_id"] == "mcp://my-agent"

    def test_no_workload_id_by_default(self):
        endpoint = MockSecureEndpoint(role="client")
        params = {"name": "tool"}

        tee_dict, _ = create_request_envelope(endpoint, params)

        assert "workload_id" not in tee_dict
