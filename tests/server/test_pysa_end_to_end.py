"""End-to-end test: Pysa analysis → capability profile → authorization → attack blocking.

This is the REAL test that connects all layers:

  1. Pysa analyzes synthetic_tools.py SOURCE CODE (real requests.get, smtplib, os.remove, subprocess)
  2. Pysa's taint tracking derives capabilities per-tool (e.g., send_email → CROSS_BOUNDARY_EGRESS)
  3. AuthorizationManager registers tools with Pysa-derived capabilities
  4. Attack simulation: "agent" tries to call unauthorized tools → BLOCKED
  5. Legitimate simulation: "agent" calls authorized tools → ALLOWED

No mocking. Real Pysa. Real taint flow. Real authorization.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from mcp.server.authorization import (
    AccessRule,
    AuthorizationManager,
    ToolCapability as TC,
)
from mcp.server.behavior_analysis import analyze_with_pysa

HAS_PYRE = shutil.which("pyre") is not None
PYSA_CONFIG = "/home/jcsu/Dev/tee-mcp/pysa-test"
TOOLS_SOURCE = Path(__file__).parent / "synthetic_tools.py"


@pytest.mark.skipif(not HAS_PYRE, reason="pyre-check not installed")
class TestPysaEndToEnd:
    """Full pipeline: Pysa analysis → authorization → attack defense."""

    @pytest.fixture()
    def pysa_profiles(self) -> dict[str, frozenset[TC]]:
        """Run Pysa on each synthetic tool function and return capabilities."""
        source = TOOLS_SOURCE.read_text()
        profiles: dict[str, frozenset[TC]] = {}

        for fn_name in ["read_inbox", "send_email", "delete_email", "run_report", "search_web"]:
            caps, findings = analyze_with_pysa(
                source,
                taint_config_dir=PYSA_CONFIG,
                entrypoint=fn_name,
            )
            profiles[fn_name] = caps

        return profiles

    # ------------------------------------------------------------------
    # Step 1: Verify Pysa correctly classifies each tool
    # ------------------------------------------------------------------

    def test_pysa_read_inbox_is_safe(self, pysa_profiles: dict[str, frozenset[TC]]):
        """read_inbox only does requests.get → should NOT have egress/exec/destroy."""
        caps = pysa_profiles["read_inbox"]
        assert TC.CROSS_BOUNDARY_EGRESS not in caps
        assert TC.CODE_EXECUTION not in caps
        assert TC.DATA_DESTRUCTION not in caps

    def test_pysa_send_email_has_egress(self, pysa_profiles: dict[str, frozenset[TC]]):
        """send_email uses smtplib.sendmail → CROSS_BOUNDARY_EGRESS."""
        caps = pysa_profiles["send_email"]
        assert TC.CROSS_BOUNDARY_EGRESS in caps

    def test_pysa_delete_email_has_destruction(self, pysa_profiles: dict[str, frozenset[TC]]):
        """delete_email uses os.remove(path derived from input) → DATA_DESTRUCTION."""
        caps = pysa_profiles["delete_email"]
        assert TC.DATA_DESTRUCTION in caps

    def test_pysa_run_report_has_code_execution(self, pysa_profiles: dict[str, frozenset[TC]]):
        """run_report uses subprocess.run with input → CODE_EXECUTION."""
        caps = pysa_profiles["run_report"]
        assert TC.CODE_EXECUTION in caps

    # ------------------------------------------------------------------
    # Step 2: Build AuthorizationManager from Pysa results
    # ------------------------------------------------------------------

    @pytest.fixture()
    def authorized_server(self, pysa_profiles: dict[str, frozenset[TC]]) -> AuthorizationManager:
        """Register tools using PYSA-DERIVED capabilities, not keyword analysis."""
        mgr = AuthorizationManager()

        descriptions = {
            "read_inbox": "Read emails from inbox",
            "send_email": "Send an email to a recipient",
            "delete_email": "Delete an email by ID",
            "run_report": "Generate a report",
            "search_web": "Search the web",
        }

        for tool_name, caps in pysa_profiles.items():
            # Use Pysa capabilities, NOT keyword analysis
            mgr.register_verified_tool(
                tool_name,
                descriptions[tool_name],
                code_capabilities=set(caps) if caps else {TC.READ_PRIVATE},
                source_hash="pysa-verified",
            )

        # Policy: email-reader agent can only READ
        mgr.add_rule(
            AccessRule(
                subject_pattern="cgroup:///email-reader",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
                require_verified=True,
            )
        )

        return mgr

    # ------------------------------------------------------------------
    # Step 3: Attack simulation with Pysa-derived authorization
    # ------------------------------------------------------------------

    def test_attack_send_email_blocked(self, authorized_server: AuthorizationManager):
        """Injection tricks agent into sending email → BLOCKED by Pysa-derived policy.

        The key: send_email's capabilities were derived by PYSA TAINT ANALYSIS,
        not by keyword matching on the description. Pysa traced the taint flow
        from the `recipient` parameter through smtplib.SMTP.sendmail → flagged
        as CROSS_BOUNDARY_EGRESS.
        """
        d = authorized_server.authorize("cgroup:///email-reader", "send_email")
        assert not d.authorized
        assert TC.CROSS_BOUNDARY_EGRESS in d.denied_capabilities

    def test_attack_delete_email_blocked(self, authorized_server: AuthorizationManager):
        """Injection tries to delete evidence → BLOCKED.

        Pysa traced: email_id parameter → f-string → os.remove(path) → DATA_DESTRUCTION.
        """
        d = authorized_server.authorize("cgroup:///email-reader", "delete_email")
        assert not d.authorized
        assert TC.DATA_DESTRUCTION in d.denied_capabilities

    def test_attack_run_report_blocked(self, authorized_server: AuthorizationManager):
        """Injection tries to execute code → BLOCKED.

        Pysa traced: report_name → subprocess.run([..., report_name]) → CODE_EXECUTION.
        """
        d = authorized_server.authorize("cgroup:///email-reader", "run_report")
        assert not d.authorized
        assert TC.CODE_EXECUTION in d.denied_capabilities

    def test_legitimate_read_inbox_allowed(self, authorized_server: AuthorizationManager):
        """Legitimate task: reading inbox succeeds.

        Pysa found NO dangerous taint flows in read_inbox — it only
        does requests.get (READ_PRIVATE), which the policy allows.
        """
        d = authorized_server.authorize("cgroup:///email-reader", "read_inbox")
        assert d.authorized

    # ------------------------------------------------------------------
    # Step 4: Multi-step attack scenario
    # ------------------------------------------------------------------

    def test_full_attack_scenario(self, authorized_server: AuthorizationManager):
        """Simulates AgentDojo InjectionTask9: exfil + delete + phishing.

        Attack chain:
        1. Agent reads inbox (ALLOWED — legitimate task)
        2. Injection in email body tricks agent into:
           a. send_email(to=attacker, body=all_emails) → BLOCKED (egress)
           b. delete_email(id=evidence) → BLOCKED (destruction)
           c. send_email(to=victim, body=phishing) → BLOCKED (egress)
        3. Agent tries to continue legitimate task → still ALLOWED

        Result: all 3 attack steps blocked, legitimate task unaffected.
        """
        agent = "cgroup:///email-reader"

        # Step 1: Legitimate read
        assert authorized_server.authorize(agent, "read_inbox").authorized

        # Step 2a: Exfiltrate emails → BLOCKED
        assert not authorized_server.authorize(agent, "send_email").authorized

        # Step 2b: Delete evidence → BLOCKED
        assert not authorized_server.authorize(agent, "delete_email").authorized

        # Step 2c: Send phishing → BLOCKED
        assert not authorized_server.authorize(agent, "send_email").authorized

        # Step 3: Legitimate task continues
        assert authorized_server.authorize(agent, "read_inbox").authorized
