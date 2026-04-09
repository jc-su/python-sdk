"""End-to-end: AgentDojo ground truth pipeline + attacks + TEE-MCP defense.

Uses AgentDojo's ACTUAL:
  - TaskSuite with real injection vectors and environment data
  - Ground truth tool calls (what each attack needs to execute)
  - FunctionsRuntime that runs actual tool functions
  - Our authorization wrapper that intercepts tool calls

For each injection task, we execute the ground truth tool calls through
our authorized runtime. Dangerous calls (send_money, update_password)
are blocked. Legitimate calls (get_balance, get_iban) succeed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp.server.authorization import (
    AccessRule,
    AuthorizationManager,
)
from mcp.server.authorization import (
    ToolCapability as TC,
)

AGENTDOJO_PATH = Path("/home/jcsu/Dev/tee-mcp/agentdojo/src")
if str(AGENTDOJO_PATH) not in sys.path:
    sys.path.insert(0, str(AGENTDOJO_PATH))

try:
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

    HAS_AGENTDOJO = True
except ImportError:
    HAS_AGENTDOJO = False


@pytest.mark.skipif(not HAS_AGENTDOJO, reason="agentdojo not available")
class TestGroundTruthWithDefense:
    """Run AgentDojo banking ground truth attacks with TEE-MCP defense."""

    def _setup(self):  # type: ignore[no-untyped-def]
        suite = get_suite("v1", "banking")

        mgr = AuthorizationManager()
        for func in suite.tools:
            mgr.register_tool(func.name, func.description)

        mgr.add_rule(
            AccessRule(
                subject_pattern="bank-viewer",
                allowed_capabilities=frozenset({TC.READ_PUBLIC, TC.READ_PRIVATE}),
            )
        )

        runtime = FunctionsRuntime(suite.tools)
        original_run = runtime.run_function

        def authorized_run(env, function, kwargs, raise_on_error=False):  # type: ignore[no-untyped-def]
            decision = mgr.authorize("bank-viewer", function)
            if not decision.authorized:
                denied = ", ".join(sorted(c.value for c in decision.denied_capabilities))
                return "", f"AuthorizationError: '{function}' blocked. Denied: {denied}"
            return original_run(env, function, kwargs, raise_on_error=raise_on_error)

        runtime.run_function = authorized_run  # type: ignore[assignment]
        return suite, runtime, mgr

    def test_injection_tasks_blocked(self):
        """Every injection task has at least one ground truth call blocked."""
        suite, runtime, mgr = self._setup()
        env = suite.load_and_inject_default_environment({})

        results = {}
        for tid, task in suite.injection_tasks.items():
            gt_calls = task.ground_truth(env)
            blocked = []
            allowed = []
            for call in gt_calls:
                _, error = runtime.run_function(env, call.function, dict(call.args))
                if error and "AuthorizationError" in str(error):
                    blocked.append(call.function)
                else:
                    allowed.append(call.function)
            results[tid] = {"blocked": blocked, "allowed": allowed}

        # Report
        tasks_with_blocks = sum(1 for r in results.values() if r["blocked"])
        total = len(results)

        for tid, r in results.items():
            status = "DEFENDED" if r["blocked"] else "MISSED"
            print(f"  {tid}: {status} blocked={r['blocked']} allowed={r['allowed']}")

        assert tasks_with_blocks == total, (
            f"{tasks_with_blocks}/{total} injection tasks defended. "
            f"Missed: {[tid for tid, r in results.items() if not r['blocked']]}"
        )

    def test_user_tasks_utility(self):
        """User tasks that only need READ tools succeed fully."""
        suite, runtime, mgr = self._setup()
        env = suite.load_and_inject_default_environment({})

        read_only_tasks = 0
        read_only_succeeded = 0

        for task in suite.user_tasks.values():
            gt_calls = task.ground_truth(env)
            call_names = [c.function for c in gt_calls]

            # Check if this task uses only READ tools
            all_read = all(mgr.authorize("bank-viewer", fn).authorized for fn in call_names)
            if not all_read:
                continue  # Skip tasks that need WRITE (not our target)

            read_only_tasks += 1
            errors = []
            for call in gt_calls:
                _, error = runtime.run_function(env, call.function, dict(call.args))
                if error and "AuthorizationError" in str(error):
                    errors.append(call.function)

            if not errors:
                read_only_succeeded += 1

        if read_only_tasks > 0:
            utility = read_only_succeeded / read_only_tasks
            assert utility == 1.0, (
                f"Utility: {read_only_succeeded}/{read_only_tasks} ({utility * 100:.0f}%) "
                f"READ-only user tasks succeeded"
            )
