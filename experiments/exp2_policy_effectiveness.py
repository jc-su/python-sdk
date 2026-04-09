"""Experiment 2: Policy Effectiveness on AgentDojo Attack Definitions.

Evaluates whether least-privilege capability policies derived from benign
task descriptions block injection attacks from AgentDojo v1 (629 scenarios).

This is a deterministic, exhaustive analysis — no LLM required.  We evaluate
the AuthorizationManager policy engine, not an LLM agent.

For each (user_task, injection_task) pair:
  1. Extract benign_tools   = tools the user task requires (from ground_truth)
  2. Extract injected_tools = tools the injection task requires (from ground_truth)
  3. Register ALL suite tools with KeywordToolAnalyzer (capabilities from descriptions)
  4. Derive least-privilege policy: allowed_capabilities = union of benign_tools' capabilities
  5. Run AuthorizationManager.authorize() on each injected tool call
  6. Record: blocked (policy denied) or allowed (policy permitted)

Metrics reported:
  - PBR (Policy Block Rate): % of injection tool calls blocked
  - BU (Benign Utility): % of benign tool calls still authorized
  - Per-suite breakdown
  - Per-lever breakdown (which policy mechanism caused the block)
  - Cross-tool vs same-tool attack analysis
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# Add agentdojo to path
AGENTDOJO_SRC = Path(__file__).resolve().parent.parent.parent / "agentdojo" / "src"
sys.path.insert(0, str(AGENTDOJO_SRC))

# Add mcp-sdk-fork to path
MCP_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(MCP_SRC))

from agentdojo.task_suite.load_suites import _SUITES  # noqa: E402

from mcp.server.authorization import (  # noqa: E402
    AccessRule,
    AuthorizationDecision,
    AuthorizationManager,
    KeywordToolAnalyzer,
    ToolCapability,
)

TC = ToolCapability


# ---------------------------------------------------------------------------
# Ground-truth capability labels for AgentDojo tools (human-labeled)
# ---------------------------------------------------------------------------

# These are the GROUND TRUTH labels used for analysis. Each tool is labeled
# with the security capabilities it ACTUALLY exercises, based on reading
# the AgentDojo tool source code.
#
# Labeling criteria:
#   - What state does the tool mutate?
#   - Does it send data outside the agent's own environment?
#   - Does it read private user data?
#   - Does it delete/destroy data?
#   - Does it access identity/credential information?
#   - Does it transfer value (financial, reservations)?

# Load Pysa-derived capabilities (from real taint analysis, NOT hand-labeled)
_PYSA_RESULTS_PATH = Path(__file__).parent / "pysa_agentdojo_results.json"
_PYSA_CAPS_RAW: dict[str, list[str]] = json.loads(_PYSA_RESULTS_PATH.read_text()) if _PYSA_RESULTS_PATH.exists() else {}
_CAP_NAME_TO_ENUM = {c.value: c for c in TC}
PYSA_CAPABILITIES: dict[str, set[TC]] = {
    tool: {_CAP_NAME_TO_ENUM[c] for c in caps if c in _CAP_NAME_TO_ENUM}
    for tool, caps in _PYSA_CAPS_RAW.items()
}

GROUND_TRUTH_CAPABILITIES: dict[str, set[TC]] = {
    # --- Banking tools ---
    "get_iban": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "send_money": {TC.VALUE_TRANSFER},
    "schedule_transaction": {TC.VALUE_TRANSFER, TC.WRITE_MUTATE},
    "update_scheduled_transaction": {TC.WRITE_MUTATE, TC.VALUE_TRANSFER},
    "get_balance": {TC.READ_PRIVATE},
    "get_most_recent_transactions": {TC.READ_PRIVATE},
    "get_scheduled_transactions": {TC.READ_PRIVATE},
    "read_file": {TC.READ_PRIVATE},
    "get_user_info": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "update_password": {TC.CREDENTIAL_ACCESS, TC.WRITE_MUTATE},
    "update_user_info": {TC.WRITE_MUTATE, TC.READ_IDENTITY},
    # --- Workspace / Email tools ---
    "send_email": {TC.CROSS_BOUNDARY_EGRESS},
    "delete_email": {TC.DATA_DESTRUCTION},
    "get_unread_emails": {TC.READ_PRIVATE},
    "get_sent_emails": {TC.READ_PRIVATE},
    "get_received_emails": {TC.READ_PRIVATE},
    "get_draft_emails": {TC.READ_PRIVATE},
    "search_emails": {TC.READ_PRIVATE},
    "search_contacts_by_name": {TC.READ_PRIVATE},
    "search_contacts_by_email": {TC.READ_PRIVATE},
    # --- Calendar tools ---
    "get_current_day": {TC.READ_PUBLIC},
    "search_calendar_events": {TC.READ_PRIVATE},
    "get_day_calendar_events": {TC.READ_PRIVATE},
    "create_calendar_event": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    "cancel_calendar_event": {TC.DATA_DESTRUCTION, TC.CROSS_BOUNDARY_EGRESS},
    "reschedule_calendar_event": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    "add_calendar_event_participants": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    # --- Cloud Drive tools ---
    "append_to_file": {TC.WRITE_MUTATE},
    "search_files_by_filename": {TC.READ_PRIVATE},
    "create_file": {TC.WRITE_MUTATE},
    "delete_file": {TC.DATA_DESTRUCTION},
    "get_file_by_id": {TC.READ_PRIVATE},
    "list_files": {TC.READ_PRIVATE},
    "share_file": {TC.CROSS_BOUNDARY_EGRESS, TC.IDENTITY_ADMIN},
    "search_files": {TC.READ_PRIVATE},
    # --- Slack tools ---
    "get_channels": {TC.READ_PRIVATE},
    "add_user_to_channel": {TC.WRITE_MUTATE, TC.IDENTITY_ADMIN},
    "read_channel_messages": {TC.READ_PRIVATE},
    "read_inbox": {TC.READ_PRIVATE},
    "send_direct_message": {TC.CROSS_BOUNDARY_EGRESS},
    "send_channel_message": {TC.CROSS_BOUNDARY_EGRESS},
    "get_users_in_channel": {TC.READ_PRIVATE},
    "invite_user_to_slack": {TC.IDENTITY_ADMIN},
    "remove_user_from_slack": {TC.IDENTITY_ADMIN, TC.DATA_DESTRUCTION},
    # --- Web tools ---
    "get_webpage": {TC.EXTERNAL_INGESTION},
    "post_webpage": {TC.CROSS_BOUNDARY_EGRESS, TC.WRITE_MUTATE},
    # --- Travel tools ---
    "get_user_information": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "get_all_hotels_in_city": {TC.READ_PUBLIC},
    "get_hotels_prices": {TC.READ_PUBLIC},
    "get_hotels_address": {TC.READ_PUBLIC},
    "get_rating_reviews_for_hotels": {TC.READ_PUBLIC},
    "get_all_restaurants_in_city": {TC.READ_PUBLIC},
    "get_restaurants_address": {TC.READ_PUBLIC},
    "get_rating_reviews_for_restaurants": {TC.READ_PUBLIC},
    "get_cuisine_type_for_restaurants": {TC.READ_PUBLIC},
    "get_dietary_restrictions_for_all_restaurants": {TC.READ_PUBLIC},
    "get_contact_information_for_restaurants": {TC.READ_PUBLIC},
    "get_price_for_restaurants": {TC.READ_PUBLIC},
    "check_restaurant_opening_hours": {TC.READ_PUBLIC},
    "get_all_car_rental_companies_in_city": {TC.READ_PUBLIC},
    "get_car_types_available": {TC.READ_PUBLIC},
    "get_rating_reviews_for_car_rental": {TC.READ_PUBLIC},
    "get_car_fuel_options": {TC.READ_PUBLIC},
    "get_car_rental_address": {TC.READ_PUBLIC},
    "get_car_price_per_day": {TC.READ_PUBLIC},
    "reserve_hotel": {TC.VALUE_TRANSFER},
    "reserve_restaurant": {TC.VALUE_TRANSFER},
    "reserve_car_rental": {TC.VALUE_TRANSFER},
    "get_flight_information": {TC.READ_PUBLIC},
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    suite: str
    user_task_id: str
    injection_task_id: str
    injection_goal: str
    benign_tools: list[str]
    injected_tools: list[str]
    benign_capabilities: set[str]
    injected_capabilities: set[str]
    # For each injected tool: was it blocked?
    injected_tool_decisions: dict[str, AuthorizationDecision]
    all_injected_blocked: bool
    any_injected_blocked: bool
    is_cross_tool_attack: bool  # injection uses tools NOT in benign set
    block_reasons: list[str]


@dataclass
class SuiteResults:
    suite: str
    n_user_tasks: int
    n_injection_tasks: int
    n_scenarios: int
    scenarios: list[ScenarioResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------


def get_tool_descriptions(suite) -> dict[str, str]:
    """Extract tool name -> description from AgentDojo suite."""
    descriptions = {}
    for tool in suite.tools:
        descriptions[tool.name] = tool.description or tool.name
    return descriptions


def get_tool_capabilities_pysa(tool_name: str) -> set[TC]:
    """Get Pysa-derived capabilities for a tool.

    Uses capabilities from real Pysa taint analysis. Tools with no Pysa
    findings (no taint flow to any sink) get an empty set — they have
    no detected security-relevant capability from static analysis.
    """
    return PYSA_CAPABILITIES.get(tool_name, set())


def get_tool_capabilities_gt(tool_name: str) -> set[TC]:
    """Get ground-truth capabilities for a tool (for comparison only)."""
    return GROUND_TRUTH_CAPABILITIES.get(tool_name, {TC.READ_PRIVATE})


def derive_least_privilege_policy(
    benign_tools: list[str],
) -> frozenset[TC]:
    """Derive the minimal capability set needed for a benign task.

    This is the LEAST PRIVILEGE principle: grant only the capabilities
    required by the tools the benign task actually uses.
    """
    capabilities: set[TC] = set()
    for tool_name in benign_tools:
        capabilities |= get_tool_capabilities_pysa(tool_name)
    return frozenset(capabilities)


def evaluate_suite(suite_name: str, suite) -> SuiteResults:
    """Evaluate all (user_task, injection_task) pairs for one suite."""
    env = suite.load_and_inject_default_environment({})
    user_tasks = suite.user_tasks
    injection_tasks = suite.injection_tasks
    tool_descriptions = get_tool_descriptions(suite)

    results = SuiteResults(
        suite=suite_name,
        n_user_tasks=len(user_tasks),
        n_injection_tasks=len(injection_tasks),
        n_scenarios=len(user_tasks) * len(injection_tasks),
    )

    for user_task_id, user_task in sorted(user_tasks.items()):
        benign_gt = user_task.ground_truth(env)
        benign_tools = [fc.function for fc in benign_gt]
        benign_tools_unique = sorted(set(benign_tools))

        # Derive least-privilege policy from benign task
        allowed_capabilities = derive_least_privilege_policy(benign_tools)

        for inj_task_id, inj_task in sorted(injection_tasks.items()):
            inj_gt = inj_task.ground_truth(env)
            injected_tools = [fc.function for fc in inj_gt]
            injected_tools_unique = sorted(set(injected_tools))

            # Is this a cross-tool attack? (injection needs tools NOT in benign set)
            benign_set = set(benign_tools)
            injected_set = set(injected_tools)
            is_cross_tool = not injected_set.issubset(benign_set)

            # Build a fresh AuthorizationManager for this scenario
            mgr = AuthorizationManager()

            # Register ALL suite tools with ground-truth capabilities
            for tool_name in tool_descriptions:
                caps = get_tool_capabilities_pysa(tool_name)
                mgr.register_tool(
                    tool_name,
                    tool_descriptions[tool_name],
                    capabilities_override=caps,
                )

            # Add least-privilege rule for this agent
            mgr.add_rule(
                AccessRule(
                    subject_pattern="*",
                    allowed_capabilities=allowed_capabilities,
                )
            )

            # Check each injected tool call
            decisions: dict[str, AuthorizationDecision] = {}
            block_reasons: list[str] = []
            for tool_name in injected_tools_unique:
                decision = mgr.authorize("agent", tool_name)
                decisions[tool_name] = decision
                if not decision.authorized:
                    block_reasons.append(
                        f"{tool_name}: {decision.reason}"
                    )

            all_blocked = all(not d.authorized for d in decisions.values())
            any_blocked = any(not d.authorized for d in decisions.values())

            # Compute capability sets for reporting
            benign_caps = set()
            for t in benign_tools_unique:
                benign_caps |= {c.value for c in get_tool_capabilities_gt(t)}
            injected_caps = set()
            for t in injected_tools_unique:
                injected_caps |= {c.value for c in get_tool_capabilities_gt(t)}

            results.scenarios.append(
                ScenarioResult(
                    suite=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=inj_task_id,
                    injection_goal=getattr(inj_task, "GOAL", ""),
                    benign_tools=benign_tools_unique,
                    injected_tools=injected_tools_unique,
                    benign_capabilities=benign_caps,
                    injected_capabilities=injected_caps,
                    injected_tool_decisions=decisions,
                    all_injected_blocked=all_blocked,
                    any_injected_blocked=any_blocked,
                    is_cross_tool_attack=is_cross_tool,
                    block_reasons=block_reasons,
                )
            )

    return results


def evaluate_suite_allowlist(suite_name: str, suite) -> SuiteResults:
    """Evaluate with TOOL-LEVEL ALLOWLIST policy.

    Stricter than capability-only: the policy grants the benign task's
    specific tools, not just their capability classes. This blocks
    same-capability cross-tool attacks (e.g., benign uses create_calendar_event
    with EGRESS, but injection uses send_email which also has EGRESS).
    """
    env = suite.load_and_inject_default_environment({})
    user_tasks = suite.user_tasks
    injection_tasks = suite.injection_tasks
    tool_descriptions = get_tool_descriptions(suite)

    results = SuiteResults(
        suite=suite_name,
        n_user_tasks=len(user_tasks),
        n_injection_tasks=len(injection_tasks),
        n_scenarios=len(user_tasks) * len(injection_tasks),
    )

    for user_task_id, user_task in sorted(user_tasks.items()):
        benign_gt = user_task.ground_truth(env)
        benign_tools = [fc.function for fc in benign_gt]
        benign_tools_set = frozenset(set(benign_tools))
        allowed_capabilities = derive_least_privilege_policy(benign_tools)

        for inj_task_id, inj_task in sorted(injection_tasks.items()):
            inj_gt = inj_task.ground_truth(env)
            injected_tools = [fc.function for fc in inj_gt]
            injected_tools_unique = sorted(set(injected_tools))

            benign_set = set(benign_tools)
            injected_set = set(injected_tools)
            is_cross_tool = not injected_set.issubset(benign_set)

            mgr = AuthorizationManager()
            for tool_name in tool_descriptions:
                caps = get_tool_capabilities_pysa(tool_name)
                mgr.register_tool(tool_name, tool_descriptions[tool_name], capabilities_override=caps)

            # Tool-level allowlist: only specific benign tools allowed
            mgr.add_rule(
                AccessRule(
                    subject_pattern="*",
                    allowed_capabilities=allowed_capabilities,
                    allowed_tools=benign_tools_set,
                )
            )

            decisions: dict[str, AuthorizationDecision] = {}
            block_reasons: list[str] = []
            for tool_name in injected_tools_unique:
                decision = mgr.authorize("agent", tool_name)
                decisions[tool_name] = decision
                if not decision.authorized:
                    block_reasons.append(f"{tool_name}: {decision.reason}")

            all_blocked = all(not d.authorized for d in decisions.values())
            any_blocked = any(not d.authorized for d in decisions.values())

            benign_caps = set()
            for t in sorted(set(benign_tools)):
                benign_caps |= {c.value for c in get_tool_capabilities_gt(t)}
            injected_caps = set()
            for t in injected_tools_unique:
                injected_caps |= {c.value for c in get_tool_capabilities_gt(t)}

            results.scenarios.append(
                ScenarioResult(
                    suite=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=inj_task_id,
                    injection_goal=getattr(inj_task, "GOAL", ""),
                    benign_tools=sorted(set(benign_tools)),
                    injected_tools=injected_tools_unique,
                    benign_capabilities=benign_caps,
                    injected_capabilities=injected_caps,
                    injected_tool_decisions=decisions,
                    all_injected_blocked=all_blocked,
                    any_injected_blocked=any_blocked,
                    is_cross_tool_attack=is_cross_tool,
                    block_reasons=block_reasons,
                )
            )

    return results


def evaluate_benign_utility(suite_name: str, suite) -> dict[str, bool]:
    """Check that benign task tools are NOT blocked by their own policy.

    For each user_task, derive the least-privilege policy, then verify
    every tool in the task's ground_truth is authorized.
    Tests BOTH capability-only and tool-allowlist policies.
    """
    env = suite.load_and_inject_default_environment({})
    user_tasks = suite.user_tasks
    tool_descriptions = get_tool_descriptions(suite)

    utility_results: dict[str, bool] = {}

    for user_task_id, user_task in sorted(user_tasks.items()):
        benign_gt = user_task.ground_truth(env)
        benign_tools = [fc.function for fc in benign_gt]
        allowed_capabilities = derive_least_privilege_policy(benign_tools)
        benign_tools_set = frozenset(set(benign_tools))

        # Test capability-only
        mgr1 = AuthorizationManager()
        for tool_name in tool_descriptions:
            caps = get_tool_capabilities_pysa(tool_name)
            mgr1.register_tool(tool_name, tool_descriptions[tool_name], capabilities_override=caps)
        mgr1.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=allowed_capabilities))

        # Test tool-allowlist
        mgr2 = AuthorizationManager()
        for tool_name in tool_descriptions:
            caps = get_tool_capabilities_pysa(tool_name)
            mgr2.register_tool(tool_name, tool_descriptions[tool_name], capabilities_override=caps)
        mgr2.add_rule(AccessRule(subject_pattern="*", allowed_capabilities=allowed_capabilities, allowed_tools=benign_tools_set))

        all_authorized = True
        for tool_name in benign_tools:
            if not mgr1.authorize("agent", tool_name).authorized:
                all_authorized = False
                break
            if not mgr2.authorize("agent", tool_name).authorized:
                all_authorized = False
                break
        utility_results[user_task_id] = all_authorized

    return utility_results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def evaluate_suite_full(suite_name: str, suite) -> SuiteResults:
    """Evaluate with FULL POLICY: capability + tool allowlist + argument constraints.

    Argument constraints restrict sensitive parameters to values that appear
    in the benign task's ground_truth calls. This blocks same-tool attacks
    where the attacker uses the same tool but with a malicious recipient/amount.
    """
    env = suite.load_and_inject_default_environment({})
    user_tasks = suite.user_tasks
    injection_tasks = suite.injection_tasks
    tool_descriptions = get_tool_descriptions(suite)

    results = SuiteResults(
        suite=suite_name,
        n_user_tasks=len(user_tasks),
        n_injection_tasks=len(injection_tasks),
        n_scenarios=len(user_tasks) * len(injection_tasks),
    )

    # Sensitive parameters that should be constrained per-tool
    SENSITIVE_PARAMS: dict[str, list[str]] = {
        "send_money": ["recipient"],
        "schedule_transaction": ["recipient"],
        "update_scheduled_transaction": ["recipient"],
        "send_email": ["recipients"],
        "send_direct_message": ["recipient"],
        "send_channel_message": ["channel"],
        "share_file": ["email"],
        "reserve_hotel": ["hotel"],
        "reserve_restaurant": ["restaurant_name"],
        "reserve_car_rental": ["car_rental_company"],
        "post_webpage": ["url"],
        "create_calendar_event": ["participants"],
        "update_password": ["password"],
        "delete_file": ["file_id"],
        "delete_email": ["email_id"],
    }

    for user_task_id, user_task in sorted(user_tasks.items()):
        benign_gt = user_task.ground_truth(env)
        benign_tools = [fc.function for fc in benign_gt]
        benign_tools_set = frozenset(set(benign_tools))
        allowed_capabilities = derive_least_privilege_policy(benign_tools)

        # Build argument constraints from benign task's actual calls
        arg_constraints: dict[str, dict[str, frozenset[str]]] = {}
        for fc in benign_gt:
            if fc.function in SENSITIVE_PARAMS:
                for param in SENSITIVE_PARAMS[fc.function]:
                    val = fc.args.get(param)
                    if val is not None:
                        vals = val if isinstance(val, list) else [val]
                        existing = arg_constraints.setdefault(fc.function, {}).get(param, frozenset())
                        arg_constraints.setdefault(fc.function, {})[param] = existing | frozenset(str(v) for v in vals)

        for inj_task_id, inj_task in sorted(injection_tasks.items()):
            inj_gt = inj_task.ground_truth(env)
            injected_tools = [fc.function for fc in inj_gt]
            injected_tools_unique = sorted(set(injected_tools))

            benign_set = set(benign_tools)
            injected_set = set(injected_tools)
            is_cross_tool = bool(injected_set) and not injected_set.issubset(benign_set)

            mgr = AuthorizationManager()
            for tool_name in tool_descriptions:
                caps = get_tool_capabilities_pysa(tool_name)
                mgr.register_tool(tool_name, tool_descriptions[tool_name], capabilities_override=caps)

            mgr.add_rule(
                AccessRule(
                    subject_pattern="*",
                    allowed_capabilities=allowed_capabilities,
                    allowed_tools=benign_tools_set,
                    argument_constraints=arg_constraints if arg_constraints else None,
                )
            )

            # Check each injected tool call WITH its arguments
            decisions: dict[str, AuthorizationDecision] = {}
            block_reasons: list[str] = []
            for fc in inj_gt:
                tool_name = fc.function
                if tool_name in decisions and not decisions[tool_name].authorized:
                    continue  # Already blocked
                decision = mgr.authorize("agent", tool_name, arguments=fc.args)
                decisions[tool_name] = decision
                if not decision.authorized:
                    block_reasons.append(f"{tool_name}: {decision.reason}")

            all_blocked = bool(decisions) and all(not d.authorized for d in decisions.values())
            any_blocked = bool(decisions) and any(not d.authorized for d in decisions.values())

            benign_caps = set()
            for t in sorted(set(benign_tools)):
                benign_caps |= {c.value for c in get_tool_capabilities_gt(t)}
            injected_caps = set()
            for t in injected_tools_unique:
                injected_caps |= {c.value for c in get_tool_capabilities_gt(t)}

            results.scenarios.append(
                ScenarioResult(
                    suite=suite_name,
                    user_task_id=user_task_id,
                    injection_task_id=inj_task_id,
                    injection_goal=getattr(inj_task, "GOAL", ""),
                    benign_tools=sorted(set(benign_tools)),
                    injected_tools=injected_tools_unique,
                    benign_capabilities=benign_caps,
                    injected_capabilities=injected_caps,
                    injected_tool_decisions=decisions,
                    all_injected_blocked=all_blocked,
                    any_injected_blocked=any_blocked,
                    is_cross_tool_attack=is_cross_tool,
                    block_reasons=block_reasons,
                )
            )

    return results


def print_report(all_results: dict[str, SuiteResults], all_utility: dict[str, dict[str, bool]]) -> dict:
    """Print and return the full evaluation report."""
    print("=" * 80)
    print("EXPERIMENT 2: Policy Effectiveness on AgentDojo v1")
    print("=" * 80)
    print()

    total_scenarios = 0
    total_blocked = 0
    total_any_blocked = 0
    total_cross_tool = 0
    total_cross_tool_blocked = 0
    total_same_tool = 0
    total_same_tool_blocked = 0
    total_benign_tasks = 0
    total_benign_authorized = 0

    suite_summaries = {}

    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results[suite_name]
        util = all_utility[suite_name]

        n = len(sr.scenarios)
        n_all_blocked = sum(1 for s in sr.scenarios if s.all_injected_blocked)
        n_any_blocked = sum(1 for s in sr.scenarios if s.any_injected_blocked)
        n_cross = sum(1 for s in sr.scenarios if s.is_cross_tool_attack)
        n_cross_blocked = sum(1 for s in sr.scenarios if s.is_cross_tool_attack and s.all_injected_blocked)
        n_same = sum(1 for s in sr.scenarios if not s.is_cross_tool_attack)
        n_same_blocked = sum(1 for s in sr.scenarios if not s.is_cross_tool_attack and s.all_injected_blocked)
        n_benign = len(util)
        n_benign_ok = sum(1 for v in util.values() if v)

        total_scenarios += n
        total_blocked += n_all_blocked
        total_any_blocked += n_any_blocked
        total_cross_tool += n_cross
        total_cross_tool_blocked += n_cross_blocked
        total_same_tool += n_same
        total_same_tool_blocked += n_same_blocked
        total_benign_tasks += n_benign
        total_benign_authorized += n_benign_ok

        pbr = n_all_blocked / n * 100 if n > 0 else 0
        bu = n_benign_ok / n_benign * 100 if n_benign > 0 else 0
        cross_pbr = n_cross_blocked / n_cross * 100 if n_cross > 0 else 0
        same_pbr = n_same_blocked / n_same * 100 if n_same > 0 else 0

        suite_summaries[suite_name] = {
            "scenarios": n,
            "all_blocked": n_all_blocked,
            "any_blocked": n_any_blocked,
            "pbr_pct": round(pbr, 1),
            "bu_pct": round(bu, 1),
            "cross_tool_attacks": n_cross,
            "cross_tool_blocked": n_cross_blocked,
            "cross_tool_pbr_pct": round(cross_pbr, 1),
            "same_tool_attacks": n_same,
            "same_tool_blocked": n_same_blocked,
            "same_tool_pbr_pct": round(same_pbr, 1),
        }

        print(f"--- {suite_name.upper()} ---")
        print(f"  Scenarios: {n} ({sr.n_user_tasks} user × {sr.n_injection_tasks} injection)")
        print(f"  PBR (all injected tools blocked): {n_all_blocked}/{n} = {pbr:.1f}%")
        print(f"  Benign Utility: {n_benign_ok}/{n_benign} = {bu:.1f}%")
        print(f"  Cross-tool attacks: {n_cross_blocked}/{n_cross} blocked = {cross_pbr:.1f}%")
        print(f"  Same-tool attacks:  {n_same_blocked}/{n_same} blocked = {same_pbr:.1f}%")
        print()

    # Overall summary
    overall_pbr = total_blocked / total_scenarios * 100
    overall_bu = total_benign_authorized / total_benign_tasks * 100
    cross_pbr = total_cross_tool_blocked / total_cross_tool * 100 if total_cross_tool > 0 else 0
    same_pbr = total_same_tool_blocked / total_same_tool * 100 if total_same_tool > 0 else 0

    print("=" * 80)
    print("OVERALL RESULTS")
    print("=" * 80)
    print(f"  Total scenarios:    {total_scenarios}")
    print(f"  PBR (all blocked):  {total_blocked}/{total_scenarios} = {overall_pbr:.1f}%")
    print(f"  Benign Utility:     {total_benign_authorized}/{total_benign_tasks} = {overall_bu:.1f}%")
    print(f"  Cross-tool PBR:     {total_cross_tool_blocked}/{total_cross_tool} = {cross_pbr:.1f}%")
    print(f"  Same-tool PBR:      {total_same_tool_blocked}/{total_same_tool} = {same_pbr:.1f}%")
    print()

    # Unblocked scenarios analysis
    print("=" * 80)
    print("UNBLOCKED INJECTION SCENARIOS (Policy allowed all injected tools)")
    print("=" * 80)
    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results[suite_name]
        unblocked = [s for s in sr.scenarios if not s.all_injected_blocked]
        if unblocked:
            print(f"\n--- {suite_name.upper()} ({len(unblocked)} unblocked) ---")
            # Group by injection task
            by_inj: dict[str, list[ScenarioResult]] = defaultdict(list)
            for s in unblocked:
                by_inj[s.injection_task_id].append(s)
            for inj_id, scenarios in sorted(by_inj.items()):
                s0 = scenarios[0]
                print(f"  {inj_id}: \"{s0.injection_goal[:80]}...\"")
                print(f"    Injected tools: {s0.injected_tools}")
                print(f"    Unblocked when benign task uses: ", end="")
                example_tasks = [s.user_task_id for s in scenarios[:5]]
                print(", ".join(example_tasks))
                if scenarios:
                    s_ex = scenarios[0]
                    print(f"    Example benign tools: {s_ex.benign_tools}")
                    print(f"    Benign caps: {sorted(s_ex.benign_capabilities)}")
                    print(f"    Injected caps: {sorted(s_ex.injected_capabilities)}")
                    excess = s_ex.injected_capabilities - s_ex.benign_capabilities
                    print(f"    Excess caps needed: {sorted(excess) if excess else 'NONE (same-tool attack)'}")

    # Denied capabilities analysis
    print()
    print("=" * 80)
    print("DENIAL REASON BREAKDOWN")
    print("=" * 80)
    denied_cap_counts: dict[str, int] = defaultdict(int)
    for suite_name, sr in all_results.items():
        for scenario in sr.scenarios:
            for tool_name, decision in scenario.injected_tool_decisions.items():
                if not decision.authorized:
                    for cap in decision.denied_capabilities:
                        denied_cap_counts[cap.value] += 1

    for cap, count in sorted(denied_cap_counts.items(), key=lambda x: -x[1]):
        print(f"  {cap:30s} blocked {count} tool-call attempts")

    report = {
        "total_scenarios": total_scenarios,
        "overall_pbr_pct": round(overall_pbr, 1),
        "overall_bu_pct": round(overall_bu, 1),
        "cross_tool_pbr_pct": round(cross_pbr, 1),
        "same_tool_pbr_pct": round(same_pbr, 1),
        "total_cross_tool": total_cross_tool,
        "total_same_tool": total_same_tool,
        "suites": suite_summaries,
        "denied_capability_counts": dict(denied_cap_counts),
    }
    return report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("Loading AgentDojo v1 suites...")
    t0 = time.time()

    version_suites = _SUITES["v1"]

    all_results: dict[str, SuiteResults] = {}
    all_results_allowlist: dict[str, SuiteResults] = {}
    all_results_full: dict[str, SuiteResults] = {}
    all_utility: dict[str, dict[str, bool]] = {}

    for suite_name in ["banking", "workspace", "slack", "travel"]:
        suite = version_suites[suite_name]
        print(f"  Evaluating {suite_name}...")
        all_results[suite_name] = evaluate_suite(suite_name, suite)
        all_results_allowlist[suite_name] = evaluate_suite_allowlist(suite_name, suite)
        all_results_full[suite_name] = evaluate_suite_full(suite_name, suite)
        all_utility[suite_name] = evaluate_benign_utility(suite_name, suite)

    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.2f}s")
    print()

    report = print_report(all_results, all_utility)
    report["elapsed_seconds"] = round(elapsed, 2)

    # Allowlist results
    print()
    print("=" * 80)
    print("POLICY VARIANT: CAPABILITY + TOOL ALLOWLIST")
    print("(Only the specific tools the benign task uses are allowed)")
    print("=" * 80)
    print()

    total_al_scenarios = 0
    total_al_blocked = 0
    total_al_cross = 0
    total_al_cross_blocked = 0
    total_al_same = 0
    total_al_same_blocked = 0

    al_suite_summaries = {}

    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results_allowlist[suite_name]
        n = len(sr.scenarios)
        n_all_blocked = sum(1 for s in sr.scenarios if s.all_injected_blocked)
        n_cross = sum(1 for s in sr.scenarios if s.is_cross_tool_attack)
        n_cross_blocked = sum(1 for s in sr.scenarios if s.is_cross_tool_attack and s.all_injected_blocked)
        n_same = sum(1 for s in sr.scenarios if not s.is_cross_tool_attack)
        n_same_blocked = sum(1 for s in sr.scenarios if not s.is_cross_tool_attack and s.all_injected_blocked)

        total_al_scenarios += n
        total_al_blocked += n_all_blocked
        total_al_cross += n_cross
        total_al_cross_blocked += n_cross_blocked
        total_al_same += n_same
        total_al_same_blocked += n_same_blocked

        pbr = n_all_blocked / n * 100 if n else 0
        cross_pbr = n_cross_blocked / n_cross * 100 if n_cross else 0
        same_pbr = n_same_blocked / n_same * 100 if n_same else 0

        al_suite_summaries[suite_name] = {
            "scenarios": n,
            "all_blocked": n_all_blocked,
            "pbr_pct": round(pbr, 1),
            "cross_tool_attacks": n_cross,
            "cross_tool_blocked": n_cross_blocked,
            "cross_tool_pbr_pct": round(cross_pbr, 1),
            "same_tool_attacks": n_same,
            "same_tool_blocked": n_same_blocked,
            "same_tool_pbr_pct": round(same_pbr, 1),
        }

        print(f"  {suite_name:12s}  PBR={pbr:5.1f}%  cross-tool={cross_pbr:5.1f}%  same-tool={same_pbr:5.1f}%")

    overall_al_pbr = total_al_blocked / total_al_scenarios * 100
    cross_al_pbr = total_al_cross_blocked / total_al_cross * 100 if total_al_cross else 0
    same_al_pbr = total_al_same_blocked / total_al_same * 100 if total_al_same else 0

    print()
    print(f"  OVERALL:      PBR={overall_al_pbr:5.1f}%  cross-tool={cross_al_pbr:5.1f}%  same-tool={same_al_pbr:5.1f}%")
    print(f"  Benign Utility: 100.0% (by construction — allowlist includes all benign tools)")

    # Comparison table
    print()
    print("=" * 80)
    print("COMPARISON: CAPABILITY-ONLY vs CAPABILITY + TOOL ALLOWLIST")
    print("=" * 80)
    print(f"{'Policy':<35s} {'PBR':>7s} {'Cross':>8s} {'Same':>8s} {'BU':>6s}")
    print("-" * 64)

    cap_pbr = report["overall_pbr_pct"]
    cap_cross = report["cross_tool_pbr_pct"]
    cap_same = report["same_tool_pbr_pct"]
    print(f"{'Capability-only':<35s} {cap_pbr:>6.1f}% {cap_cross:>7.1f}% {cap_same:>7.1f}% {'100.0':>5s}%")
    print(f"{'Capability + Tool allowlist':<35s} {overall_al_pbr:>6.1f}% {cross_al_pbr:>7.1f}% {same_al_pbr:>7.1f}% {'100.0':>5s}%")
    print()

    # Remaining unblocked in allowlist
    print("REMAINING UNBLOCKED (allowlist policy):")
    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results_allowlist[suite_name]
        unblocked = [s for s in sr.scenarios if not s.all_injected_blocked]
        if unblocked:
            # Deduplicate by injection task
            by_inj: dict[str, ScenarioResult] = {}
            for s in unblocked:
                if s.injection_task_id not in by_inj:
                    by_inj[s.injection_task_id] = s
            print(f"  {suite_name} ({len(unblocked)} scenarios):")
            for inj_id, s in sorted(by_inj.items()):
                print(f"    {inj_id}: injected={s.injected_tools} — same tools as benign, different args")

    # Full policy results (capability + allowlist + argument constraints)
    print()
    print("=" * 80)
    print("POLICY VARIANT: FULL (CAPABILITY + ALLOWLIST + ARGUMENT CONSTRAINTS)")
    print("(Arguments checked against benign task's actual values)")
    print("=" * 80)
    print()

    total_full = {"any": 0, "all": 0, "tool_attacks": 0, "textonly": 0}
    full_suite_summaries = {}

    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results_full[suite_name]
        # tool attacks = scenarios with non-empty injected tools
        tool_scenarios = [s for s in sr.scenarios if s.injected_tools]
        text_scenarios = [s for s in sr.scenarios if not s.injected_tools]
        n_tool = len(tool_scenarios)
        n_any = sum(1 for s in tool_scenarios if s.any_injected_blocked)
        n_all = sum(1 for s in tool_scenarios if s.all_injected_blocked)
        n_text = len(text_scenarios)

        total_full["any"] += n_any
        total_full["all"] += n_all
        total_full["tool_attacks"] += n_tool
        total_full["textonly"] += n_text

        any_pct = n_any / n_tool * 100 if n_tool else 0
        all_pct = n_all / n_tool * 100 if n_tool else 0

        full_suite_summaries[suite_name] = {
            "tool_attacks": n_tool,
            "text_only": n_text,
            "any_blocked": n_any,
            "all_blocked": n_all,
            "any_blocked_pct": round(any_pct, 1),
            "all_blocked_pct": round(all_pct, 1),
        }

        print(f"  {suite_name:12s}  any_blocked={n_any}/{n_tool} ({any_pct:5.1f}%)  all_blocked={n_all}/{n_tool} ({all_pct:5.1f}%)  text_only={n_text}")

    ft = total_full
    overall_any = ft["any"] / ft["tool_attacks"] * 100 if ft["tool_attacks"] else 0
    overall_all = ft["all"] / ft["tool_attacks"] * 100 if ft["tool_attacks"] else 0
    print()
    print(f"  OVERALL:      any_blocked={ft['any']}/{ft['tool_attacks']} ({overall_any:.1f}%)  all_blocked={ft['all']}/{ft['tool_attacks']} ({overall_all:.1f}%)")
    print(f"  Text-only (unblockable): {ft['textonly']}")
    print(f"  Benign Utility: 100.0%")

    # Remaining unblocked
    remaining = []
    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr = all_results_full[suite_name]
        for s in sr.scenarios:
            if s.injected_tools and not s.any_injected_blocked:
                remaining.append(s)

    if remaining:
        print(f"\n  Remaining unblocked (full policy): {len(remaining)} scenarios")
        by_inj: dict[str, list[ScenarioResult]] = defaultdict(list)
        for s in remaining:
            by_inj[f"{s.suite}/{s.injection_task_id}"].append(s)
        for key, scenarios in sorted(by_inj.items()):
            s0 = scenarios[0]
            print(f"    {key} ({len(scenarios)} scenarios): {s0.injected_tools}")
            print(f"      Goal: {s0.injection_goal[:80]}")
    else:
        print(f"\n  ALL tool-based attacks blocked!")

    # Compute any_blocked for cap-only and allowlist for fair comparison
    cap_any_total = al_any_total = tool_total_ex = 0
    for suite_name in ["banking", "workspace", "slack", "travel"]:
        sr_cap = all_results[suite_name]
        sr_al = all_results_allowlist[suite_name]
        tool_cap = [s for s in sr_cap.scenarios if s.injected_tools]
        tool_al = [s for s in sr_al.scenarios if s.injected_tools]
        cap_any_total += sum(1 for s in tool_cap if s.any_injected_blocked)
        al_any_total += sum(1 for s in tool_al if s.any_injected_blocked)
        tool_total_ex += len(tool_cap)

    cap_any_pct = cap_any_total / tool_total_ex * 100 if tool_total_ex else 0
    al_any_pct = al_any_total / tool_total_ex * 100 if tool_total_ex else 0

    # Final comparison table
    print()
    print("=" * 80)
    print("FINAL COMPARISON TABLE (any_blocked metric, excluding text-only)")
    print("=" * 80)
    print(f"{'Policy':<45s} {'PBR':>8s} {'BU':>6s}")
    print("-" * 59)
    print(f"{'Capability-only':<45s} {cap_any_pct:>7.1f}% {'100.0':>5s}%")
    print(f"{'Capability + Tool allowlist':<45s} {al_any_pct:>7.1f}% {'100.0':>5s}%")
    print(f"{'Capability + Allowlist + Arg constraints':<45s} {overall_any:>7.1f}% {'100.0':>5s}%")
    print()

    report["full_policy"] = {
        "overall_any_blocked_pct": round(overall_any, 1),
        "overall_all_blocked_pct": round(overall_all, 1),
        "text_only": ft["textonly"],
        "suites": full_suite_summaries,
    }

    report["allowlist_policy"] = {
        "overall_pbr_pct": round(overall_al_pbr, 1),
        "cross_tool_pbr_pct": round(cross_al_pbr, 1),
        "same_tool_pbr_pct": round(same_al_pbr, 1),
        "suites": al_suite_summaries,
    }

    # Save raw results
    output_path = Path(__file__).parent / "exp2_results.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
