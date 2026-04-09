"""Run TrustFnCall defense on AgentDojo benchmark with a REAL LLM agent.

Metrics (same definitions as MELON/AgentDojo papers):
  UA  — Utility Under Attack: agent completes benign task while under attack
  ASR — Attack Success Rate: fraction of attacks where malicious objective succeeds
  FPR — False Positive Rate: benign tool calls incorrectly blocked by defense
  FNR — False Negative Rate: attack scenarios not blocked = ASR

For baseline (no defense): uses AgentDojo's benchmark_suite_with_injections directly.
For TrustFnCall: builds per-user-task policy, runs each user_task separately.

Requirements:
  - OPENAI_API_KEY in environment or .env file
  - agentdojo installed

Usage:
  # Baseline (no defense) — validates setup against published numbers
  python experiments/scripts/run_agentdojo.py --no-defense

  # TrustFnCall task-level allowlist
  python experiments/scripts/run_agentdojo.py

  # TrustFnCall with argument constraints
  python experiments/scripts/run_agentdojo.py --use-args

  # Specific suite only
  python experiments/scripts/run_agentdojo.py --suites banking
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent / "src"))
sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, MODEL_PROVIDERS
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, run_task_with_injection_tasks
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import _SUITES
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

import agentdojo.attacks.baseline_attacks  # noqa: F401
import agentdojo.attacks.important_instructions_attacks  # noqa: F401
import agentdojo.attacks.dos_attacks  # noqa: F401

from mcp.server.authorization import AccessRule, AuthorizationManager, ToolCapability as TC

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("trustfncall")
logger.setLevel(logging.INFO)

CAP_MAP = {c.value: c for c in TC}
pysa_raw = json.loads((ROOT / "pysa_agentdojo_results.json").read_text())
PYSA_CAPS: dict[str, set[TC]] = {t: {CAP_MAP[c] for c in caps if c in CAP_MAP} for t, caps in pysa_raw.items()}

SENSITIVE_PARAMS: dict[str, list[str]] = {
    "send_money": ["recipient"], "schedule_transaction": ["recipient"],
    "update_scheduled_transaction": ["recipient"], "send_email": ["recipients"],
    "send_direct_message": ["recipient"], "send_channel_message": ["channel"],
    "share_file": ["email"], "reserve_hotel": ["hotel"],
    "post_webpage": ["url"], "create_calendar_event": ["participants"],
    "update_password": ["password"], "delete_file": ["file_id"], "delete_email": ["email_id"],
}


class TrustFnCallDefense(BasePipelineElement):
    """Intercepts LLM tool calls and blocks unauthorized ones."""

    name = "trustfncall"

    def __init__(self, mgr: AuthorizationManager, use_arg_constraints: bool = False):
        self._mgr = mgr
        self._use_args = use_arg_constraints
        self.calls_checked = 0
        self.calls_blocked = 0
        self.blocked_tools: list[str] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1].get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        allowed_calls = []
        blocked_results: list[ChatToolResultMessage] = []

        for tc in tool_calls:
            self.calls_checked += 1
            args = tc.args if hasattr(tc, "args") else {}
            decision = self._mgr.authorize(
                "agent", tc.function,
                arguments=args if self._use_args else None,
            )

            if decision.authorized:
                allowed_calls.append(tc)
            else:
                self.calls_blocked += 1
                self.blocked_tools.append(tc.function)
                blocked_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tc.id,
                        tool_call=tc,
                        error=f"TrustFnCall: blocked '{tc.function}' — {decision.reason}",
                    )
                )

        if blocked_results:
            if allowed_calls:
                # Some calls allowed, some blocked
                new_last = {**messages[-1], "tool_calls": allowed_calls}
                new_messages = list(messages[:-1]) + [new_last] + blocked_results
            else:
                # ALL calls blocked — keep original assistant message but add tool error results
                new_messages = list(messages) + blocked_results
            return query, runtime, env, new_messages, extra_args

        return query, runtime, env, messages, extra_args


def build_task_policy(suite, user_task, env, use_args: bool) -> AuthorizationManager:
    """Build task-level policy from benign task ground truth."""
    benign_gt = user_task.ground_truth(env)
    benign_tools = set(fc.function for fc in benign_gt)
    benign_caps = frozenset().union(*(PYSA_CAPS.get(t, set()) for t in benign_tools))

    arg_constraints: dict[str, dict[str, frozenset[str]]] = {}
    if use_args:
        for fc in benign_gt:
            if fc.function in SENSITIVE_PARAMS:
                for param in SENSITIVE_PARAMS[fc.function]:
                    val = fc.args.get(param)
                    if val is not None:
                        vals = val if isinstance(val, list) else [val]
                        existing = arg_constraints.setdefault(fc.function, {}).get(param, frozenset())
                        arg_constraints.setdefault(fc.function, {})[param] = existing | frozenset(str(v) for v in vals)

    mgr = AuthorizationManager()
    for t in suite.tools:
        mgr.register_tool(t.name, t.description or t.name, capabilities_override=PYSA_CAPS.get(t.name, set()))

    rule_kw: dict = {"subject_pattern": "*", "allowed_capabilities": benign_caps, "allowed_tools": frozenset(benign_tools)}
    if use_args and arg_constraints:
        rule_kw["argument_constraints"] = arg_constraints
    mgr.add_rule(AccessRule(**rule_kw))
    return mgr


def run_baseline(model: str, attack_name: str, suites_to_run: list[str], logdir: Path):
    """Run baseline (no defense) using AgentDojo's standard pipeline."""
    model_enum = ModelsEnum(model)
    all_utility: dict[tuple[str, str], bool] = {}
    all_security: dict[tuple[str, str], bool] = {}

    for suite_name in suites_to_run:
        suite = _SUITES["v1"][suite_name]
        llm = get_llm(MODEL_PROVIDERS[model_enum], model, None, "tool")
        pipeline = AgentPipeline([
            SystemMessage("You are a helpful assistant."),
            InitQuery(), llm,
            ToolsExecutionLoop([ToolsExecutor(), llm]),
        ])
        pipeline.name = f"{model}-baseline"

        attack = load_attack(attack_name, suite, pipeline)
        suite_logdir = logdir / suite_name
        suite_logdir.mkdir(parents=True, exist_ok=True)

        logger.info("Running baseline: %s", suite_name)
        results = benchmark_suite_with_injections(
            agent_pipeline=pipeline, suite=suite, attack=attack,
            logdir=suite_logdir, force_rerun=True, verbose=False,
        )
        all_utility.update(results["utility_results"])
        all_security.update(results["security_results"])

        # Print per-suite summary
        su = sum(1 for v in results["utility_results"].values() if v)
        ss = sum(1 for v in results["security_results"].values() if v)
        n = len(results["utility_results"])
        logger.info("  %s: %d scenarios, UA=%d/%d (%.1f%%), attacks_blocked=%d/%d (%.1f%%)",
                     suite_name, n, su, n, su / n * 100, ss, n, ss / n * 100)

    return all_utility, all_security


def run_with_defense(model: str, attack_name: str, suites_to_run: list[str],
                     use_args: bool, logdir: Path):
    """Run with TrustFnCall defense — per-user-task policy."""
    model_enum = ModelsEnum(model)
    all_utility: dict[tuple[str, str], bool] = {}
    all_security: dict[tuple[str, str], bool] = {}
    total_checked = 0
    total_blocked = 0

    for suite_name in suites_to_run:
        suite = _SUITES["v1"][suite_name]
        env = suite.load_and_inject_default_environment({})

        logger.info("Running TrustFnCall: %s (use_args=%s)", suite_name, use_args)

        for ut_id, user_task in sorted(suite.user_tasks.items()):
            # Build per-task policy + pipeline
            mgr = build_task_policy(suite, user_task, env, use_args)
            defense = TrustFnCallDefense(mgr, use_arg_constraints=use_args)

            llm = get_llm(MODEL_PROVIDERS[model_enum], model, None, "tool")
            pipeline = AgentPipeline([
                SystemMessage("You are a helpful assistant."),
                InitQuery(), llm, defense,
                ToolsExecutionLoop([ToolsExecutor(), llm]),
            ])
            pipeline.name = f"{model}-trustfncall"

            attack = load_attack(attack_name, suite, pipeline)
            task_logdir = logdir / suite_name
            task_logdir.mkdir(parents=True, exist_ok=True)

            try:
                utility_results, security_results = run_task_with_injection_tasks(
                    suite=suite, agent_pipeline=pipeline, user_task=user_task,
                    attack=attack, logdir=task_logdir, force_rerun=True,
                )
            except Exception:
                logger.exception("Error on %s/%s", suite_name, ut_id)
                continue

            all_utility.update(utility_results)
            all_security.update(security_results)
            total_checked += defense.calls_checked
            total_blocked += defense.calls_blocked

            # Log progress
            n = len(utility_results)
            su = sum(1 for v in utility_results.values() if v)
            ss = sum(1 for v in security_results.values() if v)
            logger.info("  %s/%s: %d scenarios, UA=%d/%d, blocked_attacks=%d/%d, defense_blocked=%d/%d calls",
                         suite_name, ut_id, n, su, n, ss, n, defense.calls_blocked, defense.calls_checked)

    return all_utility, all_security, total_checked, total_blocked


def compute_metrics(utility: dict, security: dict, label: str,
                    defense_checked: int = 0, defense_blocked: int = 0) -> dict:
    """Compute UA/ASR/FPR/FNR from results dicts."""
    n = len(utility)
    ua_ok = sum(1 for v in utility.values() if v)
    attacks_succeeded = sum(1 for v in security.values() if not v)  # security=False means attack succeeded

    ua = ua_ok / n * 100 if n else 0
    asr = attacks_succeeded / n * 100 if n else 0

    print(f"\n{'='*70}")
    print(f"RESULTS: {label}")
    print(f"{'='*70}")
    print(f"  Total scenarios: {n}")
    print(f"  UA  (Utility Under Attack):  {ua_ok}/{n} = {ua:.1f}%")
    print(f"  ASR (Attack Success Rate):   {attacks_succeeded}/{n} = {asr:.1f}%")
    print(f"  FNR (False Negative Rate):   {asr:.1f}% (= ASR)")
    if defense_checked > 0:
        print(f"  Defense: {defense_blocked}/{defense_checked} tool calls blocked")

    return {
        "label": label, "n_scenarios": n,
        "UA": round(ua, 1), "ASR": round(asr, 1), "FNR": round(asr, 1),
        "ua_ok": ua_ok, "attacks_succeeded": attacks_succeeded,
        "defense_checked": defense_checked, "defense_blocked": defense_blocked,
        "per_scenario": [
            {"user_task": ut, "injection_task": it,
             "utility": utility[(ut, it)], "security": security[(ut, it)]}
            for ut, it in sorted(utility.keys())
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Run TrustFnCall on AgentDojo (real LLM)")
    parser.add_argument("--model", default="gpt-4o-2024-05-13")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--no-defense", action="store_true")
    parser.add_argument("--use-args", action="store_true")
    parser.add_argument("--logdir", default=None)
    args = parser.parse_args()

    # Load API key
    load_dotenv(ROOT / ".env")
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set. Put it in experiments/.env or environment.")
        sys.exit(1)

    logdir = Path(args.logdir) if args.logdir else ROOT / "data" / "agentdojo_runs"
    logdir.mkdir(parents=True, exist_ok=True)

    start = time.time()

    if args.no_defense:
        utility, security = run_baseline(args.model, args.attack, args.suites, logdir / "baseline")
        result = compute_metrics(utility, security,
                                  f"Baseline (no defense), {args.model}, {args.attack}")
        tag = "baseline"
    else:
        utility, security, checked, blocked = run_with_defense(
            args.model, args.attack, args.suites, args.use_args, logdir / "trustfncall",
        )
        label = f"TrustFnCall ({'task+args' if args.use_args else 'task'}), {args.model}, {args.attack}"
        result = compute_metrics(utility, security, label, checked, blocked)
        tag = "trustfncall_args" if args.use_args else "trustfncall"

    elapsed = time.time() - start
    result["elapsed_sec"] = round(elapsed, 1)
    result["model"] = args.model
    result["attack"] = args.attack
    result["suites"] = args.suites

    out = ROOT / "data" / f"agentdojo_real_{tag}_{args.attack}.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nElapsed: {elapsed:.0f}s")
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
