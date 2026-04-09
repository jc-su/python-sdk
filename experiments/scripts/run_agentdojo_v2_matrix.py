"""Run a multi-attack TrustFnCall / baseline matrix on AgentDojo.

This wraps `run_agentdojo_v2.py` to:
  - run multiple attack types under a consistent setup
  - compute per-attack metrics
  - compute micro-averaged metrics across all attacked scenarios
  - compute PromptArmor-style combined-goal ASR across attacks

It is useful when we want one JSON file that summarizes multiple policy scopes
without hand-merging multiple single-attack outputs.

Important interpretation:
  - `trustfncall_task*` are oracle upper bounds built from per-task ground truth.
  - `trustfncall_suite*` are the fairer role-level comparisons.
  - `trustfncall_trace*` derive a per-task policy from a clean preflight run of
    the same prompt, then enforce that policy on clean+attacked execution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from run_agentdojo_v2 import compute_metrics, run_attacked, run_benign_no_attack  # noqa: E402


CONFIGS = [
    ("baseline", False, False, "task"),
    ("trustfncall_task", True, False, "task"),
    ("trustfncall_task_args", True, True, "task"),
    ("trustfncall_suite", True, False, "suite"),
    ("trustfncall_suite_args", True, True, "suite"),
    ("trustfncall_trace", True, False, "trace"),
    ("trustfncall_trace_args", True, True, "trace"),
    ("trustfncall_trace_hybrid", True, False, "trace_hybrid"),
    ("trustfncall_trace_hybrid_args", True, True, "trace_hybrid"),
]


def _slug(parts: list[str]) -> str:
    return "__".join(part.replace("/", "_") for part in parts if part)


def _combined_goal_asr(attacked_by_attack: dict[str, list[dict[str, Any]]]) -> float:
    grouped: dict[tuple[str, str, str], bool] = {}
    for attack_name, cases in attacked_by_attack.items():
        for case in cases:
            key = (case["suite"], case["user_task"], case["injection_task"])
            grouped[key] = grouped.get(key, False) or case["attack_succeeded"]
    if not grouped:
        return 0.0
    return sum(1 for ok in grouped.values() if ok) / len(grouped) * 100.0


def _write_checkpoint(
    *,
    out_path: Path,
    model: str,
    attacks: list[str],
    suites: list[str],
    user_tasks: list[str] | None,
    start: float,
    results: list[dict[str, Any]],
) -> None:
    payload = {
        "schema_version": "agentdojo_matrix_v1",
        "model": model,
        "attacks": list(attacks),
        "suites": list(suites),
        "user_tasks": list(user_tasks) if user_tasks else None,
        "elapsed_sec": round(time.time() - start, 1),
        "partial": True,
        "results": results,
    }
    out_path.write_text(json.dumps(payload, indent=2, default=str))


def _run_config(
    *,
    config_name: str,
    model: str,
    attacks: list[str],
    suites: list[str],
    user_tasks: list[str] | None,
    use_defense: bool,
    use_args: bool,
    policy_scope: str,
    logdir: Path,
) -> dict[str, Any]:
    preflight_trace_map: dict[tuple[str, str], Sequence[dict[str, Any]]] | None = None
    if use_defense and policy_scope in {"trace", "trace_hybrid"}:
        planning = run_benign_no_attack(
            model=model,
            suites_to_run=suites,
            use_defense=False,
            use_args=False,
            policy_scope="task",
            user_task_ids=user_tasks,
            preflight_trace_map=None,
            logdir=logdir / config_name / "preflight",
        )
        preflight_trace_map = {(row["suite"], row["user_task"]): row["trace"]["events"] for row in planning}

    benign = run_benign_no_attack(
        model=model,
        suites_to_run=suites,
        use_defense=use_defense,
        use_args=use_args,
        policy_scope=policy_scope,
        user_task_ids=user_tasks,
        preflight_trace_map=preflight_trace_map,
        logdir=logdir / config_name / "benign",
    )

    per_attack: dict[str, Any] = {}
    attacked_by_attack: dict[str, list[dict[str, Any]]] = {}
    attacked_all: list[dict[str, Any]] = []
    for attack_name in attacks:
        attacked = run_attacked(
            model=model,
            attack_name=attack_name,
            suites_to_run=suites,
            use_defense=use_defense,
            use_args=use_args,
            policy_scope=policy_scope,
            user_task_ids=user_tasks,
            preflight_trace_map=preflight_trace_map,
            logdir=logdir / config_name / "attacked" / attack_name,
        )
        attacked_by_attack[attack_name] = attacked
        attacked_all.extend(attacked)
        per_attack[attack_name] = compute_metrics(
            attacked=attacked,
            benign=benign,
            label=f"{config_name} {model} {attack_name}",
        )

    overall = compute_metrics(
        attacked=attacked_all,
        benign=benign,
        label=f"{config_name} {model} micro_avg",
    )
    overall["combined_goal_ASR"] = round(_combined_goal_asr(attacked_by_attack), 1)
    overall["attack_types"] = list(attacks)

    return {
        "config": config_name,
        "use_defense": use_defense,
        "use_args": use_args,
        "policy_scope": policy_scope,
        "per_attack": per_attack,
        "overall": overall,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentDojo v2 multi-attack matrix")
    parser.add_argument("--model", default="gpt-4o-2024-05-13")
    parser.add_argument("--attacks", nargs="+", default=["important_instructions"])
    parser.add_argument("--configs", nargs="+", default=[c[0] for c in CONFIGS])
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--user-tasks", nargs="+", default=None)
    parser.add_argument("--logdir", default=None)
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    selected = {
        name: (use_defense, use_args, policy_scope)
        for name, use_defense, use_args, policy_scope in CONFIGS
        if name in args.configs
    }
    if not selected:
        print("ERROR: no valid configs selected.")
        sys.exit(1)

    logdir = Path(args.logdir) if args.logdir else ROOT / "data" / "agentdojo_matrix_runs"
    logdir.mkdir(parents=True, exist_ok=True)

    start = time.time()
    results = []
    attack_tag = "-".join(args.attacks)
    suites_tag = _slug(list(args.suites))
    configs_tag = _slug(list(args.configs))
    task_tag = _slug(list(args.user_tasks)) if args.user_tasks else "all_tasks"
    out = ROOT / "data" / f"agentdojo_matrix_v2_{args.model}_{attack_tag}__{configs_tag}__{suites_tag}__{task_tag}.json"
    for config_name in args.configs:
        if config_name not in selected:
            continue
        use_defense, use_args, policy_scope = selected[config_name]
        print(f"\n===== {config_name} =====")
        results.append(
            _run_config(
                config_name=config_name,
                model=args.model,
                attacks=list(args.attacks),
                suites=list(args.suites),
                user_tasks=list(args.user_tasks) if args.user_tasks else None,
                use_defense=use_defense,
                use_args=use_args,
                policy_scope=policy_scope,
                logdir=logdir,
            )
        )
        _write_checkpoint(
            out_path=out,
            model=args.model,
            attacks=list(args.attacks),
            suites=list(args.suites),
            user_tasks=list(args.user_tasks) if args.user_tasks else None,
            start=start,
            results=results,
        )

    payload = {
        "schema_version": "agentdojo_matrix_v1",
        "model": args.model,
        "attacks": list(args.attacks),
        "suites": list(args.suites),
        "user_tasks": list(args.user_tasks) if args.user_tasks else None,
        "elapsed_sec": round(time.time() - start, 1),
        "partial": False,
        "results": results,
    }

    out.write_text(json.dumps(payload, indent=2, default=str))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
