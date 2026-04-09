"""Run open-source AgentDojo built-in defenses under a unified schema.

This script reruns the defenses already implemented in the local AgentDojo
codebase and saves both the original AgentDojo-style metrics and normalized
fields that line up with TrustFnCall's evaluation outputs.

Open-source defenses covered here:
  - None
  - spotlighting_with_delimiting
  - repeat_user_prompt
  - transformers_pi_detector
  - tool_filter

Reported metrics:
  - Utility: benign utility without attack (AgentDojo naming)
  - Utility under attack: benign utility during attacked scenarios
  - Targeted ASR: targeted attack success rate (AgentDojo naming)
  - UAR_no_atk: alias for Utility
  - UA: alias for Utility under attack
  - ASR: alias for Targeted ASR
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

import agentdojo.attacks.baseline_attacks  # noqa: F401,E402
import agentdojo.attacks.dos_attacks  # noqa: F401,E402
import agentdojo.attacks.important_instructions_attacks  # noqa: F401,E402


DEFAULT_DEFENSES = [
    "none",
    "spotlighting_with_delimiting",
    "repeat_user_prompt",
    "transformers_pi_detector",
    "tool_filter",
]


def _avg_bool_dict(results: dict[Any, bool]) -> float:
    if not results:
        return 0.0
    values = list(results.values())
    return sum(1 for v in values if v) / len(values)


def _normalize_defense_name(defense: str) -> str | None:
    return None if defense == "none" else defense


def run_single_defense(
    *,
    model: str,
    defense: str,
    attack_name: str,
    suites: list[str],
    benchmark_version: str,
    logdir: Path,
    force_rerun: bool,
) -> dict[str, Any]:
    suite_rows: dict[str, Any] = {}
    utility_total = 0
    utility_ok = 0
    ua_total = 0
    ua_ok = 0
    asr_total = 0
    asr_ok = 0

    pipeline_defense = _normalize_defense_name(defense)

    for suite_name in suites:
        suite = get_suite(benchmark_version, suite_name)
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=model,
                model_id=None,
                defense=pipeline_defense,
                tool_delimiter="tool",
                system_message_name=None,
                system_message=None,
                tool_output_format=None,
            )
        )
        pipeline.name = f"{model}-{defense}"
        attack = load_attack(attack_name, suite, pipeline)

        benign_results = benchmark_suite_without_injections(
            agent_pipeline=pipeline,
            suite=suite,
            logdir=logdir / defense / "benign",
            force_rerun=force_rerun,
            benchmark_version=benchmark_version,
        )
        attacked_results = benchmark_suite_with_injections(
            agent_pipeline=pipeline,
            suite=suite,
            attack=attack,
            logdir=logdir / defense / "attacked",
            force_rerun=force_rerun,
            benchmark_version=benchmark_version,
        )

        suite_utility_ok = sum(1 for v in benign_results["utility_results"].values() if v)
        suite_utility_total = len(benign_results["utility_results"])
        suite_ua_ok = sum(1 for v in attacked_results["utility_results"].values() if v)
        suite_ua_total = len(attacked_results["utility_results"])
        suite_asr_ok = sum(1 for v in attacked_results["security_results"].values() if v)
        suite_asr_total = len(attacked_results["security_results"])

        utility_ok += suite_utility_ok
        utility_total += suite_utility_total
        ua_ok += suite_ua_ok
        ua_total += suite_ua_total
        asr_ok += suite_asr_ok
        asr_total += suite_asr_total

        suite_rows[suite_name] = {
            "Utility": round(_avg_bool_dict(benign_results["utility_results"]) * 100, 2),
            "Utility_under_attack": round(_avg_bool_dict(attacked_results["utility_results"]) * 100, 2),
            "Targeted_ASR": round(_avg_bool_dict(attacked_results["security_results"]) * 100, 2),
            "counts": {
                "benign_total": suite_utility_total,
                "benign_success": suite_utility_ok,
                "attacked_total": suite_ua_total,
                "attacked_utility_success": suite_ua_ok,
                "attacked_asr_success": suite_asr_ok,
            },
        }

    utility = utility_ok / utility_total * 100 if utility_total else 0.0
    ua = ua_ok / ua_total * 100 if ua_total else 0.0
    asr = asr_ok / asr_total * 100 if asr_total else 0.0

    return {
        "schema_version": "agentdojo_builtin_v1",
        "model": model,
        "defense": defense,
        "attack": attack_name,
        "benchmark_version": benchmark_version,
        "Utility": round(utility, 2),
        "Utility_under_attack": round(ua, 2),
        "Targeted_ASR": round(asr, 2),
        "UAR_no_atk": round(utility, 2),
        "UA": round(ua, 2),
        "ASR": round(asr, 2),
        "TPR": None,
        "FPR": None,
        "suites": suite_rows,
        "counts": {
            "benign_total": utility_total,
            "benign_success": utility_ok,
            "attacked_total": ua_total,
            "attacked_utility_success": ua_ok,
            "attacked_asr_success": asr_ok,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentDojo built-in open-source baselines")
    parser.add_argument("--model", default="gpt-4o-2024-05-13")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--defenses", nargs="+", default=DEFAULT_DEFENSES)
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--logdir", default=None)
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY") and args.model.startswith("gpt-"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    logdir = Path(args.logdir) if args.logdir else ROOT / "data" / "agentdojo_builtin_runs"
    logdir.mkdir(parents=True, exist_ok=True)

    start = time.time()
    rows = []
    for defense in args.defenses:
        print(f"\n=== Built-in baseline: {defense} ===")
        rows.append(
            run_single_defense(
                model=args.model,
                defense=defense,
                attack_name=args.attack,
                suites=list(args.suites),
                benchmark_version=args.benchmark_version,
                logdir=logdir,
                force_rerun=args.force_rerun,
            )
        )

    result = {
        "schema_version": "agentdojo_builtin_collection_v1",
        "model": args.model,
        "attack": args.attack,
        "benchmark_version": args.benchmark_version,
        "suites": list(args.suites),
        "elapsed_sec": round(time.time() - start, 1),
        "results": rows,
    }

    out = ROOT / "data" / f"agentdojo_builtin_baselines_{args.model}_{args.attack}.json"
    out.write_text(json.dumps(result, indent=2, default=str))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
