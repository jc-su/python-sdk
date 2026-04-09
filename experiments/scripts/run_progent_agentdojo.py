"""Run Progent on its patched AgentDojo tree and normalize the results.

Progent's AgentDojo integration depends on suite-specific environment variables
that are read at import time. To keep that behavior correct, this script runs
one suite per subprocess and aggregates the per-suite outputs.

Supported modes:
  - manual policy: SECAGENT_GENERATE=False
  - auto policy:   SECAGENT_GENERATE=True
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
PROGENT_ROOT = ROOT.parent.parent / "progent"
PROGENT_AGENTDOJO_SRC = PROGENT_ROOT / "agentdojo" / "src"


def _suite_out_path(*, model: str, attack: str, mode: str, suite: str) -> Path:
    return ROOT / "data" / f"progent_agentdojo_{mode}_{model}_{attack}__{suite}.json"


def _is_complete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except Exception:
        return False
    return data.get("partial") is False


def _worker_result(
    *,
    suite: str,
    model: str,
    attack: str,
    benchmark_version: str,
    mode: str,
    policy_model: str,
    logdir: str,
    force_rerun: bool,
) -> dict[str, Any]:
    os.environ["SECAGENT_SUITE"] = suite
    os.environ["SECAGENT_GENERATE"] = "True" if mode == "auto" else "False"
    os.environ["SECAGENT_POLICY_MODEL"] = policy_model

    sys.path.insert(0, str(PROGENT_ROOT))
    sys.path.insert(0, str(PROGENT_AGENTDOJO_SRC))

    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig  # type: ignore
    from agentdojo.attacks.attack_registry import load_attack  # type: ignore
    from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections  # type: ignore
    from agentdojo.logging import OutputLogger  # type: ignore
    from agentdojo.task_suite.load_suites import get_suite  # type: ignore

    import agentdojo.attacks.baseline_attacks  # type: ignore # noqa: F401
    import agentdojo.attacks.dos_attacks  # type: ignore # noqa: F401
    import agentdojo.attacks.important_instructions_attacks  # type: ignore # noqa: F401

    suite_obj = get_suite(benchmark_version, suite)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=model,
            model_id=None,
            defense=None,
            tool_delimiter="tool",
            system_message_name=None,
            system_message=None,
            tool_output_format=None,
        )
    )
    pipeline.name = f"{model}-progent-{mode}"
    attack_obj = load_attack(attack, suite_obj, pipeline)

    benign_logdir = Path(logdir) / mode / "benign"
    attacked_logdir = Path(logdir) / mode / "attacked"
    benign_logdir.mkdir(parents=True, exist_ok=True)
    attacked_logdir.mkdir(parents=True, exist_ok=True)

    with OutputLogger(str(benign_logdir)):
        benign = benchmark_suite_without_injections(
            agent_pipeline=pipeline,
            suite=suite_obj,
            logdir=benign_logdir,
            force_rerun=force_rerun,
        )
    with OutputLogger(str(attacked_logdir)):
        attacked = benchmark_suite_with_injections(
            agent_pipeline=pipeline,
            suite=suite_obj,
            attack=attack_obj,
            logdir=attacked_logdir,
            force_rerun=force_rerun,
        )

    utility_values = list(benign["utility_results"].values())
    ua_values = list(attacked["utility_results"].values())
    asr_values = list(attacked["security_results"].values())
    return {
        "suite": suite,
        "Utility": round(sum(1 for v in utility_values if v) / len(utility_values) * 100, 2) if utility_values else 0.0,
        "Utility_under_attack": round(sum(1 for v in ua_values if v) / len(ua_values) * 100, 2) if ua_values else 0.0,
        "Targeted_ASR": round(sum(1 for v in asr_values if v) / len(asr_values) * 100, 2) if asr_values else 0.0,
        "counts": {
            "benign_total": len(utility_values),
            "benign_success": sum(1 for v in utility_values if v),
            "attacked_total": len(ua_values),
            "attacked_utility_success": sum(1 for v in ua_values if v),
            "attacked_asr_success": sum(1 for v in asr_values if v),
        },
    }


def _run_worker_subprocess(args: argparse.Namespace, suite: str) -> dict[str, Any]:
    out_path = _suite_out_path(model=args.model, attack=args.attack, mode=args.mode, suite=suite)
    if not args.force_rerun and _is_complete(out_path):
        return json.loads(out_path.read_text())

    cmd = [
        sys.executable,
        str(Path(__file__)),
        "--worker",
        "--suite",
        suite,
        "--model",
        args.model,
        "--attack",
        args.attack,
        "--benchmark-version",
        args.benchmark_version,
        "--mode",
        args.mode,
        "--policy-model",
        args.policy_model,
        "--logdir",
        str(args.logdir),
    ]
    if args.force_rerun:
        cmd.append("--force-rerun")
    child_env = os.environ.copy()
    proc = subprocess.run(cmd, capture_output=True, text=True, env=child_env)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Progent worker failed for suite={suite}\nSTDOUT:\n{proc.stdout[-500:]}\nSTDERR:\n{proc.stderr[-500:]}"
        )
    # Worker stdout may contain secagent debug lines before the JSON.
    # The JSON payload is always the last line.
    stdout_lines = proc.stdout.strip().splitlines()
    for line in reversed(stdout_lines):
        line = line.strip()
        if line.startswith("{"):
            payload = json.loads(line)
            break
    else:
        raise RuntimeError(f"No JSON found in worker stdout for suite={suite}\nSTDOUT tail:\n{proc.stdout[-500:]}")
    out_path.write_text(json.dumps(payload, indent=2))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Progent on AgentDojo and normalize the outputs")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--suite", default=None)
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--mode", choices=["manual", "auto"], default="manual")
    parser.add_argument("--policy-model", default="gpt-4o-2024-08-06")
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--logdir", default=str(ROOT / "data" / "progent_agentdojo_runs"))
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY not set")

    if args.worker:
        if args.suite is None:
            print("{}", end="")
            sys.exit(1)
        payload = _worker_result(
            suite=args.suite,
            model=args.model,
            attack=args.attack,
            benchmark_version=args.benchmark_version,
            mode=args.mode,
            policy_model=args.policy_model,
            logdir=args.logdir,
            force_rerun=args.force_rerun,
        )
        payload["partial"] = False
        print(json.dumps(payload))
        return

    start = time.time()
    suite_rows = []
    for suite in args.suites:
        print(f"\n=== Progent {args.mode}: {suite} ===")
        suite_rows.append(_run_worker_subprocess(args, suite))

    utility_ok = sum(row["counts"]["benign_success"] for row in suite_rows)
    utility_total = sum(row["counts"]["benign_total"] for row in suite_rows)
    ua_ok = sum(row["counts"]["attacked_utility_success"] for row in suite_rows)
    ua_total = sum(row["counts"]["attacked_total"] for row in suite_rows)
    asr_ok = sum(row["counts"]["attacked_asr_success"] for row in suite_rows)
    asr_total = sum(row["counts"]["attacked_total"] for row in suite_rows)

    result = {
        "schema_version": "progent_agentdojo_v1",
        "model": args.model,
        "attack": args.attack,
        "mode": args.mode,
        "policy_model": args.policy_model,
        "elapsed_sec": round(time.time() - start, 1),
        "Utility": round(utility_ok / utility_total * 100, 2) if utility_total else 0.0,
        "Utility_under_attack": round(ua_ok / ua_total * 100, 2) if ua_total else 0.0,
        "Targeted_ASR": round(asr_ok / asr_total * 100, 2) if asr_total else 0.0,
        "UAR_no_atk": round(utility_ok / utility_total * 100, 2) if utility_total else 0.0,
        "UA": round(ua_ok / ua_total * 100, 2) if ua_total else 0.0,
        "ASR": round(asr_ok / asr_total * 100, 2) if asr_total else 0.0,
        "TPR": None,
        "FPR": None,
        "suites": {row["suite"]: row for row in suite_rows},
    }

    out = ROOT / "data" / f"progent_agentdojo_{args.mode}_{args.model}_{args.attack}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
