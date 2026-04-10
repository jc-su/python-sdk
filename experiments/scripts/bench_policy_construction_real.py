"""Measure real policy-construction overhead for TrustFnCall.

This separates policy construction from online enforcement:
  - Pysa offline analysis time on AgentDojo tools
  - clean preflight trace collection time (benign-only runs)
  - policy materialization time from cached real traces

Outputs:
  data/policy_construction_real_<model>.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from run_agentdojo_v2 import _SUITES, build_policy_from_trace, build_manual_policy, build_policy  # noqa: E402


DATA = ROOT / "data"
PYSA_RUNNER = ROOT / "pysa_agentdojo_runner.py"
PYSA_RESULTS = ROOT / "pysa_agentdojo_results.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _round(value: float | None, digits: int = 3) -> float | None:
    if value is None:
        return None
    return round(value, digits)


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct)))
    return ordered[idx]


def _summary(values: list[float], digits: int = 3) -> dict[str, Any]:
    if not values:
        return {"n_samples": 0}
    return {
        "n_samples": len(values),
        "mean": _round(statistics.mean(values), digits),
        "std": _round(statistics.stdev(values), digits) if len(values) > 1 else 0.0,
        "p50": _round(_percentile(values, 0.50), digits),
        "p95": _round(_percentile(values, 0.95), digits),
        "p99": _round(_percentile(values, 0.99), digits),
        "min": _round(min(values), digits),
        "max": _round(max(values), digits),
    }


def measure_pysa() -> dict[str, Any]:
    original_results = PYSA_RESULTS.read_text() if PYSA_RESULTS.exists() else None
    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(PYSA_RUNNER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        elapsed = time.time() - start
        lines = proc.stdout.strip().splitlines()
        tool_lines = [line for line in lines if line.startswith("  ") and "→" in line]
        return {
            "elapsed_sec": _round(elapsed, 3),
            "n_tool_rows": len(tool_lines),
            "stdout_tail": lines[-10:],
        }
    finally:
        if original_results is not None:
            PYSA_RESULTS.write_text(original_results)


def _extract_trace_events(path: Path) -> tuple[str, str, list[dict[str, Any]]]:
    payload = _load_json(path)
    suites = payload.get("suites") or []
    tasks = payload.get("user_tasks") or []
    if len(suites) != 1 or len(tasks) != 1:
        raise ValueError(f"Expected single suite/task in {path}")
    overall = payload["results"][0]["overall"]
    benign = overall.get("benign_no_attack") or []
    events = benign[0]["trace"]["events"] if benign else []
    return str(suites[0]), str(tasks[0]), list(events)


def measure_policy_materialization(model: str, attack: str) -> dict[str, Any]:
    env_cache = {
        suite_name: _SUITES["v1"][suite_name].load_and_inject_default_environment({})
        for suite_name in _SUITES["v1"]
    }
    trace_times_ms: list[float] = []
    suite_times_ms: list[float] = []
    manual_times_ms: list[float] = []

    baseline_files = sorted(DATA.glob(f"agentdojo_matrix_v2_{model}_{attack}__baseline__*.json"))
    seen_suite_manual: set[str] = set()
    seen_suite_policy: set[tuple[str, str]] = set()

    for path in baseline_files:
        suite_name, user_task_id, events = _extract_trace_events(path)
        suite = _SUITES["v1"][suite_name]
        env = env_cache[suite_name]
        user_task = suite.user_tasks[user_task_id]

        t0 = time.perf_counter_ns()
        build_policy_from_trace(suite, env, events, True, "trace")
        t1 = time.perf_counter_ns()
        trace_times_ms.append((t1 - t0) / 1e6)

        suite_key = (suite_name, "suite")
        if suite_key not in seen_suite_policy:
            seen_suite_policy.add(suite_key)
            t2 = time.perf_counter_ns()
            build_policy(suite, user_task, env, True, "suite")
            t3 = time.perf_counter_ns()
            suite_times_ms.append((t3 - t2) / 1e6)

        if suite_name not in seen_suite_manual:
            seen_suite_manual.add(suite_name)
            t4 = time.perf_counter_ns()
            build_manual_policy(suite, env)
            t5 = time.perf_counter_ns()
            manual_times_ms.append((t5 - t4) / 1e6)

    return {
        "trace_policy_ms": _summary(trace_times_ms),
        "suite_policy_ms": _summary(suite_times_ms),
        "manual_policy_ms": _summary(manual_times_ms),
        "n_baseline_task_files": len(baseline_files),
    }


def measure_preflight_from_cached_baseline(model: str, attack: str) -> dict[str, Any]:
    files = sorted(DATA.glob(f"agentdojo_matrix_v2_{model}_{attack}__baseline__*.json"))
    per_scenario_elapsed = []
    by_suite: dict[str, list[float]] = {}
    for path in files:
        payload = _load_json(path)
        suites = payload.get("suites") or []
        tasks = payload.get("user_tasks") or []
        if len(suites) != 1 or len(tasks) != 1:
            continue
        elapsed = float(payload["elapsed_sec"])
        overall = payload["results"][0]["overall"]
        counts = overall.get("counts", {})
        scenario_total = int(counts.get("attacked_scenarios", 0)) + int(counts.get("benign_scenarios", 0))
        if scenario_total <= 0:
            continue
        per_scenario = elapsed / scenario_total
        suite_name = str(suites[0])
        by_suite.setdefault(suite_name, []).append(per_scenario)
        per_scenario_elapsed.append(per_scenario)

    return {
        "note": "This uses real baseline task files and normalizes by scenario count to estimate the cost of one clean preflight scenario. Dedicated benign-only reruns can replace it.",
        "per_scenario_elapsed_sec_proxy": _summary(per_scenario_elapsed),
        "by_suite_elapsed_sec_proxy": {
            suite: _summary(values) for suite, values in by_suite.items()
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure real policy-construction overhead")
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--skip-pysa", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    result: dict[str, Any] = {
        "schema_version": "policy_construction_real_v1",
        "model": args.model,
        "attack": args.attack,
    }

    existing = _load_json(Path(args.output)) if args.output and Path(args.output).exists() else None
    if existing is None:
        default_existing = DATA / f"policy_construction_real_{args.model}.json"
        if default_existing.exists():
            existing = _load_json(default_existing)

    if not args.skip_pysa:
        result["pysa_offline"] = measure_pysa()
    elif existing and "pysa_offline" in existing:
        result["pysa_offline"] = existing["pysa_offline"]
    result["policy_materialization"] = measure_policy_materialization(args.model, args.attack)
    result["preflight_trace_proxy"] = measure_preflight_from_cached_baseline(args.model, args.attack)

    out = Path(args.output) if args.output else DATA / f"policy_construction_real_{args.model}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
