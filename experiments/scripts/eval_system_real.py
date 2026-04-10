"""Fair real-data system evaluation for TrustFnCall and runnable baselines.

This script keeps the systems story grounded in real experiment artifacts:

1. Online enforcement overhead:
   Benchmarks `AuthorizationManager.authorize()` on real AgentDojo-derived
   policies and real traced tool calls, instead of synthetic toy examples.

2. End-to-end overhead:
   Summarizes wall-clock seconds per scenario from real benchmark outputs for
   TrustFnCall, AgentDojo built-ins, MELON, and Progent when those results are
   present locally. Coverage mismatches are surfaced explicitly.

By default this script is offline-first and only reads local files. Use
`--run-missing` to invoke the existing runners for missing baseline outputs;
those reruns may require an LLM API key depending on the chosen method.

Outputs:
  data/system_eval_real_<model>_<attack>.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from run_agentdojo_v2 import (  # noqa: E402
    _SUITES,
    build_manual_policy,
    build_policy,
    build_policy_from_trace,
)


DATA = ROOT / "data"
BUILTIN_SCRIPT = SCRIPT_DIR / "run_agentdojo_builtin_baselines.py"
MELON_SCRIPT = SCRIPT_DIR / "run_melon_agentdojo.py"
PROGENT_SCRIPT = SCRIPT_DIR / "run_progent_agentdojo.py"

DEFAULT_SUITES = ["banking", "workspace", "slack", "travel"]
DEFAULT_TRUSTFNCALL_CONFIGS = [
    "baseline",
    "trustfncall_trace_args",
    "trustfncall_manual",
]
DEFAULT_BUILTINS = [
    "none",
    "spotlighting_with_delimiting",
    "repeat_user_prompt",
    "transformers_pi_detector",
    "tool_filter",
]

TRUSTFNCALL_CONFIGS: dict[str, dict[str, Any]] = {
    "baseline": {"use_defense": False, "use_args": False, "policy_scope": "task"},
    "trustfncall_task": {"use_defense": True, "use_args": False, "policy_scope": "task"},
    "trustfncall_task_args": {"use_defense": True, "use_args": True, "policy_scope": "task"},
    "trustfncall_suite": {"use_defense": True, "use_args": False, "policy_scope": "suite"},
    "trustfncall_suite_args": {"use_defense": True, "use_args": True, "policy_scope": "suite"},
    "trustfncall_trace": {"use_defense": True, "use_args": False, "policy_scope": "trace"},
    "trustfncall_trace_args": {"use_defense": True, "use_args": True, "policy_scope": "trace"},
    "trustfncall_trace_hybrid": {"use_defense": True, "use_args": False, "policy_scope": "trace_hybrid"},
    "trustfncall_trace_hybrid_args": {"use_defense": True, "use_args": True, "policy_scope": "trace_hybrid"},
    "trustfncall_manual": {"use_defense": True, "use_args": True, "policy_scope": "manual"},
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * pct)))
    return ordered[index]


def _round(value: float | None, digits: int = 3) -> float | None:
    if value is None:
        return None
    return round(value, digits)


def _summary_stats(values: list[float], *, digits: int = 3) -> dict[str, Any]:
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


def _scenario_total(counts: dict[str, Any]) -> int:
    return int(counts.get("benign_total", 0)) + int(counts.get("attacked_total", 0))


def _task_key(payload: dict[str, Any]) -> tuple[str, str]:
    suites = payload.get("suites") or []
    user_tasks = payload.get("user_tasks") or []
    if len(suites) != 1 or len(user_tasks) != 1:
        raise ValueError("Expected a single suite and user_task per task file")
    return str(suites[0]), str(user_tasks[0])


def _load_trustfncall_task_runs(
    *,
    model: str,
    attack: str,
    config: str,
    suites: list[str],
) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    pattern = f"agentdojo_matrix_v2_{model}_{attack}__{config}__*.json"
    for path in sorted(DATA.glob(pattern)):
        payload = _load_json(path)
        if payload.get("partial") is True:
            continue
        key = _task_key(payload)
        if key[0] not in suites:
            continue
        result_rows = payload.get("results") or []
        if len(result_rows) != 1:
            continue
        row = result_rows[0]
        if row.get("config") != config:
            continue
        rows[key] = {
            "path": path,
            "payload": payload,
            "result": row,
        }
    return rows


def _trustfncall_task_summary(
    *,
    model: str,
    attack: str,
    config: str,
    suites: list[str],
    reference_tasks: set[tuple[str, str]] | None,
) -> dict[str, Any]:
    rows = _load_trustfncall_task_runs(model=model, attack=attack, config=config, suites=suites)
    available_tasks = set(rows)
    missing_tasks = sorted((reference_tasks or set()) - available_tasks)
    by_suite: dict[str, dict[str, Any]] = {}
    total_elapsed = 0.0
    total_scenarios = 0

    for suite_name in suites:
        suite_rows = [row for (suite, _), row in rows.items() if suite == suite_name]
        if not suite_rows:
            continue
        elapsed_values = []
        scenario_total = 0
        user_tasks = []
        for row in suite_rows:
            payload = row["payload"]
            result = row["result"]["overall"]
            counts = result["counts"]
            scenarios = int(counts["attacked_scenarios"]) + int(counts["benign_scenarios"])
            elapsed_sec = float(payload["elapsed_sec"])
            elapsed_values.append(elapsed_sec)
            scenario_total += scenarios
            user_tasks.append(_task_key(payload)[1])
            total_elapsed += elapsed_sec
            total_scenarios += scenarios

        by_suite[suite_name] = {
            "n_task_runs": len(suite_rows),
            "user_tasks": sorted(user_tasks),
            "total_elapsed_sec": _round(sum(elapsed_values), 3),
            "scenario_total": scenario_total,
            "mean_task_elapsed_sec": _round(statistics.mean(elapsed_values), 3),
            "p95_task_elapsed_sec": _round(_percentile(elapsed_values, 0.95), 3),
            "elapsed_sec_per_scenario": _round(sum(elapsed_values) / scenario_total, 4) if scenario_total else None,
        }

    available_suites = sorted(by_suite)
    return {
        "label": config,
        "source": "agentdojo_task_runs",
        "available": bool(rows),
        "coverage": {
            "requested_suites": list(suites),
            "available_suites": available_suites,
            "missing_suites": [suite for suite in suites if suite not in available_suites],
            "n_task_runs": len(rows),
            "missing_tasks": [{"suite": suite, "user_task": task} for suite, task in missing_tasks],
        },
        "overall": {
            "total_elapsed_sec": _round(total_elapsed, 3),
            "scenario_total": total_scenarios,
            "elapsed_sec_per_scenario": _round(total_elapsed / total_scenarios, 4) if total_scenarios else None,
        },
        "by_suite": by_suite,
    }


def _extract_preflight_trace(payload: dict[str, Any], attack: str) -> list[dict[str, Any]]:
    result = payload["results"][0]["overall"]
    benign = result.get("benign_no_attack") or payload["results"][0]["per_attack"][attack]["benign_no_attack"]
    if not benign:
        return []
    return list(benign[0]["trace"]["events"])


def _extract_real_calls(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload["results"][0]["overall"]
    events: list[dict[str, Any]] = []
    for benign_case in result.get("benign_no_attack", []):
        events.extend(benign_case["trace"]["events"])
    for attacked_case in result.get("attacked", []):
        events.extend(attacked_case["trace"]["events"])
    return [
        event
        for event in events
        if event.get("function") and not event.get("invalid", False)
    ]


def _manager_cache_key(config_name: str, suite_name: str, user_task_id: str) -> tuple[str, str, str]:
    meta = TRUSTFNCALL_CONFIGS[config_name]
    policy_scope = meta["policy_scope"]
    if policy_scope in {"manual", "suite"}:
        return config_name, suite_name, "__suite__"
    return config_name, suite_name, user_task_id


def _build_manager(
    *,
    config_name: str,
    suite_name: str,
    user_task_id: str,
    preflight_trace: list[dict[str, Any]],
    env_cache: dict[str, Any],
) -> Any:
    meta = TRUSTFNCALL_CONFIGS[config_name]
    if not meta["use_defense"]:
        return None

    suite = _SUITES["v1"][suite_name]
    env = env_cache[suite_name]
    user_task = suite.user_tasks[user_task_id]
    policy_scope = meta["policy_scope"]
    use_args = bool(meta["use_args"])

    if policy_scope == "manual":
        return build_manual_policy(suite, env)
    if policy_scope in {"trace", "trace_hybrid"}:
        return build_policy_from_trace(suite, env, preflight_trace, use_args, policy_scope)
    return build_policy(suite, user_task, env, use_args, policy_scope)


def _benchmark_real_policy_latency(
    *,
    model: str,
    attack: str,
    suites: list[str],
    configs: list[str],
    repeat: int,
    save_raw: bool,
) -> dict[str, Any]:
    baseline_rows = _load_trustfncall_task_runs(model=model, attack=attack, config="baseline", suites=suites)
    if not baseline_rows:
        return {
            "available": False,
            "reason": "baseline AgentDojo task runs not found",
        }

    env_cache = {
        suite_name: _SUITES["v1"][suite_name].load_and_inject_default_environment({})
        for suite_name in suites
    }

    output: dict[str, Any] = {
        "available": True,
        "source": "real_agentdojo_policies_and_real_traces",
        "repeat": repeat,
        "configs": {},
    }

    for config_name in configs:
        if config_name not in TRUSTFNCALL_CONFIGS:
            output["configs"][config_name] = {
                "available": False,
                "reason": "unknown config",
            }
            continue

        meta = TRUSTFNCALL_CONFIGS[config_name]
        latencies_overall: list[float] = []
        latencies_by_suite: dict[str, list[float]] = defaultdict(list)
        allowed = 0
        blocked = 0
        policies_built = 0
        policy_build_ms: list[float] = []
        real_call_count = 0
        manager_cache: dict[tuple[str, str, str], Any] = {}

        for (suite_name, user_task_id), row in sorted(baseline_rows.items()):
            payload = row["payload"]
            preflight_trace = _extract_preflight_trace(payload, attack)
            real_calls = _extract_real_calls(payload)
            real_call_count += len(real_calls)

            cache_key = _manager_cache_key(config_name, suite_name, user_task_id)
            mgr = manager_cache.get(cache_key)
            if cache_key not in manager_cache:
                t0 = time.perf_counter_ns()
                mgr = _build_manager(
                    config_name=config_name,
                    suite_name=suite_name,
                    user_task_id=user_task_id,
                    preflight_trace=preflight_trace,
                    env_cache=env_cache,
                )
                t1 = time.perf_counter_ns()
                manager_cache[cache_key] = mgr
                if mgr is not None:
                    policies_built += 1
                    policy_build_ms.append((t1 - t0) / 1e6)

            if mgr is None:
                continue

            for _ in range(repeat):
                for event in real_calls:
                    t0 = time.perf_counter_ns()
                    decision = mgr.authorize(
                        "agent",
                        event["function"],
                        arguments=event["args"] if meta["use_args"] else None,
                    )
                    t1 = time.perf_counter_ns()
                    latency_us = (t1 - t0) / 1000.0
                    latencies_overall.append(latency_us)
                    latencies_by_suite[suite_name].append(latency_us)
                    if decision.authorized:
                        allowed += 1
                    else:
                        blocked += 1

        config_row: dict[str, Any] = {
            "available": True,
            "policy_scope": meta["policy_scope"],
            "use_args": bool(meta["use_args"]),
            "n_task_policies_considered": len(baseline_rows),
            "n_policies_built": policies_built,
            "real_unique_calls": real_call_count,
            "decision_counts": {
                "authorized": allowed,
                "blocked": blocked,
            },
            "policy_build_ms": _summary_stats(policy_build_ms),
            "authorize_latency_us": _summary_stats(latencies_overall),
            "by_suite": {},
        }

        if save_raw:
            config_row["authorize_latency_us"]["raw"] = latencies_overall

        for suite_name in suites:
            suite_latencies = latencies_by_suite.get(suite_name, [])
            suite_row = _summary_stats(suite_latencies)
            if save_raw and suite_latencies:
                suite_row["raw"] = suite_latencies
            config_row["by_suite"][suite_name] = suite_row

        output["configs"][config_name] = config_row

    return output


def _run_subprocess(cmd: list[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True)


def _maybe_run_missing_agentdojo_builtins(
    *,
    model: str,
    attack: str,
    suites: list[str],
    defenses: list[str],
) -> None:
    out = DATA / f"agentdojo_builtin_baselines_{model}_{attack}.json"
    if out.exists():
        return
    _run_subprocess(
        [
            sys.executable,
            str(BUILTIN_SCRIPT),
            "--model",
            model,
            "--attack",
            attack,
            "--suites",
            *suites,
            "--defenses",
            *defenses,
        ]
    )


def _maybe_run_missing_melon(
    *,
    model: str,
    attack: str,
    suites: list[str],
) -> None:
    out = DATA / f"melon_agentdojo_{model}_{attack}.json"
    if out.exists():
        return
    _run_subprocess(
        [
            sys.executable,
            str(MELON_SCRIPT),
            "--model",
            model,
            "--attack",
            attack,
            "--suites",
            *suites,
        ]
    )


def _maybe_run_missing_progent(
    *,
    model: str,
    attack: str,
    suites: list[str],
    mode: str,
) -> None:
    out = DATA / f"progent_agentdojo_{mode}_{model}_{attack}.json"
    if out.exists():
        return
    _run_subprocess(
        [
            sys.executable,
            str(PROGENT_SCRIPT),
            "--model",
            model,
            "--attack",
            attack,
            "--mode",
            mode,
            "--policy-model",
            model,
            "--suites",
            *suites,
        ]
    )


def _suite_runtime_row(
    *,
    elapsed_sec: float | None,
    counts: dict[str, Any],
) -> dict[str, Any]:
    scenario_total = _scenario_total(counts)
    return {
        "elapsed_sec": _round(elapsed_sec, 3) if elapsed_sec is not None else None,
        "scenario_total": scenario_total,
        "elapsed_sec_per_scenario": _round(elapsed_sec / scenario_total, 4)
        if elapsed_sec is not None and scenario_total
        else None,
    }


def _sum_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    total: dict[str, int] = {
        "benign_total": 0,
        "benign_success": 0,
        "attacked_total": 0,
        "attacked_utility_success": 0,
        "attacked_asr_success": 0,
    }
    for row in rows:
        counts = row.get("counts", {}) or {}
        for key in total:
            total[key] += int(counts.get(key, 0) or 0)
    return total


def _load_builtin_methods(
    *,
    model: str,
    attack: str,
    suites: list[str],
    defenses: list[str],
) -> dict[str, Any]:
    path = DATA / f"agentdojo_builtin_baselines_{model}_{attack}.json"
    if not path.exists():
        return {
            f"agentdojo_builtin:{defense}": {
                "label": f"AgentDojo built-in: {defense}",
                "source": "agentdojo_builtin",
                "available": False,
                "reason": "result file not found",
            }
            for defense in defenses
        }

    payload = _load_json(path)
    rows = {row["defense"]: row for row in payload.get("results", [])}
    methods: dict[str, Any] = {}
    for defense in defenses:
        row = rows.get(defense)
        if not row:
            methods[f"agentdojo_builtin:{defense}"] = {
                "label": f"AgentDojo built-in: {defense}",
                "source": "agentdojo_builtin",
                "available": False,
                "reason": "defense missing from collection",
            }
            continue

        suite_rows = {}
        missing_suite_elapsed = []
        for suite_name in suites:
            suite_row = (row.get("suites") or {}).get(suite_name)
            if not suite_row:
                continue
            if suite_row.get("elapsed_sec") is None:
                missing_suite_elapsed.append(suite_name)
            suite_rows[suite_name] = _suite_runtime_row(
                elapsed_sec=suite_row.get("elapsed_sec"),
                counts=suite_row.get("counts", {}),
            )

        methods[f"agentdojo_builtin:{defense}"] = {
            "label": f"AgentDojo built-in: {defense}",
            "source": "agentdojo_builtin",
            "available": True,
            "coverage": {
                "requested_suites": list(suites),
                "available_suites": sorted(suite_rows),
                "missing_suites": [suite for suite in suites if suite not in suite_rows],
                "missing_suite_elapsed": missing_suite_elapsed,
            },
            "overall": _suite_runtime_row(
                elapsed_sec=row.get("elapsed_sec"),
                counts=row.get("counts", {}),
            ),
            "by_suite": suite_rows,
            "metrics": {
                "ASR": row.get("ASR"),
                "UA": row.get("UA"),
                "UAR_no_atk": row.get("UAR_no_atk"),
            },
        }
    return methods


def _load_single_baseline_method(
    *,
    path: Path,
    label: str,
    source: str,
    suites: list[str],
    mode: str | None = None,
) -> dict[str, Any]:
    if path.exists():
        payload = _load_json(path)
    else:
        suite_payloads = []
        for suite_path in sorted(path.parent.glob(f"{path.stem}__*.json")):
            try:
                suite_payload = _load_json(suite_path)
            except Exception:
                continue
            suite_name = suite_payload.get("suite")
            if suite_name not in suites:
                continue
            suite_payloads.append(suite_payload)
        if not suite_payloads:
            return {
                "label": label,
                "source": source,
                "available": False,
                "reason": "result file not found",
            }
        suite_map = {row["suite"]: row for row in suite_payloads}
        aggregate_counts = _sum_counts(suite_payloads)
        elapsed_total = sum(float(row.get("elapsed_sec", 0) or 0) for row in suite_payloads)
        payload = {
            "elapsed_sec": elapsed_total if elapsed_total > 0 else None,
            "counts": aggregate_counts,
            "suites": suite_map,
            "ASR": None,
            "UA": None,
            "UAR_no_atk": None,
        }

    suite_rows = {}
    missing_suite_elapsed = []
    aggregate_counts_rows = []
    for suite_name in suites:
        suite_row = (payload.get("suites") or {}).get(suite_name)
        if not suite_row:
            continue
        aggregate_counts_rows.append(suite_row)
        if suite_row.get("elapsed_sec") is None:
            missing_suite_elapsed.append(suite_name)
        suite_rows[suite_name] = _suite_runtime_row(
            elapsed_sec=suite_row.get("elapsed_sec"),
            counts=suite_row.get("counts", {}),
        )

    overall_counts = payload.get("counts", {}) or _sum_counts(aggregate_counts_rows)

    result = {
        "label": label,
        "source": source,
        "available": True,
        "coverage": {
            "requested_suites": list(suites),
            "available_suites": sorted(suite_rows),
            "missing_suites": [suite for suite in suites if suite not in suite_rows],
            "missing_suite_elapsed": missing_suite_elapsed,
        },
        "overall": _suite_runtime_row(
            elapsed_sec=payload.get("elapsed_sec"),
            counts=overall_counts,
        ),
        "by_suite": suite_rows,
        "metrics": {
            "ASR": payload.get("ASR"),
            "UA": payload.get("UA"),
            "UAR_no_atk": payload.get("UAR_no_atk"),
        },
    }
    if mode is not None:
        result["mode"] = mode
    return result


def _reference_suite_counts(summary: dict[str, Any], suites: list[str]) -> dict[str, int]:
    counts = {}
    for suite_name in suites:
        suite_row = summary.get("by_suite", {}).get(suite_name)
        if suite_row:
            counts[suite_name] = int(suite_row["scenario_total"])
    return counts


def _apply_fairness_checks(
    *,
    methods: dict[str, Any],
    reference_counts: dict[str, int],
) -> list[str]:
    warnings: list[str] = []
    for key, row in methods.items():
        if not row.get("available"):
            continue
        suite_rows = row.get("by_suite", {})
        mismatched = []
        for suite_name, expected in reference_counts.items():
            actual = suite_rows.get(suite_name, {}).get("scenario_total")
            if actual is None:
                mismatched.append(f"{suite_name}:missing")
            elif int(actual) != int(expected):
                mismatched.append(f"{suite_name}:{actual}!={expected}")
        row["fairness"] = {
            "scenario_counts_match_reference": not mismatched,
            "reference": reference_counts,
            "mismatches": mismatched,
        }
        if mismatched:
            warnings.append(f"{key} scenario coverage mismatch: {', '.join(mismatched)}")
    return warnings


def _collect_end_to_end(
    *,
    model: str,
    attack: str,
    suites: list[str],
    trustfncall_configs: list[str],
    builtins: list[str],
    run_missing: bool,
) -> dict[str, Any]:
    if run_missing:
        _maybe_run_missing_agentdojo_builtins(model=model, attack=attack, suites=suites, defenses=builtins)
        _maybe_run_missing_melon(model=model, attack=attack, suites=suites)
        _maybe_run_missing_progent(model=model, attack=attack, suites=suites, mode="manual")
        _maybe_run_missing_progent(model=model, attack=attack, suites=suites, mode="auto")

    trust_methods: dict[str, Any] = {}
    baseline_summary = _trustfncall_task_summary(
        model=model,
        attack=attack,
        config="baseline",
        suites=suites,
        reference_tasks=None,
    )
    trust_methods["trustfncall:baseline"] = baseline_summary
    reference_rows = _load_trustfncall_task_runs(model=model, attack=attack, config="baseline", suites=suites)
    reference_tasks = set(reference_rows)

    for config in trustfncall_configs:
        if config == "baseline":
            continue
        trust_methods[f"trustfncall:{config}"] = _trustfncall_task_summary(
            model=model,
            attack=attack,
            config=config,
            suites=suites,
            reference_tasks=reference_tasks,
        )

    methods = dict(trust_methods)
    methods.update(_load_builtin_methods(model=model, attack=attack, suites=suites, defenses=builtins))
    methods["melon"] = _load_single_baseline_method(
        path=DATA / f"melon_agentdojo_{model}_{attack}.json",
        label="MELON",
        source="melon_agentdojo",
        suites=suites,
    )
    methods["progent:manual"] = _load_single_baseline_method(
        path=DATA / f"progent_agentdojo_manual_{model}_{attack}.json",
        label="Progent manual",
        source="progent_agentdojo",
        suites=suites,
        mode="manual",
    )
    methods["progent:auto"] = _load_single_baseline_method(
        path=DATA / f"progent_agentdojo_auto_{model}_{attack}.json",
        label="Progent auto",
        source="progent_agentdojo",
        suites=suites,
        mode="auto",
    )

    reference_counts = _reference_suite_counts(baseline_summary, suites)
    fairness_warnings = _apply_fairness_checks(methods=methods, reference_counts=reference_counts)

    return {
        "reference_method": "trustfncall:baseline",
        "reference_suite_counts": reference_counts,
        "methods": methods,
        "fairness_warnings": fairness_warnings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fair real-data system evaluation")
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--suites", nargs="+", default=DEFAULT_SUITES)
    parser.add_argument("--trustfncall-configs", nargs="+", default=DEFAULT_TRUSTFNCALL_CONFIGS)
    parser.add_argument("--builtin-defenses", nargs="+", default=DEFAULT_BUILTINS)
    parser.add_argument("--repeat", type=int, default=20, help="Times to replay each real traced call for latency sampling")
    parser.add_argument("--run-missing", action="store_true", help="Invoke baseline runners for missing result files")
    parser.add_argument("--save-raw", action="store_true", help="Store raw authorize() latency samples in the JSON output")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    start = time.time()
    enforcement = _benchmark_real_policy_latency(
        model=args.model,
        attack=args.attack,
        suites=list(args.suites),
        configs=list(args.trustfncall_configs),
        repeat=args.repeat,
        save_raw=args.save_raw,
    )
    end_to_end = _collect_end_to_end(
        model=args.model,
        attack=args.attack,
        suites=list(args.suites),
        trustfncall_configs=list(args.trustfncall_configs),
        builtins=list(args.builtin_defenses),
        run_missing=args.run_missing,
    )

    output = {
        "schema_version": "system_eval_real_v1",
        "model": args.model,
        "attack": args.attack,
        "suites": list(args.suites),
        "trustfncall_configs": list(args.trustfncall_configs),
        "builtin_defenses": list(args.builtin_defenses),
        "elapsed_sec": round(time.time() - start, 1),
        "notes": [
            "Online enforcement latency uses real AgentDojo-derived policies and real traced tool-call arguments.",
            "End-to-end runtime rows are computed from real local result artifacts only; missing coverage is reported explicitly.",
            "TrustFnCall trace variants use cached baseline benign traces as the preflight source when rebuilding real policies offline.",
        ],
        "enforcement_latency_real": enforcement,
        "end_to_end_real": end_to_end,
    }

    out = Path(args.output) if args.output else DATA / f"system_eval_real_{args.model}_{args.attack}.json"
    out.write_text(json.dumps(output, indent=2))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
