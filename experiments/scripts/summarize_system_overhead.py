"""Summarize TrustFnCall system overhead from cached local evaluation outputs.

This script is intentionally offline-first:
  - It never calls an LLM API.
  - It reuses per-task AgentDojo matrix runs for end-to-end wall-clock overhead.
  - It reuses top-level baseline JSONs when those are already present locally.

Outputs:
  data/system_overhead_<model>_<attack>.json
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

DEFAULT_CONFIGS = [
    "baseline",
    "trustfncall_trace_args",
    "trustfncall_manual",
]


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


def _scenario_total(per_attack: dict[str, Any]) -> int:
    counts = per_attack.get("counts", {})
    return int(counts.get("attacked_scenarios", 0)) + int(counts.get("benign_scenarios", 0))


def _task_key(path: Path, payload: dict[str, Any]) -> tuple[str, str]:
    suites = payload.get("suites") or []
    user_tasks = payload.get("user_tasks") or []
    if len(suites) == 1 and len(user_tasks) == 1:
        return str(suites[0]), str(user_tasks[0])
    raise ValueError(f"Expected a single suite and user task in {path}")


def _load_agentdojo_task_runs(model: str, attack: str, config: str) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    pattern = f"agentdojo_matrix_v2_{model}_{attack}__{config}__*.json"
    for path in sorted(DATA.glob(pattern)):
        payload = _load_json(path)
        if payload.get("partial") is True:
            continue
        if payload.get("attacks") != [attack]:
            continue
        results = payload.get("results") or []
        if len(results) != 1:
            continue
        row = results[0]
        if row.get("config") != config:
            continue
        per_attack = row.get("per_attack", {}).get(attack)
        if not per_attack:
            continue
        key = _task_key(path, payload)
        scenarios = _scenario_total(per_attack)
        if scenarios <= 0:
            continue
        rows[key] = {
            "path": str(path),
            "suite": key[0],
            "user_task": key[1],
            "config": config,
            "elapsed_sec": float(payload["elapsed_sec"]),
            "scenario_total": scenarios,
            "elapsed_sec_per_scenario": float(payload["elapsed_sec"]) / scenarios,
            "attacked_scenarios": int(per_attack["counts"]["attacked_scenarios"]),
            "benign_scenarios": int(per_attack["counts"]["benign_scenarios"]),
            "ASR": per_attack.get("ASR"),
            "UA": per_attack.get("UA"),
            "UAR_no_atk": per_attack.get("UAR_no_atk"),
        }
    return rows


def _summarize_runs(rows: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "available": False,
            "n_task_runs": 0,
        }

    elapsed = [row["elapsed_sec"] for row in rows.values()]
    per_scenario = [row["elapsed_sec_per_scenario"] for row in rows.values()]
    total_elapsed = sum(elapsed)
    total_scenarios = sum(row["scenario_total"] for row in rows.values())
    return {
        "available": True,
        "n_task_runs": len(rows),
        "total_elapsed_sec": _round(total_elapsed, 1),
        "total_scenarios": total_scenarios,
        "mean_task_elapsed_sec": _round(statistics.mean(elapsed), 3),
        "p50_task_elapsed_sec": _round(_percentile(elapsed, 0.50), 3),
        "p95_task_elapsed_sec": _round(_percentile(elapsed, 0.95), 3),
        "p99_task_elapsed_sec": _round(_percentile(elapsed, 0.99), 3),
        "mean_elapsed_sec_per_scenario": _round(statistics.mean(per_scenario), 4),
        "aggregate_elapsed_sec_per_scenario": _round(total_elapsed / total_scenarios, 4) if total_scenarios else None,
    }


def _paired_overhead(
    baseline_rows: dict[tuple[str, str], dict[str, Any]],
    other_rows: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    common_keys = sorted(set(baseline_rows) & set(other_rows))
    missing_in_other = sorted(set(baseline_rows) - set(other_rows))
    missing_in_baseline = sorted(set(other_rows) - set(baseline_rows))
    if not common_keys:
        return {
            "available": False,
            "n_paired_task_runs": 0,
            "missing_in_config": [{"suite": suite, "user_task": user_task} for suite, user_task in missing_in_other],
            "missing_in_baseline": [{"suite": suite, "user_task": user_task} for suite, user_task in missing_in_baseline],
        }

    baseline_elapsed = [baseline_rows[key]["elapsed_sec"] for key in common_keys]
    other_elapsed = [other_rows[key]["elapsed_sec"] for key in common_keys]
    extra_elapsed = [other - base for base, other in zip(baseline_elapsed, other_elapsed, strict=True)]
    baseline_per_scenario = [baseline_rows[key]["elapsed_sec_per_scenario"] for key in common_keys]
    other_per_scenario = [other_rows[key]["elapsed_sec_per_scenario"] for key in common_keys]
    extra_per_scenario = [other - base for base, other in zip(baseline_per_scenario, other_per_scenario, strict=True)]
    pct_delta = [
        ((other - base) / base * 100.0) if base > 0 else None
        for base, other in zip(baseline_elapsed, other_elapsed, strict=True)
    ]
    pct_delta = [value for value in pct_delta if value is not None]

    return {
        "available": True,
        "n_paired_task_runs": len(common_keys),
        "missing_in_config": [{"suite": suite, "user_task": user_task} for suite, user_task in missing_in_other],
        "missing_in_baseline": [{"suite": suite, "user_task": user_task} for suite, user_task in missing_in_baseline],
        "mean_baseline_task_elapsed_sec": _round(statistics.mean(baseline_elapsed), 3),
        "mean_config_task_elapsed_sec": _round(statistics.mean(other_elapsed), 3),
        "mean_extra_sec_per_task": _round(statistics.mean(extra_elapsed), 3),
        "median_extra_sec_per_task": _round(_percentile(extra_elapsed, 0.50), 3),
        "p95_extra_sec_per_task": _round(_percentile(extra_elapsed, 0.95), 3),
        "mean_baseline_sec_per_scenario": _round(statistics.mean(baseline_per_scenario), 4),
        "mean_config_sec_per_scenario": _round(statistics.mean(other_per_scenario), 4),
        "mean_extra_sec_per_scenario": _round(statistics.mean(extra_per_scenario), 4),
        "mean_extra_pct_per_task": _round(statistics.mean(pct_delta), 2) if pct_delta else None,
    }


def _load_top_level_json(name: str) -> dict[str, Any] | None:
    path = DATA / name
    if not path.exists():
        return None
    try:
        payload = _load_json(path)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _summarize_top_level_baseline(payload: dict[str, Any] | None, label: str) -> dict[str, Any]:
    if not payload:
        return {
            "label": label,
            "available": False,
            "reason": "result file not found",
        }

    counts = payload.get("counts", {})
    benign_total = int(counts.get("benign_total", 0))
    attacked_total = int(counts.get("attacked_total", 0))
    scenarios = benign_total + attacked_total
    elapsed_sec = payload.get("elapsed_sec")
    if elapsed_sec is None or scenarios == 0:
        return {
            "label": label,
            "available": False,
            "reason": "elapsed_sec or scenario counts missing",
        }

    return {
        "label": label,
        "available": True,
        "elapsed_sec": _round(float(elapsed_sec), 1),
        "total_scenarios": scenarios,
        "elapsed_sec_per_scenario": _round(float(elapsed_sec) / scenarios, 4),
        "ASR": payload.get("ASR"),
        "UA": payload.get("UA"),
        "UAR_no_atk": payload.get("UAR_no_atk"),
        "path": payload.get("path"),
    }


def _summarize_builtin_collection(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {
            "label": "agentdojo_builtin_collection",
            "available": False,
            "reason": "collection file not found",
        }

    results = payload.get("results") or []
    rows = []
    for row in results:
        counts = row.get("counts", {})
        scenarios = int(counts.get("benign_total", 0)) + int(counts.get("attacked_total", 0))
        elapsed_sec = row.get("elapsed_sec")
        rows.append(
            {
                "defense": row.get("defense"),
                "available": elapsed_sec is not None and scenarios > 0,
                "elapsed_sec": _round(float(elapsed_sec), 1) if elapsed_sec is not None else None,
                "total_scenarios": scenarios,
                "elapsed_sec_per_scenario": _round(float(elapsed_sec) / scenarios, 4)
                if elapsed_sec is not None and scenarios > 0
                else None,
                "ASR": row.get("ASR"),
                "UA": row.get("UA"),
                "UAR_no_atk": row.get("UAR_no_atk"),
            }
        )

    return {
        "label": "agentdojo_builtin_collection",
        "available": bool(rows),
        "rows": rows,
        "note": "Per-defense elapsed_sec is only populated for runs produced after the elapsed-time patch.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize TrustFnCall system overhead from cached outputs")
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--configs", nargs="+", default=DEFAULT_CONFIGS)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    config_rows = {
        config: _load_agentdojo_task_runs(args.model, args.attack, config)
        for config in args.configs
    }
    config_summary = {
        config: _summarize_runs(rows)
        for config, rows in config_rows.items()
    }

    baseline_rows = config_rows.get("baseline", {})
    pairwise = {}
    for config, rows in config_rows.items():
        if config == "baseline":
            continue
        pairwise[config] = _paired_overhead(baseline_rows, rows)

    builtin_payload = _load_top_level_json(f"agentdojo_builtin_baselines_{args.model}_{args.attack}.json")
    melon_payload = _load_top_level_json(f"melon_agentdojo_{args.model}_{args.attack}.json")
    progent_manual_payload = _load_top_level_json(f"progent_agentdojo_manual_{args.model}_{args.attack}.json")
    progent_auto_payload = _load_top_level_json(f"progent_agentdojo_auto_{args.model}_{args.attack}.json")

    output = {
        "schema_version": "system_overhead_v1",
        "model": args.model,
        "attack": args.attack,
        "source": "cached_local_outputs_only",
        "agentdojo_task_runs": config_summary,
        "paired_vs_baseline": pairwise,
        "other_baselines": {
            "agentdojo_builtin": _summarize_builtin_collection(builtin_payload),
            "melon": _summarize_top_level_baseline(melon_payload, "MELON"),
            "progent_manual": _summarize_top_level_baseline(progent_manual_payload, "Progent manual"),
            "progent_auto": _summarize_top_level_baseline(progent_auto_payload, "Progent auto"),
        },
    }

    out = Path(args.output) if args.output else DATA / f"system_overhead_{args.model}_{args.attack}.json"
    out.write_text(json.dumps(output, indent=2))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
