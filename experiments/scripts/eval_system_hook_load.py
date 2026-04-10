"""Generate unified hook load-response figures from empirical service-time traces.

This script reads the real hook benchmark JSON produced by `eval_system_hooks_real.py`
and simulates a single-server decision stage under increasing offered load.

It outputs:
  - fig_hook_load_throughput.pdf : offered rate vs achieved throughput
  - fig_hook_load_latency.pdf    : offered rate vs p95 latency
  - hook_load_eval_<model>_<attack>.json

Important:
  - The load curves are simulation-based, using empirical per-invocation service
    time traces measured on real cached artifacts.
  - Tool Filter remains prep-only in this figure, because the remote OpenAI call
    is not available offline in the current environment.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUTDIR = ROOT / "system_hook_results"
OUTDIR.mkdir(exist_ok=True)
MPLCONFIGDIR = OUTDIR / ".mplconfig"
MPLCONFIGDIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPLCONFIGDIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

matplotlib.rcParams.update({
    "font.size": 8,
    "font.family": "serif",
    "axes.linewidth": 0.6,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.4,
})

DEFAULT_MODEL = "gpt-4o-2024-08-06"
DEFAULT_ATTACK = "important_instructions"
DEFAULT_INPUT = OUTDIR / f"hook_eval_real_{DEFAULT_MODEL}_{DEFAULT_ATTACK}.json"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct)))
    return ordered[idx]


def _method_meta() -> dict[str, dict[str, str]]:
    return {
        "repeat_user_prompt": {"label": "Repeat Prompt", "color": "#3182bd"},
        "spotlighting_with_delimiting": {"label": "Spotlighting", "color": "#31a354"},
        "tool_filter": {"label": "Tool Filter (prep)", "color": "#fd8d3c"},
        "transformers_pi_detector": {"label": "PI Detector", "color": "#756bb1"},
        "trustfncall_trace_args": {"label": "TrustFnCall-Trace", "color": "#08519c"},
        "trustfncall_manual": {"label": "TrustFnCall-Manual", "color": "#6baed6"},
        "progent_manual_check_tool_call": {"label": "Progent-Manual", "color": "#de2d26"},
    }


def _build_shared_rate_grid(max_capacity_ops_per_sec: float) -> list[float]:
    if max_capacity_ops_per_sec <= 0:
        return []
    upper = max(10.0, max_capacity_ops_per_sec * 2.0)
    rates: list[float] = []
    value = 1.0
    while value <= upper * 1.000001:
        rates.append(value)
        value *= 10.0
        if len(rates) > 16:
            break
    return rates


def _simulate_load_curve(
    raw_latencies_us: list[float],
    offered_rate_ops_per_sec: float,
    *,
    n_events: int,
    seed: int,
) -> dict[str, float]:
    rng = random.Random(seed)
    service_times_sec = [value / 1_000_000.0 for value in raw_latencies_us]
    last_finish = 0.0
    latencies_us: list[float] = []

    for idx in range(n_events):
        arrival = idx / offered_rate_ops_per_sec
        service = service_times_sec[rng.randrange(len(service_times_sec))]
        start = arrival if arrival > last_finish else last_finish
        finish = start + service
        last_finish = finish
        latencies_us.append((finish - arrival) * 1_000_000.0)

    total_time = max(last_finish, n_events / offered_rate_ops_per_sec, 1e-12)
    achieved_throughput = n_events / total_time
    return {
        "offered_rate_ops_per_sec": offered_rate_ops_per_sec,
        "achieved_throughput_ops_per_sec": achieved_throughput,
        "p95_latency_us": _percentile(latencies_us, 0.95),
        "p99_latency_us": _percentile(latencies_us, 0.99),
        "mean_latency_us": sum(latencies_us) / len(latencies_us),
    }


def _collect_curves(data: dict[str, Any], *, seed: int, n_events: int) -> tuple[dict[str, Any], list[float]]:
    capacities = [
        float(row.get("throughput_ops_per_sec") or 0.0)
        for row in data["methods"].values()
        if row.get("available")
    ]
    shared_rates = _build_shared_rate_grid(max(capacities) if capacities else 0.0)
    curves: dict[str, Any] = {}
    for key, meta in _method_meta().items():
        row = data["methods"].get(key)
        if not row or not row.get("available"):
            continue
        raw = (row.get("latency_us") or {}).get("raw") or []
        if not raw:
            continue
        throughput = float(row.get("throughput_ops_per_sec") or 0.0)
        points = [
            _simulate_load_curve(raw, rate, n_events=n_events, seed=seed + idx)
            for idx, rate in enumerate(shared_rates)
        ]
        curves[key] = {
            "label": meta["label"],
            "color": meta["color"],
            "measured_throughput_ops_per_sec": throughput,
            "service_trace_samples": len(raw),
            "points": points,
        }
    return curves, shared_rates


def _plot_throughput(curves: dict[str, Any]) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    all_offered = []
    for key, row in curves.items():
        points = row["points"]
        x = [p["offered_rate_ops_per_sec"] for p in points]
        y = [p["achieved_throughput_ops_per_sec"] for p in points]
        all_offered.extend(x)
        ax.plot(x, y, marker="o", linewidth=1.2, markersize=3, color=row["color"], label=row["label"])

    if all_offered:
        lo = min(all_offered)
        hi = max(all_offered)
        ax.plot([lo, hi], [lo, hi], linestyle="--", linewidth=0.8, color="#777777", label="Ideal y=x")

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Offered decision rate (ops/s)")
    ax.set_ylabel("Achieved throughput (ops/s)")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / "fig_hook_load_throughput.pdf", dpi=300, bbox_inches="tight")
    plt.close(fig)


def _plot_latency(curves: dict[str, Any]) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for key, row in curves.items():
        points = row["points"]
        x = [p["offered_rate_ops_per_sec"] for p in points]
        y = [p["p95_latency_us"] for p in points]
        ax.plot(x, y, marker="o", linewidth=1.2, markersize=3, color=row["color"], label=row["label"])

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Offered decision rate (ops/s)")
    ax.set_ylabel("p95 latency (μs)")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / "fig_hook_load_latency.pdf", dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unified hook load-response figures from empirical traces")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--n-events", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    data = _load_json(args.input)
    curves, shared_rates = _collect_curves(data, seed=args.seed, n_events=args.n_events)

    result = {
        "schema_version": "hook_load_sim_v1",
        "input": str(args.input),
        "n_events_per_point": args.n_events,
        "seed": args.seed,
        "shared_offered_rate_grid_ops_per_sec": shared_rates,
        "notes": [
            "These figures are queueing-style load simulations based on empirical service-time traces from the real hook benchmark.",
            "They model a single online decision stage under increasing offered rate.",
            "All methods are evaluated on the same offered-rate grid so the x-axis is directly comparable across lines.",
            "Tool Filter remains prep-only in this figure because the remote OpenAI filtering call is not available offline.",
        ],
        "methods": curves,
    }

    out_json = OUTDIR / f"hook_load_eval_{data['model']}_{data['attack']}.json"
    out_json.write_text(json.dumps(result, indent=2))

    _plot_throughput(curves)
    _plot_latency(curves)
    print(f"Saved {out_json}")


if __name__ == "__main__":
    main()
