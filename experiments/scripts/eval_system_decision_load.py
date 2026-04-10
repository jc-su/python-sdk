"""Real offline shared-load benchmark for online decision methods only.

This benchmark keeps the suite mix fixed across points and separates:

- Throughput phase: untimed hot loop, count completed decisions
- Latency phase: sampled per-call latency under the same worker concurrency

Included methods:
- TrustFnCall-Trace
- TrustFnCall-Manual
- Progent-Manual
- PI Detector

Excluded on purpose:
- Repeat Prompt / Spotlighting: prompt transforms, not online blocking decisions
- Tool Filter / MELON: require remote-model decisions for a fair end-to-end load path
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import random
import time
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

SCRIPT_DIR = Path(__file__).resolve().parent

import sys

sys.path.insert(0, str(SCRIPT_DIR))
import eval_system_hook_worker_load as base

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


METHODS: dict[str, dict[str, Any]] = {
    "trustfncall_trace_args": {
        "label": "TrustFnCall-Trace",
        "color": "#08519c",
        "throughput_chunk": 512,
        "latency_chunk": 256,
        "latency_sample_stride": 256,
        "warmup_calls": 64,
    },
    "trustfncall_manual": {
        "label": "TrustFnCall-Manual",
        "color": "#6baed6",
        "throughput_chunk": 512,
        "latency_chunk": 256,
        "latency_sample_stride": 256,
        "warmup_calls": 64,
    },
    "progent_manual_check_tool_call": {
        "label": "Progent-Manual",
        "color": "#de2d26",
        "throughput_chunk": 64,
        "latency_chunk": 16,
        "latency_sample_stride": 16,
        "warmup_calls": 32,
    },
    "transformers_pi_detector": {
        "label": "PI Detector",
        "color": "#756bb1",
        "throughput_chunk": 1,
        "latency_chunk": 1,
        "latency_sample_stride": 1,
        "warmup_calls": 2,
    },
}


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct)))
    return ordered[idx]


def _latency_summary(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"n_samples": 0, "p50": None, "p95": None, "p99": None}
    return {
        "n_samples": len(values),
        "p50": round(float(_percentile(values, 0.50) or 0.0), 3),
        "p95": round(float(_percentile(values, 0.95) or 0.0), 3),
        "p99": round(float(_percentile(values, 0.99) or 0.0), 3),
    }


def _throughput_worker(
    method_key: str,
    model: str,
    attack: str,
    worker_idx: int,
    start_event: Any,
    stop_event: Any,
    queue: Any,
) -> None:
    try:
        cfg = METHODS[method_key]
        fn, items, meta = base._init_worker_state(method_key, model, attack, worker_idx)
        if not items:
            queue.put({"kind": "error", "worker_idx": worker_idx, "error": "no_items"})
            return
        warmup_calls = min(int(cfg["warmup_calls"]), len(items))
        for idx in range(warmup_calls):
            fn(items[idx])

        queue.put({"kind": "ready", "worker_idx": worker_idx, "meta": meta})
        start_event.wait()

        chunk = int(cfg["throughput_chunk"])
        n_items = len(items)
        idx = worker_idx % n_items
        count = 0
        while not stop_event.is_set():
            for _ in range(chunk):
                fn(items[idx])
                idx += 1
                if idx >= n_items:
                    idx = 0
            count += chunk

        queue.put({"kind": "result", "worker_idx": worker_idx, "count": count})
    except Exception as exc:
        queue.put({"kind": "error", "worker_idx": worker_idx, "error": repr(exc)})


def _latency_worker(
    method_key: str,
    model: str,
    attack: str,
    worker_idx: int,
    start_event: Any,
    stop_event: Any,
    queue: Any,
    sample_limit: int,
) -> None:
    try:
        cfg = METHODS[method_key]
        rng = random.Random(1000 + worker_idx)
        fn, items, meta = base._init_worker_state(method_key, model, attack, worker_idx)
        if not items:
            queue.put({"kind": "error", "worker_idx": worker_idx, "error": "no_items"})
            return
        warmup_calls = min(int(cfg["warmup_calls"]), len(items))
        for idx in range(warmup_calls):
            fn(items[idx])

        queue.put({"kind": "ready", "worker_idx": worker_idx, "meta": meta})
        start_event.wait()

        chunk = int(cfg["latency_chunk"])
        stride = max(1, int(cfg["latency_sample_stride"]))
        n_items = len(items)
        idx = worker_idx % n_items
        count = 0
        sampled = 0
        samples: list[float] = []
        while not stop_event.is_set():
            for _ in range(chunk):
                item = items[idx]
                idx += 1
                if idx >= n_items:
                    idx = 0
                count += 1
                if count <= 16 or count % stride == 0:
                    t0 = time.perf_counter_ns()
                    fn(item)
                    t1 = time.perf_counter_ns()
                    sampled += 1
                    base._reservoir_add(samples, (t1 - t0) / 1000.0, seen=sampled, limit=sample_limit, rng=rng)
                else:
                    fn(item)

        queue.put({"kind": "result", "worker_idx": worker_idx, "count": count, "samples": samples})
    except Exception as exc:
        queue.put({"kind": "error", "worker_idx": worker_idx, "error": repr(exc)})


def _run_phase(
    method_key: str,
    *,
    model: str,
    attack: str,
    workers: int,
    duration_sec: float,
    sample_limit: int,
    worker_fn,
) -> tuple[float, list[dict[str, Any]]]:
    ctx = mp.get_context("fork")
    start_event = ctx.Event()
    stop_event = ctx.Event()
    queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=worker_fn,
            args=(method_key, model, attack, worker_idx, start_event, stop_event, queue, sample_limit)
            if worker_fn is _latency_worker
            else (method_key, model, attack, worker_idx, start_event, stop_event, queue),
        )
        for worker_idx in range(workers)
    ]

    for proc in procs:
        proc.start()

    ready = 0
    results: list[dict[str, Any]] = []
    while ready < workers:
        msg = queue.get()
        if msg.get("kind") == "ready":
            ready += 1
            continue
        if msg.get("kind") == "error":
            for proc in procs:
                if proc.is_alive():
                    proc.terminate()
            raise RuntimeError(f"{method_key} worker {msg.get('worker_idx')} failed: {msg.get('error')}")

    bench_start = time.perf_counter()
    start_event.set()
    time.sleep(duration_sec)
    stop_event.set()
    elapsed_sec = max(time.perf_counter() - bench_start, 1e-9)

    while len(results) < workers:
        msg = queue.get()
        if msg.get("kind") == "result":
            results.append(msg)
            continue
        if msg.get("kind") == "error":
            for proc in procs:
                if proc.is_alive():
                    proc.terminate()
            raise RuntimeError(f"{method_key} worker {msg.get('worker_idx')} failed: {msg.get('error')}")

    for proc in procs:
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()

    return elapsed_sec, results


def _run_point(
    method_key: str,
    *,
    model: str,
    attack: str,
    workers: int,
    throughput_duration_sec: float,
    latency_duration_sec: float,
    sample_limit: int,
) -> dict[str, Any]:
    throughput_elapsed, throughput_rows = _run_phase(
        method_key,
        model=model,
        attack=attack,
        workers=workers,
        duration_sec=throughput_duration_sec,
        sample_limit=sample_limit,
        worker_fn=_throughput_worker,
    )
    total_count = sum(int(row["count"]) for row in throughput_rows)
    throughput = total_count / throughput_elapsed

    latency_elapsed, latency_rows = _run_phase(
        method_key,
        model=model,
        attack=attack,
        workers=workers,
        duration_sec=latency_duration_sec,
        sample_limit=sample_limit,
        worker_fn=_latency_worker,
    )
    samples = []
    sampled_ops = 0
    for row in latency_rows:
        sampled_ops += int(row["count"])
        samples.extend(float(value) for value in row.get("samples") or [])

    return {
        "workers": workers,
        "throughput_phase_sec": round(throughput_elapsed, 3),
        "latency_phase_sec": round(latency_elapsed, 3),
        "completed_ops": total_count,
        "achieved_throughput_ops_per_sec": round(throughput, 3),
        "latency_us": _latency_summary(samples),
        "latency_sample_count": len(samples),
        "latency_phase_completed_ops": sampled_ops,
    }


def _plot_throughput(results: dict[str, Any], filename: str) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for key, cfg in METHODS.items():
        row = results["methods"].get(key)
        if not row or not row.get("available"):
            continue
        points = row.get("points") or []
        x = [pt["workers"] for pt in points]
        y = [pt["achieved_throughput_ops_per_sec"] for pt in points]
        ax.plot(x, y, marker="o", linewidth=1.3, markersize=3, color=cfg["color"], label=cfg["label"])
    ax.set_xticks(results["worker_counts"])
    ax.set_xlabel("Concurrent workers")
    ax.set_ylabel("Achieved throughput (decisions/s)")
    ax.set_yscale("log")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / filename, dpi=300, bbox_inches="tight")
    plt.close(fig)


def _plot_latency(results: dict[str, Any], filename: str) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for key, cfg in METHODS.items():
        row = results["methods"].get(key)
        if not row or not row.get("available"):
            continue
        points = row.get("points") or []
        x = [pt["workers"] for pt in points if (pt.get("latency_us") or {}).get("p95") is not None]
        y = [(pt.get("latency_us") or {}).get("p95") for pt in points if (pt.get("latency_us") or {}).get("p95") is not None]
        if not x:
            continue
        ax.plot(x, y, marker="o", linewidth=1.3, markersize=3, color=cfg["color"], label=cfg["label"])
    ax.set_xticks(results["worker_counts"])
    ax.set_xlabel("Concurrent workers")
    ax.set_ylabel("p95 decision latency (μs)")
    ax.set_yscale("log")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / filename, dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Real offline shared-load benchmark for online decision methods")
    parser.add_argument("--model", default=base.CURRENT_MODEL)
    parser.add_argument("--attack", default=base.CURRENT_ATTACK)
    parser.add_argument("--workers", default="4,8,16")
    parser.add_argument("--throughput-duration-sec", type=float, default=2.5)
    parser.add_argument("--latency-duration-sec", type=float, default=2.5)
    parser.add_argument("--sample-limit", type=int, default=4096)
    args = parser.parse_args()

    worker_counts = [int(part) for part in args.workers.split(",") if part.strip()]
    suite_count = len(base.CURRENT_SUITES)
    invalid = [count for count in worker_counts if count <= 0 or count % suite_count != 0]
    if invalid:
        raise SystemExit(
            f"--workers values must be positive multiples of {suite_count} so each point preserves the same suite mix; got {invalid}"
        )

    methods_out: dict[str, Any] = {}
    for method_key in METHODS:
        points = []
        try:
            base.preload_worker_states([method_key], model=args.model, attack=args.attack, suites=base.CURRENT_SUITES)
            for workers in worker_counts:
                points.append(_run_point(
                    method_key,
                    model=args.model,
                    attack=args.attack,
                    workers=workers,
                    throughput_duration_sec=args.throughput_duration_sec,
                    latency_duration_sec=args.latency_duration_sec,
                    sample_limit=args.sample_limit,
                ))
            methods_out[method_key] = {
                "available": True,
                "points": points,
            }
        except Exception as exc:
            methods_out[method_key] = {
                "available": False,
                "reason": repr(exc),
            }
        finally:
            base.clear_preloaded_states([method_key])

    result = {
        "schema_version": "system_decision_load_v1",
        "model": args.model,
        "attack": args.attack,
        "worker_counts": worker_counts,
        "throughput_duration_sec": args.throughput_duration_sec,
        "latency_duration_sec": args.latency_duration_sec,
        "sample_limit_per_worker": args.sample_limit,
        "methods": methods_out,
        "notes": [
            "This benchmark only includes online decision methods, not prompt-rewrite defenses.",
            "Worker counts are balanced across the four AgentDojo suites so every point preserves the same suite mix.",
            "Throughput is measured in a separate untimed hot-loop phase to avoid per-call timer overhead dominating microsecond methods.",
            "Latency is measured in a separate sampled phase under the same concurrency.",
            "PI Detector is measured as local cached transformer inference; no external serving stack or remote API is used.",
            "Tool Filter and MELON are excluded because their fair online decision path requires remote model calls.",
        ],
    }

    out_json = OUTDIR / f"decision_load_eval_{args.model}_{args.attack}.json"
    out_json.write_text(json.dumps(result, indent=2))
    _plot_throughput(result, "fig_decision_load_throughput.pdf")
    _plot_latency(result, "fig_decision_load_latency.pdf")
    print(f"Saved {out_json}")


if __name__ == "__main__":
    main()
