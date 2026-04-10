"""Real offline worker-count load benchmark for online defense hooks.

This script replaces the queueing-style offered-QPS simulation with a real
closed-loop benchmark:

- x-axis: worker count
- y-axis: achieved throughput or p95 latency

Each worker initializes the target hook on real cached AgentDojo artifacts,
waits on a start barrier, then repeatedly executes the hook until a stop
signal. No remote LLM API is used for the local-hook methods in this script.

Included methods:
- Repeat Prompt
- Spotlighting
- Tool Filter (local request-prep only)
- PI Detector
- TrustFnCall-Trace
- TrustFnCall-Manual
- Progent-Manual

Excluded:
- MELON, because its actual online path includes remote LLM and embedding-model
  calls, so there is no comparable fully-offline hook benchmark.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import math
import multiprocessing as mp
import os
import random
import sys
import time
import warnings
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUTDIR = ROOT / "system_hook_results"
OUTDIR.mkdir(exist_ok=True)
MPLCONFIGDIR = OUTDIR / ".mplconfig"
MPLCONFIGDIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPLCONFIGDIR))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
warnings.filterwarnings("ignore", category=FutureWarning, module=r"torch\.cuda")

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
CURRENT_MODEL = "gpt-4o-2024-08-06"
CURRENT_ATTACK = "important_instructions"
CURRENT_SUITES = ["banking", "workspace", "slack", "travel"]
PROGENT_ROOT = ROOT.parent.parent / "progent"
PROGENT_AGENTDOJO_SRC = PROGENT_ROOT / "agentdojo" / "src"
_PRELOADED_STATES: dict[tuple[str, str, str, str], tuple[Any, list[dict[str, Any]], dict[str, Any]]] = {}

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


def _suite_for_worker(worker_idx: int) -> str:
    return CURRENT_SUITES[worker_idx % len(CURRENT_SUITES)]


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(len(ordered) * pct)))
    return ordered[idx]


def _summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n_samples": 0, "p50": None, "p95": None, "p99": None}
    return {
        "n_samples": len(values),
        "p50": round(float(_percentile(values, 0.50) or 0.0), 3),
        "p95": round(float(_percentile(values, 0.95) or 0.0), 3),
        "p99": round(float(_percentile(values, 0.99) or 0.0), 3),
    }


def _reservoir_add(
    sample: list[float],
    value: float,
    *,
    seen: int,
    limit: int,
    rng: random.Random,
) -> None:
    if len(sample) < limit:
        sample.append(value)
        return
    idx = rng.randrange(seen)
    if idx < limit:
        sample[idx] = value


def _init_repeat_worker(model: str, suite: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    from eval_system_hooks_real import _collect_real_manual_corpus

    corpus = _collect_real_manual_corpus(model)
    items = [item for item in corpus["prompt_contexts"] if item.get("suite") == suite]
    sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))
    from agentdojo.agent_pipeline.basic_elements import InitQuery

    init_query = InitQuery()
    warnings.filterwarnings("ignore", message="The query is not being added as the first message")

    def fn(item: dict[str, Any]) -> None:
        init_query.query(item["prompt"], None, None, item["messages"], {})

    return fn, items, {"suite": suite, "items": len(items)}


def _init_spotlighting_worker(model: str, suite: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    from eval_system_hooks_real import _collect_real_manual_corpus

    corpus = _collect_real_manual_corpus(model)
    items = [item for item in corpus["tool_outputs"] if item.get("suite") == suite]

    def fn(item: dict[str, Any]) -> str:
        return f"<<{item['text']}>>"

    return fn, items, {"suite": suite, "items": len(items)}


def _init_pi_detector_worker(model: str, suite: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    from eval_system_hooks_real import _collect_real_manual_corpus

    corpus = _collect_real_manual_corpus(model)
    items = [item for item in corpus["tool_outputs"] if item.get("suite") == suite]
    sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))
    with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
        from agentdojo.agent_pipeline.pi_detector import TransformersBasedPIDetector

        detector = TransformersBasedPIDetector(
            model_name="protectai/deberta-v3-base-prompt-injection-v2",
            safe_label="SAFE",
            threshold=0.5,
            mode="message",
        )

    def fn(item: dict[str, Any]) -> tuple[bool, float]:
        return detector.detect(item["text"])

    return fn, items, {"suite": suite, "items": len(items)}


def _init_tool_filter_worker(model: str, suite: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    from eval_system_hooks_real import _collect_real_manual_corpus
    from eval_system_real import _SUITES

    corpus = _collect_real_manual_corpus(model)
    sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))
    from agentdojo.agent_pipeline.agent_pipeline import TOOL_FILTER_PROMPT
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai, _message_to_openai
    from agentdojo.types import ChatSystemMessage, ChatUserMessage, text_content_block_from_string

    suite_obj = _SUITES["v1"][suite]
    tool_defs = [_function_to_openai(tool) for tool in suite_obj.tools]
    items = []
    for row in corpus["task_starts"]:
        if row.get("suite") != suite:
            continue
        items.append({
            "suite": suite,
            "system_prompt": row["system_prompt"],
            "prompt": row["prompt"],
            "tool_defs": tool_defs,
        })

    def fn(item: dict[str, Any]) -> dict[str, Any]:
        messages = []
        if item["system_prompt"]:
            system_msg = ChatSystemMessage(
                role="system",
                content=[text_content_block_from_string(item["system_prompt"])],
            )
            messages.append(_message_to_openai(system_msg, model))
        user_msg = ChatUserMessage(role="user", content=[text_content_block_from_string(item["prompt"])])
        filter_msg = ChatUserMessage(role="user", content=[text_content_block_from_string(TOOL_FILTER_PROMPT)])
        messages.append(_message_to_openai(user_msg, model))
        messages.append(_message_to_openai(filter_msg, model))
        return {
            "messages": messages,
            "tools": item["tool_defs"],
            "tool_choice": "none",
            "temperature": 0.0,
        }

    return fn, items, {"suite": suite, "items": len(items)}


def _init_trustfncall_worker(
    config_name: str,
    model: str,
    attack: str,
    suite: str,
) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    from eval_system_real import (
        TRUSTFNCALL_CONFIGS,
        _SUITES,
        _build_manager,
        _extract_preflight_trace,
        _extract_real_calls,
        _load_trustfncall_task_runs,
        _manager_cache_key,
    )

    meta = TRUSTFNCALL_CONFIGS[config_name]
    baseline_rows = _load_trustfncall_task_runs(model=model, attack=attack, config="baseline", suites=[suite])
    env_cache = {suite: _SUITES["v1"][suite].load_and_inject_default_environment({})}
    manager_cache: dict[tuple[str, str, str], Any] = {}
    items: list[dict[str, Any]] = []
    registered_tools = 0
    allowed_tools = None
    arg_constraints = None

    for (suite_name, user_task_id), row in sorted(baseline_rows.items()):
        payload = row["payload"]
        preflight_trace = _extract_preflight_trace(payload, attack)
        real_calls = _extract_real_calls(payload)
        cache_key = _manager_cache_key(config_name, suite_name, user_task_id)
        mgr = manager_cache.get(cache_key)
        if cache_key not in manager_cache:
            mgr = _build_manager(
                config_name=config_name,
                suite_name=suite_name,
                user_task_id=user_task_id,
                preflight_trace=preflight_trace,
                env_cache=env_cache,
            )
            manager_cache[cache_key] = mgr
        if mgr is None:
            continue

        registered_tools = len(mgr.registered_tools())
        if mgr.rules:
            rule = mgr.rules[0]
            allowed_tools = None if rule.allowed_tools is None else len(rule.allowed_tools)
            arg_constraints = None if rule.argument_constraints is None else len(rule.argument_constraints)

        for event in real_calls:
            items.append({
                "manager": mgr,
                "function": event["function"],
                "args": event["args"] if meta["use_args"] else None,
            })

    def fn(item: dict[str, Any]) -> Any:
        return item["manager"].authorize("agent", item["function"], arguments=item["args"])

    return fn, items, {
        "suite": suite,
        "items": len(items),
        "registered_tools": registered_tools,
        "allowed_tools": allowed_tools,
        "arg_constraints": arg_constraints,
    }


def _init_progent_worker(model: str, attack: str, suite: str) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    os.environ["SECAGENT_SUITE"] = suite
    os.environ["SECAGENT_GENERATE"] = "False"
    os.environ["SECAGENT_POLICY_MODEL"] = model

    sys.path.insert(0, str(PROGENT_ROOT))
    sys.path.insert(0, str(PROGENT_AGENTDOJO_SRC))
    sys.path.insert(0, str(SCRIPT_DIR))

    with open(os.devnull, "w") as devnull, contextlib.redirect_stderr(devnull):
        import secagent.tool as stool  # type: ignore
        from eval_system_real import _extract_real_calls, _load_trustfncall_task_runs

        stool.available_tools = []
        stool.security_policy = None
        stool.init_user_query = ""

        suite_path = PROGENT_AGENTDOJO_SRC / "agentdojo" / "default_suites" / "v1" / suite / "task_suite.py"
        module_name = f"progent_worker_suite_{suite}"
        if module_name in sys.modules:
            del sys.modules[module_name]
        spec = importlib.util.spec_from_file_location(module_name, suite_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load Progent suite file: {suite_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        baseline_rows = _load_trustfncall_task_runs(
            model=model,
            attack=attack,
            config="baseline",
            suites=[suite],
        )
        items: list[dict[str, Any]] = []
        for (suite_name, _user_task_id), row in sorted(baseline_rows.items()):
            if suite_name != suite:
                continue
            items.extend(_extract_real_calls(row["payload"]))

        unique_tool_count = len({tool.get("name") for tool in stool.available_tools})
        policy_entries = sum(len(v) for v in (stool.security_policy or {}).values())

        def fn(item: dict[str, Any]) -> None:
            try:
                stool.check_tool_call(item["function"], item["args"])
            except Exception:
                pass

        return fn, items, {
            "suite": suite,
            "items": len(items),
            "available_tools": unique_tool_count,
            "policy_entries": policy_entries,
        }


def _init_worker_state(method_key: str, model: str, attack: str, worker_idx: int) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    suite = _suite_for_worker(worker_idx)
    cache_key = (method_key, model, attack, suite)
    cached = _PRELOADED_STATES.get(cache_key)
    if cached is not None:
        return cached
    if method_key == "repeat_user_prompt":
        state = _init_repeat_worker(model, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "spotlighting_with_delimiting":
        state = _init_spotlighting_worker(model, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "transformers_pi_detector":
        state = _init_pi_detector_worker(model, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "tool_filter":
        state = _init_tool_filter_worker(model, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "trustfncall_trace_args":
        state = _init_trustfncall_worker("trustfncall_trace_args", model, attack, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "trustfncall_manual":
        state = _init_trustfncall_worker("trustfncall_manual", model, attack, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    if method_key == "progent_manual_check_tool_call":
        state = _init_progent_worker(model, attack, suite)
        _PRELOADED_STATES[cache_key] = state
        return state
    raise ValueError(f"Unsupported method: {method_key}")


def preload_worker_states(
    method_keys: list[str],
    *,
    model: str,
    attack: str,
    suites: list[str] | None = None,
) -> None:
    suites = suites or list(CURRENT_SUITES)
    for method_key in method_keys:
        for suite in suites:
            cache_key = (method_key, model, attack, suite)
            if cache_key in _PRELOADED_STATES:
                continue
            worker_idx = CURRENT_SUITES.index(suite)
            _init_worker_state(method_key, model, attack, worker_idx)


def clear_preloaded_states(method_keys: list[str] | None = None) -> None:
    if method_keys is None:
        _PRELOADED_STATES.clear()
        return
    doomed = [key for key in _PRELOADED_STATES if key[0] in set(method_keys)]
    for key in doomed:
        _PRELOADED_STATES.pop(key, None)


def _worker_entry(
    method_key: str,
    model: str,
    attack: str,
    worker_idx: int,
    start_event: Any,
    stop_event: Any,
    queue: Any,
    sample_limit: int,
    warmup_calls: int,
) -> None:
    try:
        rng = random.Random(1000 + worker_idx)
        fn, items, meta = _init_worker_state(method_key, model, attack, worker_idx)
        if not items:
            queue.put({"kind": "error", "worker_idx": worker_idx, "error": f"No items for {method_key} worker {worker_idx}"})
            return

        for idx in range(min(warmup_calls, len(items))):
            fn(items[idx])

        queue.put({"kind": "ready", "worker_idx": worker_idx, "meta": meta})
        start_event.wait()

        latencies_us: list[float] = []
        count = 0
        idx = worker_idx % len(items)
        while not stop_event.is_set():
            item = items[idx]
            idx += 1
            if idx >= len(items):
                idx = 0
            t0 = time.perf_counter_ns()
            fn(item)
            t1 = time.perf_counter_ns()
            count += 1
            _reservoir_add(
                latencies_us,
                (t1 - t0) / 1000.0,
                seen=count,
                limit=sample_limit,
                rng=rng,
            )

        queue.put({
            "kind": "result",
            "worker_idx": worker_idx,
            "count": count,
            "latency_sample_us": latencies_us,
            "meta": meta,
        })
    except Exception as exc:
        queue.put({"kind": "error", "worker_idx": worker_idx, "error": repr(exc)})


def _run_point(
    method_key: str,
    *,
    model: str,
    attack: str,
    workers: int,
    duration_sec: float,
    sample_limit: int,
    warmup_calls: int,
) -> dict[str, Any]:
    ctx = mp.get_context("fork")
    start_event = ctx.Event()
    stop_event = ctx.Event()
    queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=_worker_entry,
            args=(method_key, model, attack, worker_idx, start_event, stop_event, queue, sample_limit, warmup_calls),
        )
        for worker_idx in range(workers)
    ]

    for proc in procs:
        proc.start()

    ready = 0
    metas = []
    while ready < workers:
        msg = queue.get()
        if msg.get("kind") == "ready":
            ready += 1
            metas.append(msg.get("meta") or {})
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

    results = []
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

    latencies = []
    total_count = 0
    for row in results:
        total_count += int(row["count"])
        latencies.extend(float(x) for x in row.get("latency_sample_us") or [])

    throughput = total_count / elapsed_sec
    return {
        "workers": workers,
        "duration_sec": round(elapsed_sec, 3),
        "completed_ops": total_count,
        "throughput_ops_per_sec": round(throughput, 3),
        "latency_us": _summary(latencies),
        "worker_meta": metas,
    }


def _plot_throughput(results: dict[str, Any]) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for key, meta in _method_meta().items():
        row = results["methods"].get(key)
        if not row or not row.get("available"):
            continue
        points = row.get("points") or []
        x = [p["workers"] for p in points]
        y = [p["throughput_ops_per_sec"] for p in points]
        ax.plot(x, y, marker="o", linewidth=1.2, markersize=3, color=meta["color"], label=meta["label"])
    ax.set_xticks(results.get("worker_counts") or [])
    ax.set_xlabel("Workers")
    ax.set_ylabel("Achieved throughput (ops/s)")
    ax.set_yscale("log")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / "fig_hook_worker_load_throughput.pdf", dpi=300, bbox_inches="tight")
    plt.close(fig)


def _plot_latency(results: dict[str, Any]) -> None:
    fig, ax = plt.subplots(figsize=(5.4, 3.0))
    for key, meta in _method_meta().items():
        row = results["methods"].get(key)
        if not row or not row.get("available"):
            continue
        points = row.get("points") or []
        x = [p["workers"] for p in points]
        y = [p["latency_us"]["p95"] for p in points if (p.get("latency_us") or {}).get("p95") is not None]
        x = [p["workers"] for p in points if (p.get("latency_us") or {}).get("p95") is not None]
        if not x:
            continue
        ax.plot(x, y, marker="o", linewidth=1.2, markersize=3, color=meta["color"], label=meta["label"])
    ax.set_xticks(results.get("worker_counts") or [])
    ax.set_xlabel("Workers")
    ax.set_ylabel("Observed p95 latency (μs)")
    ax.set_yscale("log")
    ax.legend(fontsize=6, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUTDIR / "fig_hook_worker_load_latency.pdf", dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Real offline worker-count load benchmark for defense hooks")
    parser.add_argument("--model", default=CURRENT_MODEL)
    parser.add_argument("--attack", default=CURRENT_ATTACK)
    parser.add_argument("--workers", default="4,8,16")
    parser.add_argument("--duration-sec", type=float, default=2.0)
    parser.add_argument("--sample-limit", type=int, default=5000)
    parser.add_argument("--warmup-calls", type=int, default=8)
    args = parser.parse_args()

    worker_counts = [int(part) for part in args.workers.split(",") if part.strip()]
    suite_count = len(CURRENT_SUITES)
    invalid = [count for count in worker_counts if count <= 0 or count % suite_count != 0]
    if invalid:
        raise SystemExit(
            f"--workers values must be positive multiples of {suite_count} so each point preserves the same suite mix; got {invalid}"
        )
    methods_out: dict[str, Any] = {}

    for method_key in _method_meta():
        points = []
        try:
            for workers in worker_counts:
                points.append(_run_point(
                    method_key,
                    model=args.model,
                    attack=args.attack,
                    workers=workers,
                    duration_sec=args.duration_sec,
                    sample_limit=args.sample_limit,
                    warmup_calls=args.warmup_calls,
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

    result = {
        "schema_version": "system_hook_worker_load_v1",
        "model": args.model,
        "attack": args.attack,
        "worker_counts": worker_counts,
        "duration_sec_per_point": args.duration_sec,
        "sample_limit_per_worker": args.sample_limit,
        "methods": methods_out,
        "notes": [
            "These figures are real offline closed-loop worker-count benchmarks on cached real AgentDojo artifacts.",
            "Each worker initializes the actual local hook, waits on a start barrier, then executes until the stop signal.",
            "Worker counts are balanced across the four AgentDojo suites so every point preserves the same suite mix.",
            "No remote LLM/API latency is included; Tool Filter remains local request-prep only, and MELON is excluded.",
            "Observed p95 latency is estimated from per-worker reservoir samples collected during the load run.",
        ],
    }

    out_json = OUTDIR / f"hook_worker_load_eval_{args.model}_{args.attack}.json"
    out_json.write_text(json.dumps(result, indent=2))
    _plot_throughput(result)
    _plot_latency(result)
    print(f"Saved {out_json}")


if __name__ == "__main__":
    main()
