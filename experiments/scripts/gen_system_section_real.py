"""Generate system-section figures and tables from real-data evaluation outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FIGURES = ROOT / "figures"
FIGURES.mkdir(exist_ok=True)

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


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def plot_enforcement_cdf(system_eval: dict[str, Any], bench: dict[str, Any]) -> None:
    fig, ax = plt.subplots(figsize=(4.4, 2.6))
    cfg = system_eval["enforcement_latency_real"]["configs"]

    series = [
        ("trustfncall_trace", "Real policy: allowlist", "#3182bd", "-"),
        ("trustfncall_trace_args", "Real policy: + arg constraints", "#08519c", "-"),
    ]
    for key, label, color, ls in series:
        raw = cfg.get(key, {}).get("authorize_latency_us", {}).get("raw")
        if not raw:
            continue
        raw = sorted(raw)
        n = len(raw)
        idx = np.linspace(0, n - 1, min(n, 3000), dtype=int)
        x = [raw[i] for i in idx]
        y = [i / n for i in idx]
        ax.plot(x, y, label=label, color=color, linewidth=1.3, linestyle=ls)

    # Optional synthetic worst-case line from bench latency data if raw exists.
    rules = bench.get("latency", {}).get("rules_100", {})
    if "raw_us" in rules:
        raw = sorted(rules["raw_us"])
        n = len(raw)
        idx = np.linspace(0, n - 1, min(n, 3000), dtype=int)
        ax.plot([raw[i] for i in idx], [i / n for i in idx], label="Synthetic worst-case: 100 rules", color="#de2d26", linewidth=1.1, linestyle="--")

    ax.set_xlabel("authorize() latency (μs)")
    ax.set_ylabel("CDF")
    ax.legend(fontsize=6, loc="lower right")
    ax.set_xlim(left=0)
    fig.tight_layout()
    path = FIGURES / "fig_system_enforcement_cdf.pdf"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {path}")


def plot_scalability(bench: dict[str, Any]) -> None:
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.0, 2.3))
    by_tools = bench["scalability"]["by_tools"]
    x = sorted(int(k) for k in by_tools.keys())
    y = [by_tools[str(k)] if str(k) in by_tools else by_tools[k] for k in x]
    ax1.plot(x, y, "o-", color="#2171b5", linewidth=1.2, markersize=3)
    ax1.set_xlabel("Number of tools")
    ax1.set_ylabel("Latency (μs)")
    ax1.set_xscale("log")

    by_rules = bench["scalability"]["by_rules"]
    x2 = sorted(int(k) for k in by_rules.keys())
    y2 = [by_rules[str(k)] if str(k) in by_rules else by_rules[k] for k in x2]
    ax2.plot(x2, y2, "s-", color="#de2d26", linewidth=1.2, markersize=3)
    ax2.set_xlabel("Number of rules")
    ax2.set_ylabel("Latency (μs)")
    ax2.set_xscale("log")

    fig.tight_layout()
    path = FIGURES / "fig_system_scalability_real.pdf"
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {path}")


def write_primary_table(bench: dict[str, Any], system_eval: dict[str, Any]) -> None:
    trace = system_eval["enforcement_latency_real"]["configs"]["trustfncall_trace"]
    trace_args = system_eval["enforcement_latency_real"]["configs"]["trustfncall_trace_args"]
    mem = bench["memory"]
    tp = bench["throughput"]
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{TrustFnCall online enforcement overhead on real AgentDojo-derived policies.}",
        r"\label{tab:system-primary}",
        r"\small",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"\textbf{Configuration} & \textbf{p50} & \textbf{p95} & \textbf{p99} & \textbf{Mean} \\",
        r" & ($\mu$s) & ($\mu$s) & ($\mu$s) & ($\mu$s) \\",
        r"\midrule",
        f"Real policy: allowlist & {trace['authorize_latency_us']['p50']:.2f} & {trace['authorize_latency_us']['p95']:.2f} & {trace['authorize_latency_us']['p99']:.2f} & {trace['authorize_latency_us']['mean']:.2f} \\\\",
        f"Real policy: + arg constraints & {trace_args['authorize_latency_us']['p50']:.2f} & {trace_args['authorize_latency_us']['p95']:.2f} & {trace_args['authorize_latency_us']['p99']:.2f} & {trace_args['authorize_latency_us']['mean']:.2f} \\\\",
        f"Synthetic worst-case (100 rules) & {bench['latency']['rules_100']['p50_us']:.2f} & {bench['latency']['rules_100']['p95_us']:.2f} & {bench['latency']['rules_100']['p99_us']:.2f} & {bench['latency']['rules_100']['mean_us']:.2f} \\\\",
        r"\midrule",
        f"Throughput & \\multicolumn{{4}}{{r}}{{{tp['calls_per_sec']:,} calls/sec}} \\\\",
        f"Memory (100 tools) & \\multicolumn{{4}}{{r}}{{{mem['100']['peak_kb']:.1f} KB}} \\\\",
        f"Memory (1000 tools) & \\multicolumn{{4}}{{r}}{{{mem['1000']['peak_kb']:.1f} KB}} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    path = FIGURES / "table_system_primary.tex"
    path.write_text("\n".join(lines))
    print(f"Saved {path}")


def write_policy_table(policy: dict[str, Any]) -> None:
    pm = policy["policy_materialization"]
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Policy-construction overhead for TrustFnCall-Trace.}",
        r"\label{tab:system-policy}",
        r"\small",
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"\textbf{Stage} & \textbf{Time} \\",
        r"\midrule",
    ]
    if "pysa_offline" in policy:
        lines.append(f"Pysa offline analysis (all AgentDojo tools) & {policy['pysa_offline']['elapsed_sec']:.2f} sec \\\\")
    lines.append(f"Policy materialization from trace (mean) & {pm['trace_policy_ms']['mean']:.3f} ms \\\\")
    lines.append(f"Policy materialization from trace (p95) & {pm['trace_policy_ms']['p95']:.3f} ms \\\\")
    proxy_block = policy.get("preflight_trace_proxy", {})
    proxy = proxy_block.get("per_scenario_elapsed_sec_proxy") or proxy_block.get("per_task_elapsed_sec_proxy")
    if proxy and proxy.get("mean") is not None:
        lines.append(f"Preflight trace collection proxy (mean scenario) & {proxy['mean']:.2f} sec \\\\")
        lines.append(f"Preflight trace collection proxy (p95 scenario) & {proxy['p95']:.2f} sec \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    path = FIGURES / "table_system_policy.tex"
    path.write_text("\n".join(lines))
    print(f"Saved {path}")


def write_end_to_end_table(system_eval: dict[str, Any]) -> None:
    methods = system_eval["end_to_end_real"]["methods"]
    rows = []
    order = [
        "trustfncall:baseline",
        "agentdojo_builtin:none",
        "agentdojo_builtin:spotlighting_with_delimiting",
        "agentdojo_builtin:repeat_user_prompt",
        "agentdojo_builtin:transformers_pi_detector",
        "agentdojo_builtin:tool_filter",
        "melon",
        "progent:manual",
        "progent:auto",
        "trustfncall:trustfncall_trace_args",
        "trustfncall:trustfncall_manual",
    ]
    for key in order:
        row = methods.get(key)
        if not row or not row.get("available"):
            continue
        metric = row.get("overall", {}).get("elapsed_sec_per_scenario")
        if metric is None:
            continue
        fair = row.get("fairness", {}).get("scenario_counts_match_reference", False)
        label = row["label"]
        rows.append((label, metric, "Yes" if fair else "No"))

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{End-to-end scenario time on real AgentDojo runs.}",
        r"\label{tab:system-end-to-end}",
        r"\small",
        r"\begin{tabular}{lrr}",
        r"\toprule",
        r"\textbf{Method} & \textbf{sec/scenario} & \textbf{Coverage Match} \\",
        r"\midrule",
    ]
    for label, metric, fair in rows:
        lines.append(f"{label} & {metric:.4f} & {fair} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    path = FIGURES / "table_system_end_to_end.tex"
    path.write_text("\n".join(lines))
    print(f"Saved {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate real-data system section figures/tables")
    parser.add_argument("--model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack", default="important_instructions")
    args = parser.parse_args()

    system_eval = _load(DATA / f"system_eval_real_{args.model}_{args.attack}.json")
    bench = _load(DATA / "bench_system.json")
    policy = _load(DATA / f"policy_construction_real_{args.model}.json")

    plot_enforcement_cdf(system_eval, bench)
    plot_scalability(bench)
    write_primary_table(bench, system_eval)
    write_policy_table(policy)
    write_end_to_end_table(system_eval)


if __name__ == "__main__":
    main()
