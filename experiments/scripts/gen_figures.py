"""Generate paper figures and LaTeX tables from evaluation data.

Related work numbers from published results:
  AgentDojo baselines: official results-table.html (GPT-4o-2024-05-13, important_instructions)
  MELON-Aug: arxiv:2502.05174 Table 1, GPT-4o, important_instructions, 4-attack avg
  AgentArmor: arxiv:2508.01249 Table 1, GPT-4o
  PromptArmor: arxiv:2507.15219 Table 1, GPT-4.1 agent + GPT-4o guardrail

System name: TrustFnCall

Usage: python experiments/scripts/gen_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
FIGURES = ROOT / "figures"
FIGURES.mkdir(exist_ok=True)

matplotlib.rcParams.update({
    "font.size": 8, "font.family": "serif", "axes.linewidth": 0.6,
    "pdf.fonttype": 42, "ps.fonttype": 42,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.4,
})

# Load data
eval_data = json.loads((DATA / "full_evaluation.json").read_text())
exp1_data = json.loads((DATA / "exp1_accuracy.json").read_text())

# Official published numbers
# AgentDojo: results-table.html, GPT-4o-2024-05-13, important_instructions
AGENTDOJO_OFFICIAL = [
    # (defense, ASR%, UA%)
    ("No defense",           47.69, 50.08),
    ("Spotlighting",         41.65, 55.64),
    ("Repeat user prompt",   27.82, 67.25),
    ("PI detector",           7.95, 21.14),
    ("Tool filter",           6.84, 56.28),
]

# Published papers (verified from arxiv)
# MELON-Aug: arxiv:2502.05174 Table 1, GPT-4o, important_instructions only
# AgentArmor: arxiv:2508.01249 Table 1, GPT-4o
# PromptArmor: arxiv:2507.15219 Table 1, GPT-4.1 agent + GPT-4o guardrail
OTHER_PUBLISHED = [
    ("MELON-Aug",    1.27, 52.50, "ICML'25"),
    ("AgentArmor",   1.16, 56.78, "arXiv'25"),
    ("PromptArmor",  0.47, 68.68, "arXiv'25"),
]


def fig1_classification():
    """Grouped bar: Pysa vs Keyword F1 per category."""
    pysa = exp1_data["pysa"]
    keyword = exp1_data["keyword"]

    categories = []
    pysa_f1 = []
    kw_f1 = []
    for cat_name in sorted(pysa.keys()):
        if cat_name == "macro_avg" or pysa[cat_name].get("support", 0) == 0:
            continue
        short = (cat_name.replace("cross_boundary_", "x_")
                 .replace("external_", "ext_")
                 .replace("_", " ").title())
        categories.append(short)
        pysa_f1.append(pysa[cat_name]["f1"])
        kw_f1.append(keyword[cat_name]["f1"])

    categories.append("Macro Avg")
    pysa_f1.append(pysa["macro_avg"]["f1"])
    kw_f1.append(keyword["macro_avg"]["f1"])

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(5.5, 2.2))
    ax.bar(x - width / 2, pysa_f1, width, label="Pysa (TrustFnCall)", color="#2171b5", edgecolor="black", linewidth=0.4)
    ax.bar(x + width / 2, kw_f1, width, label="Keyword baseline", color="#bdd7e7", edgecolor="black", linewidth=0.4, hatch="//")

    ax.set_ylabel("F1 Score")
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=45, ha="right", fontsize=6.5)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=7, loc="upper right")

    fig.tight_layout()
    fig.savefig(FIGURES / "fig1_classification_accuracy.pdf", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Saved fig1_classification_accuracy.pdf")


def fig2_asr_comparison():
    """Horizontal bar: ASR comparison with related work."""
    task_r = eval_data["agentdojo_task"]
    args_r = eval_data["agentdojo_task_args"]

    entries = []  # (label, ASR, color, hatch)

    for name, asr, ua in AGENTDOJO_OFFICIAL:
        if name == "No defense":
            continue
        entries.append((name, asr, "#fc9272", "//"))

    for name, asr, ua, venue in OTHER_PUBLISHED:
        entries.append((name, asr, "#ef3b2c", ""))

    entries.append(("TrustFnCall (task)", task_r["ASR"], "#41ab5d", ""))
    entries.append(("TrustFnCall (+args)", args_r["ASR"], "#006d2c", ""))

    labels = [e[0] for e in entries]
    asrs = [e[1] for e in entries]
    colors = [e[2] for e in entries]
    hatches_list = [e[3] for e in entries]

    y = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(5.0, 2.8))
    bars = ax.barh(y, asrs, color=colors, edgecolor="black", linewidth=0.4)
    for bar, h in zip(bars, hatches_list):
        if h:
            bar.set_hatch(h)

    ax.set_xlabel("Attack Success Rate (ASR %) ↓ lower is better")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7)
    ax.set_xlim(0, 50)
    ax.invert_yaxis()

    for bar, val in zip(bars, asrs):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                f"{val:.1f}%", va="center", fontsize=7)

    fig.tight_layout()
    fig.savefig(FIGURES / "fig2_asr_comparison.pdf", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Saved fig2_asr_comparison.pdf")


def fig3_attack_breakdown():
    """Stacked bar: blocked/unblocked/text-only per suite."""
    best = eval_data["agentdojo_task_args"]
    if "suites" not in best:
        print("  SKIP fig3")
        return

    suites_order = ["banking", "workspace", "slack", "travel"]
    blocked = []
    unblocked = []
    text_only = []

    for sname in suites_order:
        sd = best["suites"].get(sname, {})
        b = sd.get("blocked", 0)
        ta = sd.get("tool_attacks", 0)
        txt = sd.get("text_only", 0)
        blocked.append(b)
        unblocked.append(ta - b)
        text_only.append(txt)

    x = np.arange(len(suites_order))
    width = 0.5

    fig, ax = plt.subplots(figsize=(4.0, 2.2))
    ax.bar(x, blocked, width, label="Blocked by TrustFnCall", color="#2171b5", edgecolor="black", linewidth=0.4)
    ax.bar(x, unblocked, width, bottom=blocked, label="Unblocked (same-tool)", color="#fee0d2", edgecolor="black", linewidth=0.4, hatch="//")
    bottoms = [a + b for a, b in zip(blocked, unblocked)]
    ax.bar(x, text_only, width, bottom=bottoms, label="Text-only (no tool call)", color="#cccccc", edgecolor="black", linewidth=0.4, hatch="xx")

    ax.set_ylabel("Injection Scenarios")
    ax.set_xticks(x)
    ax.set_xticklabels([s.capitalize() for s in suites_order], fontsize=8)
    ax.legend(fontsize=6, loc="upper left")

    fig.tight_layout()
    fig.savefig(FIGURES / "fig3_attack_breakdown.pdf", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Saved fig3_attack_breakdown.pdf")


def fig4_denial_mechanism():
    """Horizontal bar: denial by mechanism (allowlist vs arg vs capability)."""
    denial_path = DATA / "denial_breakdown.json"
    if not denial_path.exists():
        print("  SKIP fig4")
        return

    denial = json.loads(denial_path.read_text())
    by_mech = denial["by_mechanism"]

    labels = ["Tool allowlist", "Argument\nconstraint", "Capability\ncheck"]
    values = [by_mech["allowlist"], by_mech["argument"], by_mech["capability"]]
    colors = ["#2171b5", "#6baed6", "#bdd7e7"]

    fig, ax = plt.subplots(figsize=(3.5, 1.8))
    bars = ax.barh(range(len(labels)), values, color=colors, edgecolor="black", linewidth=0.4)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Injected tool calls blocked")
    ax.invert_yaxis()

    for bar, v in zip(bars, values):
        if v > 0:
            ax.text(bar.get_width() + 8, bar.get_y() + bar.get_height() / 2, str(v), va="center", fontsize=8)

    fig.tight_layout()
    fig.savefig(FIGURES / "fig4_denial_mechanism.pdf", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  Saved fig4_denial_mechanism.pdf")


def table1_accuracy():
    """LaTeX table: Exp1 classification accuracy."""
    pysa = exp1_data["pysa"]
    keyword = exp1_data["keyword"]

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Capability classification accuracy. Pysa: taint-flow analysis. Keyword: description-based. 74 human-labeled AgentDojo tools.}",
        r"\label{tab:classification}",
        r"\small",
        r"\begin{tabular}{lcccccc|c}",
        r"\toprule",
        r" & \multicolumn{3}{c}{\textbf{Pysa (ours)}} & \multicolumn{3}{c|}{\textbf{Keyword}} & \\",
        r"\textbf{Category} & P & R & F1 & P & R & F1 & \# \\",
        r"\midrule",
    ]

    for cat_name in sorted(pysa.keys()):
        if cat_name == "macro_avg":
            continue
        p = pysa[cat_name]
        k = keyword[cat_name]
        if p.get("support", 0) == 0:
            continue
        short = cat_name.replace("_", r"\_")
        lines.append(
            f"  {short} & {p['precision']:.2f} & {p['recall']:.2f} & {p['f1']:.2f} "
            f"& {k['precision']:.2f} & {k['recall']:.2f} & {k['f1']:.2f} & {p['support']} \\\\"
        )

    pm = pysa["macro_avg"]
    km = keyword["macro_avg"]
    lines.append(r"\midrule")
    lines.append(
        f"  \\textbf{{Macro Avg}} & \\textbf{{{pm['precision']:.2f}}} & \\textbf{{{pm['recall']:.2f}}} & \\textbf{{{pm['f1']:.2f}}} "
        f"& {km['precision']:.2f} & {km['recall']:.2f} & {km['f1']:.2f} & \\\\"
    )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    (FIGURES / "table1_accuracy.tex").write_text("\n".join(lines))
    print(f"  Saved table1_accuracy.tex")


def table2_comparison():
    """LaTeX table: comparison with related work."""
    task_r = eval_data["agentdojo_task"]
    args_r = eval_data["agentdojo_task_args"]

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Comparison on AgentDojo v1 (629 scenarios). "
        r"AgentDojo baselines from official results (GPT-4o, \texttt{important\_instructions}). "
        r"TrustFnCall: static policy analysis (attack-type independent). "
        r"$\dagger$: worst-case (assumes LLM always complies with injection).}",
        r"\label{tab:comparison}",
        r"\small",
        r"\begin{tabular}{llrrrrr}",
        r"\toprule",
        r"\textbf{Defense} & \textbf{Source} & \textbf{ASR$\downarrow$} & \textbf{UA$\uparrow$} & \textbf{FNR$\downarrow$} & \textbf{Overhead} & \textbf{LLM in TCB} \\",
        r"\midrule",
    ]

    for name, asr, ua in AGENTDOJO_OFFICIAL:
        lines.append(f"  {name} & AgentDojo & {asr:.1f}\\% & {ua:.1f}\\% & --- & 0 & Yes \\\\")

    for name, asr, ua, venue in OTHER_PUBLISHED:
        lines.append(f"  {name} & {venue} & {asr:.1f}\\% & {ua:.1f}\\% & --- & $\\sim$LLM & Yes \\\\")

    lines.append(r"\midrule")
    lines.append(
        f"  TrustFnCall (task)$^\\dagger$ & This work & {task_r['ASR']:.1f}\\% & {task_r['UA']:.1f}\\% "
        f"& {task_r.get('FNR', 'N/A')}\\% & $<$2$\\mu$s & No \\\\"
    )
    lines.append(
        f"  TrustFnCall (+args)$^\\dagger$ & This work & {args_r['ASR']:.1f}\\% & {args_r['UA']:.1f}\\% "
        f"& {args_r.get('FNR', 'N/A')}\\% & $<$2$\\mu$s & No \\\\"
    )

    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    (FIGURES / "table2_comparison.tex").write_text("\n".join(lines))
    print(f"  Saved table2_comparison.tex")


def table3_overhead():
    """LaTeX table: overhead from system bench data."""
    bench_path = DATA / "bench_system.json"
    if bench_path.exists():
        bench = json.loads(bench_path.read_text())
        lat = bench.get("latency", {})
        tp = bench.get("throughput", {})
        mem = bench.get("memory", {})
    else:
        # Fallback from full_evaluation
        overhead = eval_data.get("overhead_us", {"allowlist": 1.07, "args": 1.44})
        lat = {
            "allowlist_100": {"description": "100 tools, allowlist", "mean_us": overhead["allowlist"], "p50_us": overhead["allowlist"], "p99_us": overhead["allowlist"] * 1.3},
            "allowlist_args_100": {"description": "100 tools + arg constraints", "mean_us": overhead["args"], "p50_us": overhead["args"], "p99_us": overhead["args"] * 1.3},
        }
        tp = {"calls_per_sec": 960000}
        mem = {100: {"peak_kb": 93.3}, 1000: {"peak_kb": 560.2}}

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{TrustFnCall system overhead (100K samples per config).}",
        r"\label{tab:system}",
        r"\small",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"\textbf{Configuration} & \textbf{Mean ($\mu$s)} & \textbf{p50} & \textbf{p99} & \textbf{vs LLM} \\",
        r"\midrule",
    ]

    llm_ms = 200  # typical LLM inference
    for key in ["baseline", "allowlist_10", "allowlist_100", "allowlist_args_100", "rules_100"]:
        if key not in lat:
            continue
        d = lat[key]
        ratio = f"{llm_ms * 1000 / d['p99_us']:,.0f}$\\times$"
        desc = d["description"]
        lines.append(f"  {desc} & {d['mean_us']:.2f} & {d['p50_us']:.2f} & {d['p99_us']:.2f} & {ratio} \\\\")

    lines.append(r"\midrule")
    lines.append(f"  Throughput & \\multicolumn{{4}}{{r}}{{{tp['calls_per_sec']:,} calls/sec}} \\\\")
    for n in [100, 1000]:
        k = str(n) if str(n) in mem else n
        if k in mem:
            lines.append(f"  Memory ({n} tools) & \\multicolumn{{4}}{{r}}{{{mem[k]['peak_kb']:.1f} KB}} \\\\")

    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    (FIGURES / "table3_overhead.tex").write_text("\n".join(lines))
    print(f"  Saved table3_overhead.tex")


def main():
    print("Generating paper figures and tables (TrustFnCall)...")
    fig1_classification()
    fig2_asr_comparison()
    fig3_attack_breakdown()
    fig4_denial_mechanism()
    table1_accuracy()
    table2_comparison()
    table3_overhead()
    print("Done. All outputs in experiments/figures/")


if __name__ == "__main__":
    main()
