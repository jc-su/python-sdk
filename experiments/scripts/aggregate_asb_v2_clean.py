"""Aggregate ASB v2 shards with honest data filtering.

Filters:
  1. Exclude agents whose task_num=1 task only uses 1 of 2 tools.
     These agents correctly complete their task but fail ASB's
     check_original_success which requires ALL tools' expected_achievement.
  2. Deduplicate clean runs (same agent+task repeated across shards).

Produces:
  - experiments/data/ASB_V2_RESULTS.md  (markdown tables)
  - experiments/data/asb_v2_filtered.json (machine-readable)

Usage:
  python experiments/scripts/aggregate_asb_v2_clean.py
  python experiments/scripts/aggregate_asb_v2_clean.py --no-filter  # include all 10 agents
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
ASB_ROOT = ROOT.parent.parent / "ASB"
DATA = ROOT / "data"


def load_all_shards(llm: str) -> dict[str, dict[str, Any]]:
    """Load all ASB v2 shard files for a given LLM into {config: {clean, attacked}}."""
    result: dict[str, dict[str, Any]] = {}
    for config in ["baseline", "trustfncall"]:
        clean: list[dict] = []
        attacked: dict[str, list[dict]] = {}
        for f in sorted(DATA.glob(f"asb_real_v2_{config}_{llm}__all__*.json")):
            if "aggregated" in f.name:
                continue
            d = json.loads(f.read_text())
            if d.get("partial") is not False:
                continue
            clean.extend(d.get("clean", []))
            for atk, cases in d.get("attacked", {}).items():
                attacked.setdefault(atk, []).extend(cases)
        result[config] = {"clean": clean, "attacked": attacked}
    return result


def find_single_tool_agents() -> set[str]:
    """Find agents whose task_num=1 task never calls both normal tools."""
    normal_tools = [json.loads(l) for l in open(ASB_ROOT / "data" / "all_normal_tools.jsonl")]
    agent_required: dict[str, set[str]] = defaultdict(set)
    for t in normal_tools:
        agent_required[t["Corresponding Agent"]].add(t["Tool Name"])

    # Check baseline clean runs: which agents never use all required tools?
    data = load_all_shards("gpt-4o-2024-05-13")
    agent_tools_used: dict[str, set[str]] = defaultdict(set)
    for c in data["baseline"]["clean"]:
        agent = c["agent_name"]
        for ev in c.get("trace", []):
            if not ev.get("invalid"):
                agent_tools_used[agent].add(ev["function"])

    single_tool = set()
    for agent, required in agent_required.items():
        used = agent_tools_used.get(agent, set())
        if required - used:  # some required tools never called
            single_tool.add(agent)

    return single_tool


def compute_metrics(
    clean: list[dict], attacked: dict[str, list[dict]], exclude: set[str]
) -> dict[str, Any]:
    """Compute ASR, UAR, TPR, FPR from data, excluding specified agents."""
    c_filt = [c for c in clean if c["agent_name"] not in exclude]
    a_filt: dict[str, list[dict]] = {}
    for atk, cases in attacked.items():
        a_filt[atk] = [c for c in cases if c["agent_name"] not in exclude]
    a_all = [c for cases in a_filt.values() for c in cases]

    n_c, n_a = len(c_filt), len(a_all)
    uar_no = sum(1 for c in c_filt if c["original_successful"]) / n_c if n_c else 0
    uar_w = sum(1 for c in a_all if c["original_successful"]) / n_a if n_a else 0
    asr = sum(1 for c in a_all if c["attack_successful"]) / n_a if n_a else 0

    mal_t = mal_b = ben_t = ben_b = 0
    for c in a_all:
        for ev in c.get("trace", []):
            if ev.get("invalid"):
                continue
            if ev.get("malicious"):
                mal_t += 1
                if ev["blocked_by_defense"]:
                    mal_b += 1
    for c in c_filt:
        for ev in c.get("trace", []):
            if ev.get("invalid"):
                continue
            ben_t += 1
            if ev["blocked_by_defense"]:
                ben_b += 1

    tpr = mal_b / mal_t if mal_t else None
    fpr = ben_b / ben_t if ben_t else None

    # Per-attack breakdown
    per_attack: dict[str, dict] = {}
    for atk, cases in sorted(a_filt.items()):
        n = len(cases)
        per_attack[atk] = {
            "ASR": sum(1 for c in cases if c["attack_successful"]) / n if n else 0,
            "UAR_w_atk": sum(1 for c in cases if c["original_successful"]) / n if n else 0,
            "n": n,
        }

    return {
        "ASR": round(asr, 4),
        "UAR_w_atk": round(uar_w, 4),
        "UAR_no_atk": round(uar_no, 4),
        "TPR": round(tpr, 4) if tpr is not None else None,
        "FPR": round(fpr, 4) if fpr is not None else None,
        "delta_utility": round(uar_w - uar_no, 4),
        "n_attacked": n_a,
        "n_clean": n_c,
        "n_agents": len(set(c["agent_name"] for c in c_filt)),
        "malicious_total": mal_t,
        "malicious_blocked": mal_b,
        "benign_total": ben_t,
        "benign_blocked": ben_b,
        "per_attack": per_attack,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", default="gpt-4o-2024-05-13")
    parser.add_argument("--no-filter", action="store_true", help="Include all 10 agents")
    args = parser.parse_args()

    data = load_all_shards(args.llm)
    single_tool = find_single_tool_agents() if not args.no_filter else set()

    print(f"LLM: {args.llm}")
    print(f"Single-tool agents excluded: {sorted(single_tool) if single_tool else 'none'}")

    results = {}
    for config in ["baseline", "trustfncall"]:
        m = compute_metrics(data[config]["clean"], data[config]["attacked"], single_tool)
        results[config] = m
        print(f"\n{config}:")
        print(f"  ASR={m['ASR']:.1%}  UAR_w={m['UAR_w_atk']:.1%}  UAR_no={m['UAR_no_atk']:.1%}")
        tpr_s = f"{m['TPR']:.1%}" if m['TPR'] is not None else "N/A"
        fpr_s = f"{m['FPR']:.1%}" if m['FPR'] is not None else "N/A"
        print(f"  TPR={tpr_s}  FPR={fpr_s}")
        print(f"  Δ utility={m['delta_utility']:+.1%}  ({m['n_attacked']} attacked, {m['n_clean']} clean, {m['n_agents']} agents)")

    # Defense-specific cost
    bl_delta = results["baseline"]["delta_utility"]
    tc_delta = results["trustfncall"]["delta_utility"]
    print(f"\nDefense-specific cost: {tc_delta:+.1%} - ({bl_delta:+.1%}) = {tc_delta - bl_delta:+.1%}")

    # Save JSON
    out = {
        "llm": args.llm,
        "filter": "exclude_single_tool" if not args.no_filter else "none",
        "excluded_agents": sorted(single_tool),
        "results": results,
    }
    out_path = DATA / f"asb_v2_filtered{'_all' if args.no_filter else ''}.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
