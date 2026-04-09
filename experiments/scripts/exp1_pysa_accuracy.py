"""Experiment 1: Static Analysis Capability Classification Accuracy.

Compares three methods of deriving tool capabilities:
  1. Pysa taint-flow analysis (our approach)
  2. KeywordToolAnalyzer (description-based baseline)
  3. Human ground truth (oracle)

Metrics per method × per capability category:
  - Precision: of tools labeled X by method, fraction truly X
  - Recall: of tools truly X, fraction found by method
  - F1: harmonic mean
  - Mismatch rate: tools where method disagrees with ground truth

Outputs:
  - data/exp1_accuracy.json          Raw metrics
  - figures/exp1_accuracy_table.tex  LaTeX table for paper
  - stdout: human-readable report

Usage: python experiments/scripts/exp1_pysa_accuracy.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent / "src"))
sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))

from mcp.server.authorization import KeywordToolAnalyzer, ToolCapability as TC

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

PYSA_PATH = ROOT / "pysa_agentdojo_results.json"
pysa_raw: dict[str, list[str]] = json.loads(PYSA_PATH.read_text())

CAP_MAP = {c.value: c for c in TC}
pysa_caps: dict[str, set[TC]] = {
    tool: {CAP_MAP[c] for c in caps if c in CAP_MAP} for tool, caps in pysa_raw.items()
}

# ---------------------------------------------------------------------------
# Get tool descriptions from AgentDojo
# ---------------------------------------------------------------------------

from agentdojo.task_suite.load_suites import _SUITES  # noqa: E402

tool_descriptions: dict[str, str] = {}
for suite in _SUITES["v1"].values():
    for t in suite.tools:
        if t.name not in tool_descriptions:
            tool_descriptions[t.name] = t.description or t.name

# Run keyword analyzer on all tools
analyzer = KeywordToolAnalyzer()
keyword_caps: dict[str, set[TC]] = {}
for tool_name, desc in tool_descriptions.items():
    keyword_caps[tool_name] = analyzer.analyze(tool_name, desc)

# ---------------------------------------------------------------------------
# Human ground truth (from exp2 file — re-declare here for standalone use)
# ---------------------------------------------------------------------------

GT: dict[str, set[TC]] = {
    "get_iban": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "send_money": {TC.VALUE_TRANSFER},
    "schedule_transaction": {TC.VALUE_TRANSFER, TC.WRITE_MUTATE},
    "update_scheduled_transaction": {TC.WRITE_MUTATE, TC.VALUE_TRANSFER},
    "get_balance": {TC.READ_PRIVATE},
    "get_most_recent_transactions": {TC.READ_PRIVATE},
    "get_scheduled_transactions": {TC.READ_PRIVATE},
    "read_file": {TC.READ_PRIVATE},
    "get_user_info": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "update_password": {TC.CREDENTIAL_ACCESS, TC.WRITE_MUTATE},
    "update_user_info": {TC.WRITE_MUTATE, TC.READ_IDENTITY},
    "send_email": {TC.CROSS_BOUNDARY_EGRESS},
    "delete_email": {TC.DATA_DESTRUCTION},
    "get_unread_emails": {TC.READ_PRIVATE},
    "get_sent_emails": {TC.READ_PRIVATE},
    "get_received_emails": {TC.READ_PRIVATE},
    "get_draft_emails": {TC.READ_PRIVATE},
    "search_emails": {TC.READ_PRIVATE},
    "search_contacts_by_name": {TC.READ_PRIVATE},
    "search_contacts_by_email": {TC.READ_PRIVATE},
    "get_current_day": {TC.READ_PUBLIC},
    "search_calendar_events": {TC.READ_PRIVATE},
    "get_day_calendar_events": {TC.READ_PRIVATE},
    "create_calendar_event": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    "cancel_calendar_event": {TC.DATA_DESTRUCTION, TC.CROSS_BOUNDARY_EGRESS},
    "reschedule_calendar_event": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    "add_calendar_event_participants": {TC.WRITE_MUTATE, TC.CROSS_BOUNDARY_EGRESS},
    "append_to_file": {TC.WRITE_MUTATE},
    "search_files_by_filename": {TC.READ_PRIVATE},
    "create_file": {TC.WRITE_MUTATE},
    "delete_file": {TC.DATA_DESTRUCTION},
    "get_file_by_id": {TC.READ_PRIVATE},
    "list_files": {TC.READ_PRIVATE},
    "share_file": {TC.CROSS_BOUNDARY_EGRESS, TC.IDENTITY_ADMIN},
    "search_files": {TC.READ_PRIVATE},
    "get_channels": {TC.READ_PRIVATE},
    "add_user_to_channel": {TC.WRITE_MUTATE, TC.IDENTITY_ADMIN},
    "read_channel_messages": {TC.READ_PRIVATE},
    "read_inbox": {TC.READ_PRIVATE},
    "send_direct_message": {TC.CROSS_BOUNDARY_EGRESS},
    "send_channel_message": {TC.CROSS_BOUNDARY_EGRESS},
    "get_users_in_channel": {TC.READ_PRIVATE},
    "invite_user_to_slack": {TC.IDENTITY_ADMIN},
    "remove_user_from_slack": {TC.IDENTITY_ADMIN, TC.DATA_DESTRUCTION},
    "get_webpage": {TC.EXTERNAL_INGESTION},
    "post_webpage": {TC.CROSS_BOUNDARY_EGRESS, TC.WRITE_MUTATE},
    "get_user_information": {TC.READ_PRIVATE, TC.READ_IDENTITY},
    "get_all_hotels_in_city": {TC.READ_PUBLIC},
    "get_hotels_prices": {TC.READ_PUBLIC},
    "get_hotels_address": {TC.READ_PUBLIC},
    "get_rating_reviews_for_hotels": {TC.READ_PUBLIC},
    "get_all_restaurants_in_city": {TC.READ_PUBLIC},
    "get_restaurants_address": {TC.READ_PUBLIC},
    "get_rating_reviews_for_restaurants": {TC.READ_PUBLIC},
    "get_cuisine_type_for_restaurants": {TC.READ_PUBLIC},
    "get_dietary_restrictions_for_all_restaurants": {TC.READ_PUBLIC},
    "get_contact_information_for_restaurants": {TC.READ_PUBLIC},
    "get_price_for_restaurants": {TC.READ_PUBLIC},
    "check_restaurant_opening_hours": {TC.READ_PUBLIC},
    "get_all_car_rental_companies_in_city": {TC.READ_PUBLIC},
    "get_car_types_available": {TC.READ_PUBLIC},
    "get_rating_reviews_for_car_rental": {TC.READ_PUBLIC},
    "get_car_fuel_options": {TC.READ_PUBLIC},
    "get_car_rental_address": {TC.READ_PUBLIC},
    "get_car_price_per_day": {TC.READ_PUBLIC},
    "reserve_hotel": {TC.VALUE_TRANSFER},
    "reserve_restaurant": {TC.VALUE_TRANSFER},
    "reserve_car_rental": {TC.VALUE_TRANSFER},
    "get_flight_information": {TC.READ_PUBLIC},
    "download_file": {TC.EXTERNAL_INGESTION, TC.WRITE_MUTATE},
    "standardize_url": set(),
    "next_id": {TC.READ_PRIVATE},
    "set_balance": {TC.WRITE_MUTATE},
    "set_iban": {TC.WRITE_MUTATE},
}

# All tools present in any of the three sources
ALL_TOOLS = sorted(set(GT.keys()) | set(pysa_caps.keys()) | set(keyword_caps.keys()))
CATEGORIES = sorted(TC, key=lambda c: c.value)

# ---------------------------------------------------------------------------
# Compute per-category precision / recall / F1
# ---------------------------------------------------------------------------


def compute_metrics(predicted: dict[str, set[TC]], ground_truth: dict[str, set[TC]], tools: list[str]):
    """Compute per-category and macro-average P/R/F1."""
    results: dict[str, dict[str, float]] = {}

    for cat in CATEGORIES:
        tp = fp = fn = 0
        for tool in tools:
            pred_has = cat in predicted.get(tool, set())
            gt_has = cat in ground_truth.get(tool, set())
            if pred_has and gt_has:
                tp += 1
            elif pred_has and not gt_has:
                fp += 1
            elif not pred_has and gt_has:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        results[cat.value] = {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn,
            "support": tp + fn,  # number of tools truly in this category
        }

    # Macro average (only over categories with support > 0)
    cats_with_support = [c for c in CATEGORIES if results[c.value]["support"] > 0]
    macro_p = sum(results[c.value]["precision"] for c in cats_with_support) / len(cats_with_support)
    macro_r = sum(results[c.value]["recall"] for c in cats_with_support) / len(cats_with_support)
    macro_f1 = sum(results[c.value]["f1"] for c in cats_with_support) / len(cats_with_support)

    results["macro_avg"] = {
        "precision": round(macro_p, 3),
        "recall": round(macro_r, 3),
        "f1": round(macro_f1, 3),
        "categories_with_support": len(cats_with_support),
    }

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    tools = ALL_TOOLS
    print(f"Evaluating {len(tools)} tools across {len(CATEGORIES)} categories")
    print()

    pysa_metrics = compute_metrics(pysa_caps, GT, tools)
    keyword_metrics = compute_metrics(keyword_caps, GT, tools)

    # Print comparison table
    print(f"{'Category':<28s} {'Pysa P/R/F1':>20s}   {'Keyword P/R/F1':>20s}   {'Support':>7s}")
    print("-" * 85)
    for cat in CATEGORIES:
        cv = cat.value
        pm = pysa_metrics[cv]
        km = keyword_metrics[cv]
        sup = pm["support"]
        if sup == 0:
            continue
        print(f"{cv:<28s} {pm['precision']:.2f}/{pm['recall']:.2f}/{pm['f1']:.2f}   "
              f"  {km['precision']:.2f}/{km['recall']:.2f}/{km['f1']:.2f}      {sup:>3d}")

    pm = pysa_metrics["macro_avg"]
    km = keyword_metrics["macro_avg"]
    print("-" * 85)
    print(f"{'Macro Average':<28s} {pm['precision']:.2f}/{pm['recall']:.2f}/{pm['f1']:.2f}   "
          f"  {km['precision']:.2f}/{km['recall']:.2f}/{km['f1']:.2f}")

    # Mismatch analysis
    print()
    print("=" * 85)
    print("MISMATCH ANALYSIS: tools where Pysa ≠ Keyword (motivates static analysis)")
    print("=" * 85)
    mismatches = 0
    for tool in sorted(tool_descriptions.keys()):
        p = pysa_caps.get(tool, set())
        k = keyword_caps.get(tool, set())
        if p != k:
            mismatches += 1
            p_str = ",".join(sorted(c.value for c in p)) if p else "(none)"
            k_str = ",".join(sorted(c.value for c in k)) if k else "(none)"
            only_pysa = p - k
            only_keyword = k - p
            if only_pysa or only_keyword:
                print(f"  {tool:35s}  pysa={p_str}")
                print(f"  {'':35s}  keyword={k_str}")
                if only_pysa:
                    print(f"  {'':35s}  Pysa found (keyword missed): {','.join(c.value for c in only_pysa)}")
                if only_keyword:
                    print(f"  {'':35s}  Keyword claimed (Pysa denied): {','.join(c.value for c in only_keyword)}")
                print()

    print(f"Total tools with Pysa≠Keyword: {mismatches}/{len(tool_descriptions)}")

    # Save data
    output = {
        "n_tools": len(tools),
        "n_categories": len(CATEGORIES),
        "pysa": pysa_metrics,
        "keyword": keyword_metrics,
        "mismatch_count": mismatches,
    }
    data_path = ROOT / "data" / "exp1_accuracy.json"
    data_path.write_text(json.dumps(output, indent=2))
    print(f"\nSaved to {data_path}")

    # Save ground truth + pysa + keyword as standalone files
    (ROOT / "data" / "ground_truth.json").write_text(
        json.dumps({t: sorted(c.value for c in cs) for t, cs in GT.items()}, indent=2))
    (ROOT / "data" / "pysa_capabilities.json").write_text(
        json.dumps({t: sorted(c.value for c in cs) for t, cs in pysa_caps.items()}, indent=2))
    (ROOT / "data" / "keyword_capabilities.json").write_text(
        json.dumps({t: sorted(c.value for c in cs) for t, cs in keyword_caps.items()}, indent=2))


if __name__ == "__main__":
    main()
