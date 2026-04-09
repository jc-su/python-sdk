"""Aggregate AgentDojo v2 shard files into one final result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
import sys

sys.path.insert(0, str(SCRIPT_DIR))

from run_agentdojo_v2 import compute_metrics  # noqa: E402


def _combined_goal_asr(attacked_by_attack: dict[str, list[dict[str, Any]]]) -> float:
    grouped: dict[tuple[str, str, str], bool] = {}
    for attack_name, cases in attacked_by_attack.items():
        for case in cases:
            key = (case["suite"], case["user_task"], case["injection_task"])
            grouped[key] = grouped.get(key, False) or case["attack_succeeded"]
    if not grouped:
        return 0.0
    return sum(1 for ok in grouped.values() if ok) / len(grouped) * 100.0


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate AgentDojo v2 shards")
    parser.add_argument("--pattern", default="agentdojo_matrix_v2_*.json")
    parser.add_argument("--output", default=str(ROOT / "data" / "agentdojo_matrix_v2_aggregated.json"))
    args = parser.parse_args()

    files = sorted((ROOT / "data").glob(args.pattern))
    complete_files = []
    for path in files:
        data = _load(path)
        if data.get("partial") is False:
            complete_files.append((path, data))

    by_config: dict[str, dict[str, Any]] = {}
    meta_model = None
    meta_attacks = None

    for path, data in complete_files:
        meta_model = data.get("model", meta_model)
        meta_attacks = data.get("attacks", meta_attacks)
        for result in data.get("results", []):
            config = result["config"]
            bucket = by_config.setdefault(
                config,
                {
                    "config": config,
                    "use_defense": result.get("use_defense"),
                    "use_args": result.get("use_args"),
                    "policy_scope": result.get("policy_scope"),
                    "benign": [],
                    "attacked_by_attack": {},
                    "source_files": [],
                },
            )
            bucket["source_files"].append(str(path))
            overall = result["overall"]
            bucket["benign"].extend(overall.get("benign_no_attack", []))
            for attack_name, attack_metrics in result.get("per_attack", {}).items():
                bucket["attacked_by_attack"].setdefault(attack_name, []).extend(attack_metrics.get("attacked", []))

    aggregated_results = []
    for config, bucket in sorted(by_config.items()):
        per_attack = {}
        attacked_all = []
        for attack_name, attacked in sorted(bucket["attacked_by_attack"].items()):
            attacked_all.extend(attacked)
            per_attack[attack_name] = compute_metrics(attacked=attacked, benign=bucket["benign"], label=f"{config} {attack_name}")

        overall = compute_metrics(attacked=attacked_all, benign=bucket["benign"], label=f"{config} aggregated")
        overall["combined_goal_ASR"] = round(_combined_goal_asr(bucket["attacked_by_attack"]), 1)
        overall["attack_types"] = sorted(bucket["attacked_by_attack"].keys())
        aggregated_results.append(
            {
                "config": config,
                "use_defense": bucket["use_defense"],
                "use_args": bucket["use_args"],
                "policy_scope": bucket["policy_scope"],
                "source_files": sorted(set(bucket["source_files"])),
                "per_attack": per_attack,
                "overall": overall,
            }
        )

    payload = {
        "schema_version": "agentdojo_matrix_v1_aggregated",
        "model": meta_model,
        "attacks": meta_attacks,
        "results": aggregated_results,
    }
    out = Path(args.output)
    out.write_text(json.dumps(payload, indent=2, default=str))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
