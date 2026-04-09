"""Aggregate ASB v2 shard files into one final result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
import sys

sys.path.insert(0, str(SCRIPT_DIR))

from run_asb_v2 import aggregate_metrics  # noqa: E402


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _clean_key(case: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    return (
        case.get("agent_name"),
        case.get("agent_path"),
        case.get("task"),
    )


def _attacked_key(attack_name: str, case: dict[str, Any]) -> tuple[str | None, str | None, str | None, str | None]:
    return (
        attack_name,
        case.get("agent_name"),
        case.get("task"),
        case.get("attack_tool"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate ASB v2 shards")
    parser.add_argument("--pattern", default="asb_real_v2_*.json")
    parser.add_argument("--output", default=str(ROOT / "data" / "asb_real_v2_aggregated.json"))
    args = parser.parse_args()

    files = sorted((ROOT / "data").glob(args.pattern))
    complete_files = []
    for path in files:
        data = _load(path)
        if data.get("schema_version") == "asb_v2_aggregated":
            continue
        if data.get("partial") is not True:
            complete_files.append((path, data))

    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path, data in complete_files:
        config = "trustfncall" if data.get("use_defense") else "baseline"
        llm_name = data.get("llm_name")
        attack_tool_set = data.get("attack_tool_set")
        key = (config, llm_name, attack_tool_set)
        bucket = buckets.setdefault(
            key,
            {
                "config": config,
                "llm_name": llm_name,
                "attack_tool_set": attack_tool_set,
                "attack_types": set(),
                "agents": set(),
                "attacked": {},
                "clean": {},
                "source_files": [],
            },
        )
        bucket["source_files"].append(str(path))
        bucket["attack_types"].update(data.get("attack_types", []))
        bucket["agents"].update(data.get("agents") or [])
        for attack_name, cases in data.get("attacked", {}).items():
            attack_bucket = bucket["attacked"].setdefault(attack_name, {})
            for case in cases:
                attack_bucket[_attacked_key(attack_name, case)] = case
        for case in data.get("clean", []):
            bucket["clean"][_clean_key(case)] = case

    results = []
    def _sort_key(item: tuple[tuple[str | None, str | None, str | None], dict[str, Any]]) -> tuple[str, str, str]:
        config, llm_name, attack_tool_set = item[0]
        return (str(config), str(llm_name), str(attack_tool_set))

    for (_config, _llm_name, _attack_tool_set), bucket in sorted(buckets.items(), key=_sort_key):
        attacked = {
            attack_name: list(cases.values())
            for attack_name, cases in sorted(bucket["attacked"].items())
        }
        clean = list(bucket["clean"].values())
        summary = aggregate_metrics(attacked, clean)
        results.append(
            {
                "config": bucket["config"],
                "llm_name": bucket["llm_name"],
                "attack_tool_set": bucket["attack_tool_set"],
                "attack_types": sorted(bucket["attack_types"]),
                "agents": sorted(bucket["agents"]),
                "source_files": sorted(set(bucket["source_files"])),
                "summary": summary,
                "attacked": attacked,
                "clean": clean,
            }
        )

    payload = {
        "schema_version": "asb_v2_aggregated",
        "results": results,
    }
    out = Path(args.output)
    out.write_text(json.dumps(payload, indent=2, default=str))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
