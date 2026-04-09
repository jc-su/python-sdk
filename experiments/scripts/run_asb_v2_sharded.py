"""Run ASB v2 in agent shards and resume cleanly."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
ASB_ROOT = ROOT.parent.parent / "ASB"
SCRIPT = Path(__file__).resolve().parent / "run_asb_v2.py"


def _slug(parts: list[str]) -> str:
    return "__".join(part.replace("/", "_") for part in parts if part)


def expected_output(llm_name: str, tag: str, attack_tool_set: str, attack_types: list[str], agents: list[str]) -> Path:
    attack_tag = _slug(attack_types)
    agents_tag = _slug(agents) if agents else "all_agents"
    return ROOT / "data" / f"asb_real_v2_{tag}_{llm_name}__{attack_tool_set}__{attack_tag}__{agents_tag}.json"


def is_complete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except Exception:
        return False
    return data.get("partial") is False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ASB v2 in agent shards")
    parser.add_argument("--llm-name", default="gpt-4o-mini")
    parser.add_argument("--attack-tool-set", choices=["all", "agg", "non-agg", "test"], default="all")
    parser.add_argument("--task-num", type=int, default=1)
    parser.add_argument("--attack-types", nargs="+", default=["naive"])
    parser.add_argument("--configs", nargs="+", default=["baseline", "trustfncall"])
    parser.add_argument("--agents", nargs="+", default=None)
    parser.add_argument("--split-attack-types", action="store_true")
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--no-resume", dest="resume", action="store_false")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    if args.agents is None:
        tasks_df = pd.read_json(ASB_ROOT / "data" / "agent_task.jsonl", lines=True)
        agents = list(tasks_df["agent_name"])
    else:
        agents = list(args.agents)

    attack_type_groups = [[attack_type] for attack_type in args.attack_types] if args.split_attack_types else [list(args.attack_types)]

    for config in args.configs:
        tag = "baseline" if config == "baseline" else "trustfncall"
        for attack_types in attack_type_groups:
            for agent in agents:
                out = expected_output(args.llm_name, tag, args.attack_tool_set, list(attack_types), [agent])
                if args.resume and is_complete(out):
                    print(f"SKIP complete shard: {out.name}")
                    continue

                cmd = [
                    sys.executable,
                    str(SCRIPT),
                    "--llm-name",
                    args.llm_name,
                    "--attack-tool-set",
                    args.attack_tool_set,
                    "--task-num",
                    str(args.task_num),
                    "--attack-types",
                    *attack_types,
                    "--agents",
                    agent,
                ]
                if config == "baseline":
                    cmd.append("--no-defense")
                print(f"RUN {config} {agent} attacks={','.join(attack_types)}")
                subprocess.run(cmd, cwd=ROOT.parent, check=True)


if __name__ == "__main__":
    main()
