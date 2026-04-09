"""Run AgentDojo v2 matrix in suite-level shards and resume cleanly.

Each shard is one `(config, suite-set)` invocation of `run_agentdojo_v2_matrix.py`.
This keeps runs restartable and produces stable per-shard JSON files that can be
aggregated later.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = Path(__file__).resolve().parent / "run_agentdojo_v2_matrix.py"
sys.path.insert(0, str(ROOT.parent.parent / "agentdojo" / "src"))

from agentdojo.task_suite.load_suites import _SUITES  # noqa: E402


def _slug(parts: list[str]) -> str:
    return "__".join(part.replace("/", "_") for part in parts if part)


def expected_output(model: str, attacks: list[str], config: str, suites: list[str], user_tasks: list[str]) -> Path:
    attack_tag = "-".join(attacks)
    suites_tag = _slug(suites)
    configs_tag = _slug([config])
    tasks_tag = _slug(user_tasks) if user_tasks else "all_tasks"
    return ROOT / "data" / f"agentdojo_matrix_v2_{model}_{attack_tag}__{configs_tag}__{suites_tag}__{tasks_tag}.json"


def is_complete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except Exception:
        return False
    return data.get("partial") is False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AgentDojo v2 in suite shards")
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--attacks", nargs="+", default=["important_instructions"])
    parser.add_argument("--configs", nargs="+", default=["baseline", "trustfncall_suite", "trustfncall_suite_args"])
    parser.add_argument("--suites", nargs="+", default=["banking", "workspace", "slack", "travel"])
    parser.add_argument("--tasks-per-shard", type=int, default=1)
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--no-resume", dest="resume", action="store_false")
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    for config in args.configs:
        for suite in args.suites:
            task_ids = list(_SUITES["v1"][suite].user_tasks.keys())
            for start in range(0, len(task_ids), args.tasks_per_shard):
                shard_tasks = task_ids[start : start + args.tasks_per_shard]
                out = expected_output(args.model, list(args.attacks), config, [suite], shard_tasks)
                if args.resume and is_complete(out):
                    print(f"SKIP complete shard: {out.name}")
                    continue

                cmd = [
                    sys.executable,
                    str(SCRIPT),
                    "--model",
                    args.model,
                    "--configs",
                    config,
                    "--suites",
                    suite,
                    "--user-tasks",
                    *shard_tasks,
                    "--attacks",
                    *args.attacks,
                ]
                print(f"RUN {config} {suite} tasks={','.join(shard_tasks)}")
                subprocess.run(cmd, cwd=ROOT.parent, check=True)


if __name__ == "__main__":
    main()
