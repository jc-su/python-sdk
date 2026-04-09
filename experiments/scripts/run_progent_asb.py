"""Run Progent on its ASB tree and normalize CSV outputs.

This wrapper drives Progent's ASB `main_attacker.py` directly, once per attack
type and once for clean runs, then parses the emitted CSVs into a normalized
JSON summary.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
PROGENT_ROOT = ROOT.parent.parent / "progent"
PROGENT_ASB_ROOT = PROGENT_ROOT / "asb"

DEFAULT_ATTACK_TYPES = [
    "combined_attack",
    "context_ignoring",
    "fake_completion",
    "escape_characters",
    "naive",
]


def _to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _csv_complete(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    try:
        with path.open(newline="") as f:
            rows = list(csv.DictReader(f))
    except Exception:
        return False
    return len(rows) > 0


def _run_csv_job(
    *,
    llm_name: str,
    use_backend: str | None,
    attack_type: str,
    res_file: Path,
    mode: str,
    policy_model: str,
    attack_tool_set: str,
    task_num: int,
    clean: bool,
) -> list[dict[str, str]]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{PROGENT_ROOT}:{PROGENT_ASB_ROOT}:{env.get('PYTHONPATH', '')}".rstrip(":")
    env["SECAGENT_GENERATE"] = "True" if mode == "auto" else "False"
    env["SECAGENT_POLICY_MODEL"] = policy_model

    attacker_tools_path = {
        "all": "data/all_attack_tools.jsonl",
        "agg": "data/all_attack_tools_aggressive.jsonl",
        "non-agg": "data/all_attack_tools_non_aggressive.jsonl",
        "test": "data/attack_tools_test.jsonl",
    }[attack_tool_set]

    cmd = [
        sys.executable,
        "main_attacker.py",
        "--llm_name",
        llm_name,
        "--attack_type",
        attack_type,
        "--attacker_tools_path",
        attacker_tools_path,
        "--res_file",
        str(res_file),
        "--task_num",
        str(task_num),
    ]
    if use_backend:
        cmd.extend(["--use_backend", use_backend])
    if clean:
        cmd.append("--clean")
    else:
        cmd.append("--observation_prompt_injection")

    res_file.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(cmd, cwd=PROGENT_ASB_ROOT, env=env, check=True)

    with res_file.open(newline="") as f:
        return list(csv.DictReader(f))


def _summarize_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    total = len(rows)
    attack_success = sum(1 for row in rows if _to_bool(row.get("Attack Successful", "")))
    original_success = sum(1 for row in rows if _to_bool(row.get("Original Task Successful", "")))
    return {
        "rows": total,
        "attack_success": attack_success,
        "original_success": original_success,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Progent on ASB and normalize outputs")
    parser.add_argument("--llm-name", default="gpt-4o-2024-08-06")
    parser.add_argument("--use-backend", default=None)
    parser.add_argument("--mode", choices=["manual", "auto"], default="manual")
    parser.add_argument("--policy-model", default="gpt-4o-2024-08-06")
    parser.add_argument("--attack-tool-set", choices=["all", "agg", "non-agg", "test"], default="all")
    parser.add_argument("--task-num", type=int, default=1)
    parser.add_argument("--attack-types", nargs="+", default=DEFAULT_ATTACK_TYPES)
    parser.add_argument("--outdir", default=str(ROOT / "data" / "progent_asb_runs"))
    parser.add_argument("--force-rerun", action="store_true")
    args = parser.parse_args()

    load_dotenv(PROGENT_ASB_ROOT / ".env")
    load_dotenv(PROGENT_ROOT / ".env")
    load_dotenv(ROOT / ".env")
    load_dotenv()
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY not set.")
        sys.exit(1)

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out = ROOT / "data" / f"progent_asb_{args.mode}_{args.llm_name}.json"

    start = time.time()
    per_attack: dict[str, Any] = {}
    all_rows: list[dict[str, str]] = []

    def write_partial(clean_rows: list[dict[str, str]] | None = None) -> None:
        clean_rows = clean_rows or []
        clean_stats = _summarize_rows(clean_rows) if clean_rows else {"rows": 0, "original_success": 0}
        overall_rows = len(all_rows)
        overall_asr = (
            sum(1 for row in all_rows if _to_bool(row.get("Attack Successful", ""))) / overall_rows
            if overall_rows
            else 0.0
        )
        overall_uar_w_atk = (
            sum(1 for row in all_rows if _to_bool(row.get("Original Task Successful", ""))) / overall_rows
            if overall_rows
            else 0.0
        )
        overall_uar_no_atk = clean_stats["original_success"] / clean_stats["rows"] if clean_stats["rows"] else 0.0
        payload = {
            "schema_version": "progent_asb_v1",
            "llm_name": args.llm_name,
            "use_backend": args.use_backend,
            "mode": args.mode,
            "policy_model": args.policy_model,
            "attack_types": list(args.attack_types),
            "attack_tool_set": args.attack_tool_set,
            "task_num": args.task_num,
            "elapsed_sec": round(time.time() - start, 1),
            "partial": True,
            "summary": {
                "overall": {
                    "ASR": round(overall_asr, 4),
                    "UAR_w_atk": round(overall_uar_w_atk, 4),
                    "UAR_no_atk": round(overall_uar_no_atk, 4),
                    "TPR": None,
                    "FPR": None,
                    "counts": {
                        "attacked_scenarios": overall_rows,
                        "clean_scenarios": clean_stats["rows"],
                        "clean_original_success": clean_stats["original_success"],
                    },
                },
                "per_attack": per_attack,
            },
        }
        out.write_text(json.dumps(payload, indent=2))

    for attack_type in args.attack_types:
        print(f"\n=== Progent ASB attacked: {attack_type} ===")
        csv_path = outdir / f"{args.mode}_{args.llm_name}_{attack_type}.csv"
        if not args.force_rerun and _csv_complete(csv_path):
            with csv_path.open(newline="") as f:
                rows = list(csv.DictReader(f))
        else:
            rows = _run_csv_job(
                llm_name=args.llm_name,
                use_backend=args.use_backend,
                attack_type=attack_type,
                res_file=csv_path,
                mode=args.mode,
                policy_model=args.policy_model,
                attack_tool_set=args.attack_tool_set,
                task_num=args.task_num,
                clean=False,
            )
        all_rows.extend(rows)
        stats = _summarize_rows(rows)
        per_attack[attack_type] = {
            "ASR": round(stats["attack_success"] / stats["rows"], 4) if stats["rows"] else 0.0,
            "UAR_w_atk": round(stats["original_success"] / stats["rows"], 4) if stats["rows"] else 0.0,
            "TPR": None,
            "FPR": None,
            "counts": stats,
            "csv_path": str(csv_path),
        }
        write_partial()

    print("\n=== Progent ASB clean ===")
    clean_csv = outdir / f"{args.mode}_{args.llm_name}_clean.csv"
    if not args.force_rerun and _csv_complete(clean_csv):
        with clean_csv.open(newline="") as f:
            clean_rows = list(csv.DictReader(f))
    else:
        clean_rows = _run_csv_job(
            llm_name=args.llm_name,
            use_backend=args.use_backend,
            attack_type=args.attack_types[0],
            res_file=clean_csv,
            mode=args.mode,
            policy_model=args.policy_model,
            attack_tool_set=args.attack_tool_set,
            task_num=args.task_num,
            clean=True,
        )
    clean_stats = _summarize_rows(clean_rows)

    overall_rows = len(all_rows)
    overall_asr = sum(1 for row in all_rows if _to_bool(row.get("Attack Successful", ""))) / overall_rows if overall_rows else 0.0
    overall_uar_w_atk = sum(1 for row in all_rows if _to_bool(row.get("Original Task Successful", ""))) / overall_rows if overall_rows else 0.0
    overall_uar_no_atk = clean_stats["original_success"] / clean_stats["rows"] if clean_stats["rows"] else 0.0

    result = {
        "schema_version": "progent_asb_v1",
        "llm_name": args.llm_name,
        "use_backend": args.use_backend,
        "mode": args.mode,
        "policy_model": args.policy_model,
        "attack_types": list(args.attack_types),
        "attack_tool_set": args.attack_tool_set,
        "task_num": args.task_num,
        "elapsed_sec": round(time.time() - start, 1),
        "partial": False,
        "summary": {
            "overall": {
                "ASR": round(overall_asr, 4),
                "UAR_w_atk": round(overall_uar_w_atk, 4),
                "UAR_no_atk": round(overall_uar_no_atk, 4),
                "TPR": None,
                "FPR": None,
                "counts": {
                    "attacked_scenarios": overall_rows,
                    "clean_scenarios": clean_stats["rows"],
                    "clean_original_success": clean_stats["original_success"],
                },
            },
            "per_attack": per_attack,
            "clean_csv_path": str(clean_csv),
        },
    }

    out.write_text(json.dumps(result, indent=2))
    print(f"\nSaved to {out}")


if __name__ == "__main__":
    main()
