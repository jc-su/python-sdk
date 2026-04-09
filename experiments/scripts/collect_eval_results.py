"""Collect runnable evaluation outputs into one normalized JSON file.

This script does not rerun experiments. It gathers any existing result files
produced by the open-source runners and writes a compact summary that is easier
to feed into figure/table generation.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
AGENTDOJO_RESULTS_HTML = ROOT.parent.parent / "agentdojo" / "docs" / "results-table.html"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _find(glob_pattern: str) -> list[Path]:
    return sorted(DATA.glob(glob_pattern))


def collect_agentdojo_single_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("agentdojo_real_v2_*.json"):
        data = _load_json(path)
        rows.append(
            {
                "path": str(path),
                "label": data.get("label"),
                "model": data.get("model"),
                "attack": data.get("attack"),
                "use_defense": data.get("use_defense"),
                "use_args": data.get("use_args"),
                "ASR": data.get("ASR"),
                "UA": data.get("UA"),
                "UAR_no_atk": data.get("UAR_no_atk"),
                "TPR": data.get("TPR_labeled"),
                "FNR": data.get("FNR_labeled"),
                "FPR": data.get("FPR_benign"),
            }
        )
    return rows


def collect_agentdojo_matrix_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("agentdojo_matrix_v2_*.json"):
        data = _load_json(path)
        rows.append({"path": str(path), **data})
    return rows


def collect_agentdojo_builtin_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("agentdojo_builtin_baselines_*.json"):
        data = _load_json(path)
        rows.append({"path": str(path), **data})
    return rows


def collect_agentdojo_builtin_official_rows() -> list[dict[str, Any]]:
    if not AGENTDOJO_RESULTS_HTML.exists():
        return []

    html = AGENTDOJO_RESULTS_HTML.read_text()
    rows = []
    pattern = re.compile(r"<tr>\s*(.*?)\s*</tr>", re.S)
    td_pattern = re.compile(r"<td>(.*?)</td>", re.S)

    for tr in pattern.findall(html):
        cols = [re.sub(r"<.*?>", "", cell).strip() for cell in td_pattern.findall(tr)]
        if len(cols) < 8:
            continue
        provider, model, defense, attack, utility, ua, asr, date = cols[:8]
        if defense == "Defense":
            continue
        try:
            utility_f = float(utility.rstrip("%"))
            ua_f = float(ua.rstrip("%"))
            asr_f = float(asr.rstrip("%"))
        except ValueError:
            continue

        rows.append(
            {
                "source": "agentdojo_official_local_html",
                "path": str(AGENTDOJO_RESULTS_HTML),
                "provider": provider,
                "model": model,
                "defense": defense,
                "attack": attack,
                "date": date,
                "Utility": utility_f,
                "Utility_under_attack": ua_f,
                "Targeted_ASR": asr_f,
                "UAR_no_atk": utility_f,
                "UA": ua_f,
                "ASR": asr_f,
                "TPR": None,
                "FPR": None,
            }
        )
    return rows


def collect_asb_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("asb_real_v2_*.json"):
        data = _load_json(path)
        summary = data.get("summary", {}).get("overall", {})
        rows.append(
            {
                "path": str(path),
                "llm_name": data.get("llm_name"),
                "use_defense": data.get("use_defense"),
                "attack_types": data.get("attack_types"),
                "ASR": summary.get("ASR"),
                "UAR_w_atk": summary.get("UAR_w_atk"),
                "UAR_no_atk": summary.get("UAR_no_atk"),
                "TPR": summary.get("TPR"),
                "FNR": summary.get("FNR"),
                "FPR": summary.get("FPR"),
            }
        )
    return rows


def collect_progent_agentdojo_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("progent_agentdojo_*.json"):
        data = _load_json(path)
        rows.append({"path": str(path), **data})
    return rows


def collect_melon_agentdojo_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("melon_agentdojo_*.json"):
        data = _load_json(path)
        rows.append({"path": str(path), **data})
    return rows


def collect_progent_asb_runs() -> list[dict[str, Any]]:
    rows = []
    for path in _find("progent_asb_*.json"):
        data = _load_json(path)
        rows.append({"path": str(path), **data})
    return rows


def collect_static_capabilities() -> dict[str, Any]:
    payload: dict[str, Any] = {}

    agentdojo_path = ROOT / "pysa_agentdojo_results.json"
    if agentdojo_path.exists():
        data = _load_json(agentdojo_path)
        payload["agentdojo"] = {
            "path": str(agentdojo_path),
            "n_tools": len(data),
            "with_capabilities": sum(1 for caps in data.values() if caps),
            "results": data,
        }

    asb_named = ROOT / "pysa_asb_results.json"
    asb_report = DATA / "pysa_asb_report.json"
    if asb_named.exists() or asb_report.exists():
        entry: dict[str, Any] = {}
        if asb_named.exists():
            named = _load_json(asb_named)
            entry["path"] = str(asb_named)
            entry["n_named_tools"] = len(named)
            entry["with_capabilities"] = sum(1 for caps in named.values() if caps)
            entry["results"] = named
        if asb_report.exists():
            report = _load_json(asb_report)
            entry["report_path"] = str(asb_report)
            entry["report"] = report
        payload["asb"] = entry

    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect open-source evaluation outputs")
    parser.add_argument("--output", default=str(DATA / "collected_eval_results.json"))
    args = parser.parse_args()

    payload = {
        "agentdojo_single": collect_agentdojo_single_runs(),
        "agentdojo_matrix": collect_agentdojo_matrix_runs(),
        "agentdojo_builtin": collect_agentdojo_builtin_runs(),
        "agentdojo_builtin_official": collect_agentdojo_builtin_official_rows(),
        "melon_agentdojo": collect_melon_agentdojo_runs(),
        "progent_agentdojo": collect_progent_agentdojo_runs(),
        "progent_asb": collect_progent_asb_runs(),
        "asb": collect_asb_runs(),
        "static_capabilities": collect_static_capabilities(),
    }

    out = Path(args.output)
    out.write_text(json.dumps(payload, indent=2))
    print(f"Saved to {out}")


if __name__ == "__main__":
    main()
