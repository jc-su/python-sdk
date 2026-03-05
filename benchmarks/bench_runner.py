"""CLI entry point for TEE-MCP benchmarks.

Usage:
    uv run python -m benchmarks.bench_runner --suite all
    uv run python -m benchmarks.bench_runner --suite crypto
    uv run python -m benchmarks.bench_runner --suite attestation
    uv run python -m benchmarks.bench_runner --suite e2e
    uv run python -m benchmarks.bench_runner --suite session
    uv run python -m benchmarks.bench_runner --suite all --format latex
"""

from __future__ import annotations

import argparse
import json
from typing import Any


def _format_json(results: dict[str, dict[str, Any]]) -> str:
    return json.dumps(results, indent=2)


def _format_table(results: dict[str, dict[str, Any]]) -> str:
    lines = []
    lines.append(f"{'Benchmark':<40} {'Mean (ms)':>10} {'Median (ms)':>12} {'Min (ms)':>10} {'Max (ms)':>10}")
    lines.append("-" * 86)
    for name, stats in results.items():
        lines.append(
            f"{name:<40} {stats['mean_ms']:>10.3f} {stats['median_ms']:>12.3f} "
            f"{stats['min_ms']:>10.3f} {stats['max_ms']:>10.3f}"
        )
    return "\n".join(lines)


def _format_latex(results: dict[str, dict[str, Any]]) -> str:
    lines = []
    lines.append(r"\begin{tabular}{lrrr}")
    lines.append(r"\toprule")
    lines.append(r"Operation & Mean (ms) & Median (ms) & Std Dev (ms) \\")
    lines.append(r"\midrule")
    for name, stats in results.items():
        escaped_name = name.replace("_", r"\_")
        lines.append(
            f"{escaped_name} & {stats['mean_ms']:.3f} & {stats['median_ms']:.3f} & {stats['stdev_ms']:.3f} \\\\"
        )
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    return "\n".join(lines)


def run_suite(suite: str) -> dict[str, dict[str, Any]]:
    """Run a benchmark suite and return results."""
    all_results: dict[str, dict[str, Any]] = {}

    if suite in ("all", "crypto"):
        from benchmarks.bench_envelope_crypto import run_all as run_crypto

        all_results.update({"crypto/" + k: v for k, v in run_crypto().items()})

    if suite in ("all", "attestation"):
        from benchmarks.bench_attestation import run_all as run_attestation

        all_results.update({"attestation/" + k: v for k, v in run_attestation().items()})

    if suite in ("all", "e2e"):
        from benchmarks.bench_end_to_end import run_all as run_e2e

        all_results.update({"e2e/" + k: v for k, v in run_e2e().items()})

    if suite in ("all", "session"):
        from benchmarks.bench_session_binding import run_all as run_session

        all_results.update({"session/" + k: v for k, v in run_session().items()})

    return all_results


def main() -> None:
    parser = argparse.ArgumentParser(description="TEE-MCP Benchmark Runner")
    parser.add_argument(
        "--suite",
        choices=["all", "crypto", "attestation", "e2e", "session"],
        default="all",
        help="Benchmark suite to run",
    )
    parser.add_argument(
        "--format",
        choices=["json", "table", "latex"],
        default="table",
        help="Output format",
    )
    args = parser.parse_args()

    results = run_suite(args.suite)

    if args.format == "json":
        print(_format_json(results))
    elif args.format == "latex":
        print(_format_latex(results))
    else:
        print(_format_table(results))


if __name__ == "__main__":
    main()
