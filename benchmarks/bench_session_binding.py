"""Benchmark session binding operations.

Measures:
- HMAC-SHA256 derivation overhead vs raw random
- establish_session() cost
- derive_sig_data() throughput
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import statistics
import time
from typing import Any


def _bench(fn: Any, iterations: int = 1000) -> dict[str, float]:
    """Run a function multiple times and return timing statistics."""
    times: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
    return {
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
        "min_ms": min(times),
        "max_ms": max(times),
        "iterations": iterations,
    }


def bench_random_sig_data(iterations: int = 10000) -> dict[str, float]:
    """Baseline: generate random 32-byte sig_data."""

    def fn() -> None:
        secrets.token_bytes(32)

    return _bench(fn, iterations)


def bench_hmac_derivation(iterations: int = 10000) -> dict[str, float]:
    """HMAC-SHA256 sig_data derivation."""
    session_id = secrets.token_bytes(32)
    counter = 0

    def fn() -> None:
        nonlocal counter
        entropy = secrets.token_bytes(32)
        counter_bytes = counter.to_bytes(8, "big")
        hmac.new(session_id, entropy + counter_bytes, hashlib.sha256).digest()
        counter += 1

    return _bench(fn, iterations)


def bench_establish_session(iterations: int = 1000) -> dict[str, float]:
    """Benchmark session_id computation."""
    client_pk = secrets.token_bytes(512)  # Simulated PEM
    server_pk = secrets.token_bytes(512)
    client_sd = secrets.token_bytes(32)
    server_sd = secrets.token_bytes(32)

    def fn() -> None:
        hashlib.sha256(client_pk + server_pk + client_sd + server_sd).digest()

    return _bench(fn, iterations)


def run_all() -> dict[str, dict[str, float]]:
    """Run all session binding benchmarks."""
    results: dict[str, dict[str, float]] = {}

    results["random_sig_data"] = bench_random_sig_data()
    results["hmac_derivation"] = bench_hmac_derivation()
    results["establish_session"] = bench_establish_session()

    return results


if __name__ == "__main__":
    import json

    results = run_all()
    print(json.dumps(results, indent=2))
