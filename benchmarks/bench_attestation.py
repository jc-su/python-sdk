"""Benchmark attestation operations: evidence creation and verification.

Uses mock TDX for non-hardware environments with configurable simulated latency.

Measures:
- create_evidence() fresh
- _verify_evidence() authority-backed verification
"""

from __future__ import annotations

import hashlib
import secrets
import statistics
import time
from typing import Any
from unittest.mock import patch

from mcp.shared.crypto import rsa
from mcp.shared.secure_channel import (
    AttestationEvidence,
    SecureEndpoint,
    _verify_evidence,
)

# Simulated latency for mock TDX operations (ms)
DEFAULT_QUOTE_GEN_LATENCY_MS = 1.0


def _bench(fn: Any, iterations: int = 100) -> dict[str, float]:
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


def _mock_generate_quote(reportdata: bytes, latency_ms: float = DEFAULT_QUOTE_GEN_LATENCY_MS) -> bytes:
    """Mock TDX quote generation with simulated latency."""
    time.sleep(latency_ms / 1000.0)
    # Return a minimal fake quote structure
    return b"\x04\x00" + b"\x00" * 254 + reportdata + b"\x00" * (1020 - len(reportdata))


def _mock_parse_quote(quote_bytes: bytes) -> Any:
    """Mock quote parser returning a plausible structure."""
    from dataclasses import dataclass

    @dataclass
    class MockMeasurements:
        mrtd: bytes = bytes(48)
        rtmr0: bytes = bytes(48)
        rtmr1: bytes = bytes(48)
        rtmr2: bytes = bytes(48)
        rtmr3: bytes = bytes(48)

    @dataclass
    class MockQuote:
        version: int = 4
        reportdata: bytes = b"\x00" * 64
        measurements: MockMeasurements = None  # type: ignore[assignment]
        raw: bytes = b""

    rd = quote_bytes[256:320] if len(quote_bytes) >= 320 else b"\x00" * 64
    return MockQuote(reportdata=rd, measurements=MockMeasurements(), raw=quote_bytes)


def bench_create_evidence_fresh(iterations: int = 50) -> dict[str, float]:
    """Benchmark fresh evidence creation (no cache)."""
    with (
        patch("mcp.shared.secure_channel.generate_quote", _mock_generate_quote),
        patch("mcp.shared.secure_channel.parse_quote", _mock_parse_quote),
        patch("mcp.shared.secure_channel.get_current_cgroup", return_value="/docker/bench"),
        patch("mcp.shared.secure_channel.get_container_rtmr3", return_value=bytes(48)),
    ):
        ep = SecureEndpoint.create(role="server")
        nonce = secrets.token_bytes(32)

        def fn() -> None:
            ep.create_evidence(nonce)

        return _bench(fn, iterations)


def bench_verify_evidence_full(iterations: int = 50) -> dict[str, float]:
    """Benchmark full evidence verification."""
    keypair = rsa.generate_keypair()
    pub_pem = rsa.export_public_key(keypair.public_key)
    nonce = secrets.token_bytes(32)
    rd = hashlib.sha256(nonce).digest() + hashlib.sha256(pub_pem).digest()

    evidence = AttestationEvidence(
        quote=_mock_generate_quote(rd, latency_ms=0),
        public_key=pub_pem,
        nonce=nonce,
        cgroup="/docker/bench",
        rtmr3=bytes(48),
        timestamp_ms=int(time.time() * 1000),
        role="client",
    )

    with (
        patch("mcp.shared.secure_channel.parse_quote", _mock_parse_quote),
        patch("mcp.shared.secure_channel._verify_quote_via_authority", return_value=(True, "")),
    ):

        def fn() -> None:
            _verify_evidence(evidence, nonce)

        return _bench(fn, iterations)


def run_all() -> dict[str, dict[str, float]]:
    """Run all attestation benchmarks."""
    results: dict[str, dict[str, float]] = {}

    results["create_evidence_fresh"] = bench_create_evidence_fresh()
    results["verify_evidence_full"] = bench_verify_evidence_full()

    return results


if __name__ == "__main__":
    import json

    results = run_all()
    print(json.dumps(results, indent=2))
