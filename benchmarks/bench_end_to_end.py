"""End-to-end benchmark: full request+response envelope cycle.

Measures total overhead per tool call in different modes:
- no_tee: Plain dict serialization (baseline)
- fresh_quote: Fresh quote generation per call
"""

from __future__ import annotations

import base64
import json
import secrets
import statistics
import time
from typing import Any

from mcp.shared.crypto import aes, rsa
from mcp.shared.crypto.envelope import ResponseKey
from mcp.shared.crypto.envelope import encrypt as envelope_encrypt


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


# Sample tool call params and result
SAMPLE_PARAMS = {"name": "get_data", "arguments": {"query": "SELECT * FROM users LIMIT 10"}}
SAMPLE_RESULT = {
    "content": [{"type": "text", "text": '{"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}'}],
    "isError": False,
}


def bench_no_tee(iterations: int = 1000) -> dict[str, float]:
    """Baseline: just JSON serialization, no TEE."""

    def fn() -> None:
        _ = json.dumps(SAMPLE_PARAMS, separators=(",", ":")).encode()
        _ = json.dumps(SAMPLE_RESULT, separators=(",", ":")).encode()

    return _bench(fn, iterations)


def bench_envelope_round_trip(iterations: int = 100) -> dict[str, float]:
    """Full envelope encrypt request + encrypt response (RSA + AES)."""
    server_kp = rsa.generate_keypair()

    def fn() -> None:
        # Client encrypts request to server
        plaintext = json.dumps(SAMPLE_PARAMS, separators=(",", ":")).encode()
        enc_msg, response_key = envelope_encrypt(server_kp.public_key, plaintext)

        # Server decrypts request
        aes_key = rsa.decrypt(server_kp.private_key, enc_msg.encrypted_key)
        _ = aes.decrypt(aes_key, enc_msg.nonce, enc_msg.ciphertext)

        # Server encrypts response using ResponseKey
        resp_plaintext = json.dumps(SAMPLE_RESULT, separators=(",", ":")).encode()
        rk = ResponseKey(aes_key=aes_key)
        resp_enc = rk.encrypt(resp_plaintext)

        # Client decrypts response
        _ = response_key.decrypt(resp_enc)

    return _bench(fn, iterations)


def bench_evidence_creation_overhead(iterations: int = 100) -> dict[str, float]:
    """Measure evidence creation overhead (mock, excluding quote generation)."""

    def fn() -> None:
        sig_data = secrets.token_bytes(32)
        # Simulate evidence creation: just dict construction + base64
        evidence = {
            "quote": base64.b64encode(b"mock_quote").decode(),
            "public_key": base64.b64encode(b"mock_pubkey").decode(),
            "nonce": base64.b64encode(sig_data).decode(),
            "cgroup": "/docker/container",
            "rtmr3": bytes(48).hex(),
            "timestamp_ms": int(time.time() * 1000),
            "role": "client",
            "sig_data": base64.b64encode(sig_data).decode(),
        }
        _ = json.dumps(evidence, separators=(",", ":"))

    return _bench(fn, iterations)


def run_all() -> dict[str, dict[str, float]]:
    """Run all end-to-end benchmarks."""
    results: dict[str, dict[str, float]] = {}

    results["no_tee_baseline"] = bench_no_tee()
    results["envelope_round_trip"] = bench_envelope_round_trip()
    results["evidence_creation_overhead"] = bench_evidence_creation_overhead()

    return results


if __name__ == "__main__":
    results = run_all()
    print(json.dumps(results, indent=2))
