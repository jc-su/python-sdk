"""Benchmark TEE-MCP crypto and protocol overhead (no TDX hardware required).

Measures the pure software overhead added by TEE-MCP on top of vanilla MCP:
- RSA-4096: key generation, OAEP encrypt/decrypt, PSS sign/verify
- AES-256-GCM: encrypt/decrypt across payload sizes (256B .. 64KB)
- Envelope encryption: RSA+AES combined encrypt/decrypt, ResponseKey reuse
- Session binding: establish_session, derive_sig_data, verify_derived_sig_data

All timings use time.perf_counter_ns() for nanosecond precision and report
median, p95, p99 in microseconds.

Usage:
    uv run python benchmarks/bench_tee_overhead.py
    uv run python benchmarks/bench_tee_overhead.py --iterations 500
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import statistics
import time
from dataclasses import dataclass
from typing import Any

from mcp.shared.crypto import aes, rsa
from mcp.shared.crypto.envelope import EncryptedMessage, ResponseKey
from mcp.shared.crypto.envelope import decrypt as envelope_decrypt
from mcp.shared.crypto.envelope import encrypt as envelope_encrypt

PAYLOAD_SIZES = [256, 1024, 4096, 16384, 65536]
PAYLOAD_LABELS = ["256B", "1KB", "4KB", "16KB", "64KB"]


@dataclass
class BenchResult:
    """Timing statistics for a single benchmark."""

    name: str
    iterations: int
    median_us: float
    p95_us: float
    p99_us: float
    min_us: float
    max_us: float
    payload_label: str = ""


def _run(fn: Any, iterations: int) -> list[int]:
    """Run fn() for the given iterations and return a list of elapsed nanoseconds."""
    times_ns: list[int] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        elapsed = time.perf_counter_ns() - start
        times_ns.append(elapsed)
    return times_ns


def _stats(name: str, times_ns: list[int], iterations: int, payload_label: str = "") -> BenchResult:
    """Compute statistics from raw nanosecond timings."""
    times_us = [t / 1000.0 for t in times_ns]
    med = statistics.median(times_us)
    # quantiles(n=100) gives 99 cut points; index 94 is p95, index 98 is p99
    quantiles = statistics.quantiles(times_us, n=100)
    return BenchResult(
        name=name,
        iterations=iterations,
        median_us=med,
        p95_us=quantiles[94],
        p99_us=quantiles[98],
        min_us=min(times_us),
        max_us=max(times_us),
        payload_label=payload_label,
    )


# =============================================================================
# RSA-4096 benchmarks
# =============================================================================


def bench_rsa_keygen(iterations: int) -> BenchResult:
    """RSA-4096 key pair generation."""
    times = _run(rsa.generate_keypair, iterations)
    return _stats("RSA-4096 keygen", times, iterations)


def bench_rsa_encrypt(iterations: int) -> BenchResult:
    """RSA-4096 OAEP encrypt (32-byte AES key)."""
    keypair = rsa.generate_keypair()
    plaintext = aes.generate_key()  # 32 bytes

    def fn() -> None:
        rsa.encrypt(keypair.public_key, plaintext)

    times = _run(fn, iterations)
    return _stats("RSA-4096 OAEP encrypt", times, iterations)


def bench_rsa_decrypt(iterations: int) -> BenchResult:
    """RSA-4096 OAEP decrypt (32-byte AES key)."""
    keypair = rsa.generate_keypair()
    plaintext = aes.generate_key()
    ciphertext = rsa.encrypt(keypair.public_key, plaintext)

    def fn() -> None:
        rsa.decrypt(keypair.private_key, ciphertext)

    times = _run(fn, iterations)
    return _stats("RSA-4096 OAEP decrypt", times, iterations)


def bench_rsa_sign(iterations: int) -> BenchResult:
    """RSA-4096 PSS sign (32-byte message)."""
    keypair = rsa.generate_keypair()
    message = secrets.token_bytes(32)

    def fn() -> None:
        rsa.sign(keypair.private_key, message)

    times = _run(fn, iterations)
    return _stats("RSA-4096 PSS sign", times, iterations)


def bench_rsa_verify(iterations: int) -> BenchResult:
    """RSA-4096 PSS verify (32-byte message)."""
    keypair = rsa.generate_keypair()
    message = secrets.token_bytes(32)
    signature = rsa.sign(keypair.private_key, message)

    def fn() -> None:
        rsa.verify(keypair.public_key, message, signature)

    times = _run(fn, iterations)
    return _stats("RSA-4096 PSS verify", times, iterations)


# =============================================================================
# AES-256-GCM benchmarks
# =============================================================================


def bench_aes_encrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """AES-256-GCM encrypt at a given payload size."""
    key = aes.generate_key()
    data = secrets.token_bytes(payload_size)

    def fn() -> None:
        aes.encrypt(key, data)

    times = _run(fn, iterations)
    return _stats(f"AES-256-GCM encrypt ({payload_label})", times, iterations, payload_label)


def bench_aes_decrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """AES-256-GCM decrypt at a given payload size."""
    key = aes.generate_key()
    data = secrets.token_bytes(payload_size)
    encrypted = aes.encrypt(key, data)

    def fn() -> None:
        aes.decrypt(key, encrypted.nonce, encrypted.ciphertext)

    times = _run(fn, iterations)
    return _stats(f"AES-256-GCM decrypt ({payload_label})", times, iterations, payload_label)


# =============================================================================
# Envelope encryption benchmarks (RSA + AES combined)
# =============================================================================


def bench_envelope_encrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """Full envelope encrypt: AES-GCM + RSA-OAEP key wrap."""
    keypair = rsa.generate_keypair()
    data = secrets.token_bytes(payload_size)

    def fn() -> None:
        envelope_encrypt(keypair.public_key, data)

    times = _run(fn, iterations)
    return _stats(f"Envelope encrypt ({payload_label})", times, iterations, payload_label)


def bench_envelope_decrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """Full envelope decrypt: RSA-OAEP key unwrap + AES-GCM."""
    keypair = rsa.generate_keypair()
    data = secrets.token_bytes(payload_size)
    enc_msg, _ = envelope_encrypt(keypair.public_key, data)

    def fn() -> None:
        envelope_decrypt(keypair.private_key, enc_msg)

    times = _run(fn, iterations)
    return _stats(f"Envelope decrypt ({payload_label})", times, iterations, payload_label)


def bench_response_key_encrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """ResponseKey reuse encrypt (AES-only, no RSA overhead)."""
    rk = ResponseKey(aes_key=aes.generate_key())
    data = secrets.token_bytes(payload_size)

    def fn() -> None:
        rk.encrypt(data)

    times = _run(fn, iterations)
    return _stats(f"ResponseKey encrypt ({payload_label})", times, iterations, payload_label)


def bench_response_key_decrypt(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """ResponseKey reuse decrypt (AES-only, no RSA overhead)."""
    rk = ResponseKey(aes_key=aes.generate_key())
    data = secrets.token_bytes(payload_size)
    enc_msg = rk.encrypt(data)

    def fn() -> None:
        rk.decrypt(enc_msg)

    times = _run(fn, iterations)
    return _stats(f"ResponseKey decrypt ({payload_label})", times, iterations, payload_label)


# =============================================================================
# Envelope serialization round-trip
# =============================================================================


def bench_envelope_serialize(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """EncryptedMessage to_dict + from_dict round-trip (base64 encode/decode)."""
    keypair = rsa.generate_keypair()
    data = secrets.token_bytes(payload_size)
    enc_msg, _ = envelope_encrypt(keypair.public_key, data)

    def fn() -> None:
        d = enc_msg.to_dict()
        EncryptedMessage.from_dict(d)

    times = _run(fn, iterations)
    return _stats(f"Envelope serialize RT ({payload_label})", times, iterations, payload_label)


# =============================================================================
# Session binding benchmarks
# =============================================================================


def bench_establish_session(iterations: int) -> BenchResult:
    """SHA-256 session_id computation (simulated PEM-sized keys)."""
    # Simulate realistic PEM sizes (~800 bytes for RSA-4096 public key)
    client_pk = secrets.token_bytes(800)
    server_pk = secrets.token_bytes(800)
    client_sd = secrets.token_bytes(32)
    server_sd = secrets.token_bytes(32)

    def fn() -> None:
        hashlib.sha256(client_pk + server_pk + client_sd + server_sd).digest()

    times = _run(fn, iterations)
    return _stats("establish_session (SHA-256)", times, iterations)


def bench_derive_sig_data(iterations: int) -> BenchResult:
    """HMAC-SHA256 sig_data derivation (per-call overhead)."""
    session_id = secrets.token_bytes(32)
    counter = 0

    def fn() -> None:
        nonlocal counter
        entropy = secrets.token_bytes(32)
        counter_bytes = counter.to_bytes(8, "big")
        hmac.new(session_id, entropy + counter_bytes, hashlib.sha256).digest()
        counter += 1

    times = _run(fn, iterations)
    return _stats("derive_sig_data (HMAC-SHA256)", times, iterations)


def bench_verify_derived_sig_data(iterations: int) -> BenchResult:
    """HMAC-SHA256 sig_data verification (peer-side recomputation)."""
    session_id = secrets.token_bytes(32)
    # Pre-generate entropy/counter pairs
    pairs: list[tuple[bytes, int]] = []
    for i in range(iterations):
        pairs.append((secrets.token_bytes(32), i))
    idx = 0

    def fn() -> None:
        nonlocal idx
        entropy, counter = pairs[idx]
        counter_bytes = counter.to_bytes(8, "big")
        hmac.new(session_id, entropy + counter_bytes, hashlib.sha256).digest()
        idx += 1

    times = _run(fn, iterations)
    return _stats("verify_derived_sig_data (HMAC-SHA256)", times, iterations)


def bench_random_sig_data(iterations: int) -> BenchResult:
    """Baseline: random 32-byte sig_data generation (no session binding)."""

    def fn() -> None:
        secrets.token_bytes(32)

    times = _run(fn, iterations)
    return _stats("random sig_data (baseline)", times, iterations)


# =============================================================================
# PSS sign/verify with varying message sizes
# =============================================================================


def bench_rsa_sign_varied(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """RSA-4096 PSS sign with varying message size."""
    keypair = rsa.generate_keypair()
    message = secrets.token_bytes(payload_size)

    def fn() -> None:
        rsa.sign(keypair.private_key, message)

    times = _run(fn, iterations)
    return _stats(f"RSA-4096 PSS sign ({payload_label})", times, iterations, payload_label)


def bench_rsa_verify_varied(payload_size: int, payload_label: str, iterations: int) -> BenchResult:
    """RSA-4096 PSS verify with varying message size."""
    keypair = rsa.generate_keypair()
    message = secrets.token_bytes(payload_size)
    signature = rsa.sign(keypair.private_key, message)

    def fn() -> None:
        rsa.verify(keypair.public_key, message, signature)

    times = _run(fn, iterations)
    return _stats(f"RSA-4096 PSS verify ({payload_label})", times, iterations, payload_label)


# =============================================================================
# Print results
# =============================================================================


def print_table(title: str, results: list[BenchResult]) -> None:
    """Print a section of benchmark results as a formatted table."""
    print()
    print(f"  {title}")
    print(f"  {'=' * len(title)}")
    print()
    header = f"  {'Operation':<42} {'Median':>10} {'p95':>10} {'p99':>10} {'Min':>10} {'Max':>10}  {'Iters':>6}"
    print(header)
    print(f"  {'-' * (len(header) - 2)}")
    for r in results:
        # Format values: use ms if >= 1000 us, otherwise use us
        def fmt(v: float) -> str:
            if v >= 1000.0:
                return f"{v / 1000.0:.2f} ms"
            else:
                return f"{v:.1f} us"

        print(
            f"  {r.name:<42} {fmt(r.median_us):>10} {fmt(r.p95_us):>10} {fmt(r.p99_us):>10} "
            f"{fmt(r.min_us):>10} {fmt(r.max_us):>10}  {r.iterations:>6}"
        )
    print()


def run_all(iterations: int) -> None:
    """Run all benchmarks and print results."""
    print()
    print("=" * 100)
    print("  TEE-MCP Crypto & Protocol Overhead Benchmark")
    print("  (No TDX hardware required -- pure software overhead)")
    print(f"  Iterations per benchmark: {iterations}")
    print("=" * 100)

    # --- RSA-4096 ---
    # Keygen is slow; use fewer iterations to keep total time reasonable
    keygen_iters = max(1, iterations // 10)
    rsa_results: list[BenchResult] = [
        bench_rsa_keygen(keygen_iters),
        bench_rsa_encrypt(iterations),
        bench_rsa_decrypt(iterations),
        bench_rsa_sign(iterations),
        bench_rsa_verify(iterations),
    ]
    print_table("RSA-4096 Operations", rsa_results)

    # --- AES-256-GCM by payload size ---
    aes_results: list[BenchResult] = []
    for size, label in zip(PAYLOAD_SIZES, PAYLOAD_LABELS):
        aes_results.append(bench_aes_encrypt(size, label, iterations))
        aes_results.append(bench_aes_decrypt(size, label, iterations))
    print_table("AES-256-GCM by Payload Size", aes_results)

    # --- Envelope encryption by payload size ---
    env_results: list[BenchResult] = []
    for size, label in zip(PAYLOAD_SIZES, PAYLOAD_LABELS):
        env_results.append(bench_envelope_encrypt(size, label, iterations))
        env_results.append(bench_envelope_decrypt(size, label, iterations))
    print_table("Envelope Encryption (RSA + AES) by Payload Size", env_results)

    # --- ResponseKey reuse by payload size ---
    rk_results: list[BenchResult] = []
    for size, label in zip(PAYLOAD_SIZES, PAYLOAD_LABELS):
        rk_results.append(bench_response_key_encrypt(size, label, iterations))
        rk_results.append(bench_response_key_decrypt(size, label, iterations))
    print_table("ResponseKey Reuse (AES-only) by Payload Size", rk_results)

    # --- Envelope serialization ---
    ser_results: list[BenchResult] = []
    for size, label in zip(PAYLOAD_SIZES, PAYLOAD_LABELS):
        ser_results.append(bench_envelope_serialize(size, label, iterations))
    print_table("Envelope Serialization Round-Trip (base64)", ser_results)

    # --- Session binding ---
    session_results: list[BenchResult] = [
        bench_random_sig_data(iterations),
        bench_establish_session(iterations),
        bench_derive_sig_data(iterations),
        bench_verify_derived_sig_data(iterations),
    ]
    print_table("Session Binding Operations", session_results)

    # --- PSS sign/verify by message size ---
    pss_results: list[BenchResult] = []
    for size, label in zip(PAYLOAD_SIZES, PAYLOAD_LABELS):
        pss_results.append(bench_rsa_sign_varied(size, label, iterations))
        pss_results.append(bench_rsa_verify_varied(size, label, iterations))
    print_table("RSA-4096 PSS Sign/Verify by Message Size", pss_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Benchmark TEE-MCP crypto and protocol overhead (no TDX hardware required).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Number of iterations per benchmark (default: 100)",
    )
    args = parser.parse_args()

    if args.iterations < 4:
        parser.error("--iterations must be >= 4 (required for quantile computation)")

    run_all(args.iterations)
