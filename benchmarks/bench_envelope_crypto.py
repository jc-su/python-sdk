"""Benchmark RSA-4096 and AES-256-GCM operations used in TEE-MCP envelope encryption.

Measures:
- RSA-4096 keygen
- RSA-4096 OAEP encrypt/decrypt
- AES-256-GCM encrypt/decrypt at various payload sizes
- Full envelope encrypt vs ResponseKey reuse
"""

from __future__ import annotations

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
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)
    return {
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0.0,
        "min_ms": min(times),
        "max_ms": max(times),
        "iterations": iterations,
    }


def bench_rsa_keygen(iterations: int = 10) -> dict[str, float]:
    """Benchmark RSA-4096 key pair generation."""
    return _bench(rsa.generate_keypair, iterations)


def bench_rsa_encrypt(iterations: int = 100) -> dict[str, float]:
    """Benchmark RSA-4096 OAEP encryption of a 32-byte AES key."""
    keypair = rsa.generate_keypair()
    plaintext = aes.generate_key()  # 32 bytes

    def fn() -> None:
        rsa.encrypt(keypair.public_key, plaintext)

    return _bench(fn, iterations)


def bench_rsa_decrypt(iterations: int = 100) -> dict[str, float]:
    """Benchmark RSA-4096 OAEP decryption."""
    keypair = rsa.generate_keypair()
    plaintext = aes.generate_key()
    ciphertext = rsa.encrypt(keypair.public_key, plaintext)

    def fn() -> None:
        rsa.decrypt(keypair.private_key, ciphertext)

    return _bench(fn, iterations)


def bench_aes_encrypt(payload_size: int = 1024, iterations: int = 1000) -> dict[str, float]:
    """Benchmark AES-256-GCM encryption."""
    key = aes.generate_key()
    data = bytes(payload_size)

    def fn() -> None:
        aes.encrypt(key, data)

    result = _bench(fn, iterations)
    result["payload_bytes"] = payload_size
    return result


def bench_aes_decrypt(payload_size: int = 1024, iterations: int = 1000) -> dict[str, float]:
    """Benchmark AES-256-GCM decryption."""
    key = aes.generate_key()
    data = bytes(payload_size)
    encrypted = aes.encrypt(key, data)

    def fn() -> None:
        aes.decrypt(key, encrypted.nonce, encrypted.ciphertext)

    result = _bench(fn, iterations)
    result["payload_bytes"] = payload_size
    return result


def bench_envelope_encrypt(payload_size: int = 1024, iterations: int = 100) -> dict[str, float]:
    """Benchmark full envelope encryption (RSA + AES)."""
    keypair = rsa.generate_keypair()
    data = bytes(payload_size)

    def fn() -> None:
        envelope_encrypt(keypair.public_key, data)

    result = _bench(fn, iterations)
    result["payload_bytes"] = payload_size
    return result


def bench_response_key_reuse(payload_size: int = 1024, iterations: int = 1000) -> dict[str, float]:
    """Benchmark ResponseKey reuse (AES-only, no RSA)."""
    key = aes.generate_key()
    rk = ResponseKey(aes_key=key)
    data = bytes(payload_size)

    def fn() -> None:
        rk.encrypt(data)

    result = _bench(fn, iterations)
    result["payload_bytes"] = payload_size
    return result


def run_all() -> dict[str, dict[str, float]]:
    """Run all crypto benchmarks and return results."""
    results: dict[str, dict[str, float]] = {}

    results["rsa_keygen"] = bench_rsa_keygen(iterations=10)
    results["rsa_encrypt"] = bench_rsa_encrypt()
    results["rsa_decrypt"] = bench_rsa_decrypt()

    for size in [64, 1024, 16384, 1048576]:
        label = f"aes_encrypt_{size}B"
        results[label] = bench_aes_encrypt(payload_size=size)
        label = f"aes_decrypt_{size}B"
        results[label] = bench_aes_decrypt(payload_size=size)

    results["envelope_encrypt_1KB"] = bench_envelope_encrypt(payload_size=1024)
    results["response_key_reuse_1KB"] = bench_response_key_reuse(payload_size=1024)

    return results


if __name__ == "__main__":
    import json

    results = run_all()
    print(json.dumps(results, indent=2))
