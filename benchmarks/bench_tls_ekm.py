"""Benchmark: TLS EKM extraction overhead.

Measures the cost of extracting Exported Keying Material (EKM) from a
TLS connection via ctypes, compared to baseline operations.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import tempfile
import time


def _generate_self_signed_cert():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    key_file.close()
    return cert_file.name, key_file.name


def run_benchmarks(iterations: int = 1000) -> dict:
    from mcp.shared.tls_ekm import extract_ekm, is_ekm_available

    if not is_ekm_available():
        print("  libssl not available — skipping TLS EKM benchmarks")
        return {}

    cert_path, key_path = _generate_self_signed_cert()
    results = {}

    try:
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        ssl_obj_holder = [None]

        async def run():
            async def handler(reader, writer):
                await asyncio.sleep(5)
                writer.close()

            server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_ctx)
            addr = server.sockets[0].getsockname()

            reader, writer = await asyncio.open_connection("127.0.0.1", addr[1], ssl=client_ctx)
            ssl_obj_holder[0] = writer.transport.get_extra_info("ssl_object")

            # Benchmark EKM extraction
            start = time.perf_counter()
            for _ in range(iterations):
                extract_ekm(ssl_obj_holder[0])
            elapsed = time.perf_counter() - start
            results["ekm_extraction"] = {
                "iterations": iterations,
                "total_ms": elapsed * 1000,
                "per_call_us": (elapsed / iterations) * 1_000_000,
            }

            # Benchmark get_channel_binding for comparison
            start = time.perf_counter()
            for _ in range(iterations):
                ssl_obj_holder[0].get_channel_binding("tls-unique")
            elapsed = time.perf_counter() - start
            results["channel_binding_tls_unique"] = {
                "iterations": iterations,
                "total_ms": elapsed * 1000,
                "per_call_us": (elapsed / iterations) * 1_000_000,
            }

            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()

        asyncio.run(run())
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)

    return results


if __name__ == "__main__":
    print("TLS EKM Extraction Benchmark")
    print("=" * 50)
    results = run_benchmarks()
    for name, data in results.items():
        print(f"\n  {name}:")
        print(f"    {data['iterations']} iterations")
        print(f"    Total: {data['total_ms']:.2f} ms")
        print(f"    Per call: {data['per_call_us']:.2f} us")
