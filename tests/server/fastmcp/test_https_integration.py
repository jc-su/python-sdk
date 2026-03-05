"""HTTPS integration tests for FastMCP Streamable HTTP transport."""

from __future__ import annotations

import datetime
import ipaddress
import multiprocessing
import os
import ssl
import socket
import tempfile
from collections.abc import Generator

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.types import InitializeResult
from tests.test_helpers import wait_for_server


def _free_port() -> int:
    """Get an available localhost TCP port."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _generate_self_signed_cert_for_localhost() -> tuple[str, str]:
    """Generate a temporary self-signed cert/key for localhost and 127.0.0.1."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert_pem)
    cert_file.close()

    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(key_pem)
    key_file.close()

    return cert_file.name, key_file.name


def _run_https_fastmcp_server(port: int, certfile: str, keyfile: str) -> None:  # pragma: no cover
    """Run a minimal FastMCP server over HTTPS for integration testing."""
    mcp = FastMCP(
        name="HTTPSFastMCP",
        host="127.0.0.1",
        port=port,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )
    mcp.run(transport="streamable-http")


@pytest.fixture
def https_server() -> Generator[tuple[int, str], None, None]:
    """Start a temporary HTTPS FastMCP server and yield (port, cert_path)."""
    port = _free_port()
    cert_path, key_path = _generate_self_signed_cert_for_localhost()
    proc = multiprocessing.Process(
        target=_run_https_fastmcp_server,
        args=(port, cert_path, key_path),
        daemon=True,
    )
    proc.start()
    wait_for_server(port)

    try:
        yield port, cert_path
    finally:
        proc.kill()
        proc.join(timeout=2)
        if proc.is_alive():  # pragma: no cover
            proc.terminate()
            proc.join(timeout=2)
        os.unlink(cert_path)
        os.unlink(key_path)


@pytest.mark.anyio
async def test_streamable_http_https_initialize_end_to_end(https_server: tuple[int, str]) -> None:
    """Verify initialize works end-to-end over real HTTPS transport."""
    port, cert_path = https_server
    endpoint = f"https://127.0.0.1:{port}/mcp"
    ssl_context = ssl.create_default_context(cafile=cert_path)

    async with httpx.AsyncClient(verify=ssl_context) as http_client:
        async with streamable_http_client(endpoint, http_client=http_client) as (
            read_stream,
            write_stream,
            _,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                result = await session.initialize()
                assert isinstance(result, InitializeResult)
                assert result.serverInfo.name == "HTTPSFastMCP"
