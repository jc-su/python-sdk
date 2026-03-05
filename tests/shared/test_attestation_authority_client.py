"""Tests for attestation authority client configuration helpers."""

from pathlib import Path

from mcp.shared.attestation_authority_client import AttestationAuthorityClient


class _FakeGrpc:
    class StatusCode:
        NOT_FOUND = object()

    class RpcError(Exception):
        pass

    def insecure_channel(self, address: str):  # noqa: ANN001
        return ("insecure", address)

    def ssl_channel_credentials(  # noqa: ANN001
        self,
        *,
        root_certificates=None,
        private_key=None,
        certificate_chain=None,
    ):
        return {
            "root_certificates": root_certificates,
            "private_key": private_key,
            "certificate_chain": certificate_chain,
        }

    def secure_channel(self, address: str, credentials, options=None):  # noqa: ANN001
        return ("secure", address, credentials, options or [])


def test_create_channel_uses_insecure_when_tls_disabled():
    client = AttestationAuthorityClient("127.0.0.1:50051", tls_enabled=False)
    client._grpc = _FakeGrpc()  # type: ignore[attr-defined]
    client._pb2 = object()  # type: ignore[attr-defined]

    channel = client._create_channel()  # type: ignore[attr-defined]
    assert channel == ("insecure", "127.0.0.1:50051")


def test_create_channel_uses_secure_when_tls_enabled(tmp_path: Path):
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    ca.write_bytes(b"ca")
    cert.write_bytes(b"cert")
    key.write_bytes(b"key")

    client = AttestationAuthorityClient(
        "127.0.0.1:50051",
        tls_enabled=True,
        tls_ca_cert=str(ca),
        tls_client_cert=str(cert),
        tls_client_key=str(key),
        tls_server_name="attestation.local",
    )
    client._grpc = _FakeGrpc()  # type: ignore[attr-defined]
    client._pb2 = object()  # type: ignore[attr-defined]

    channel = client._create_channel()  # type: ignore[attr-defined]
    assert channel[0] == "secure"
    assert channel[1] == "127.0.0.1:50051"
    assert ("grpc.ssl_target_name_override", "attestation.local") in channel[3]


def test_preflight_fails_when_health_fails(monkeypatch):
    client = AttestationAuthorityClient("127.0.0.1:50051")
    client._grpc = _FakeGrpc()  # type: ignore[attr-defined]
    client._pb2 = object()  # type: ignore[attr-defined]

    monkeypatch.setattr(client, "_get_channel", lambda: object())
    monkeypatch.setattr(client, "health_check", lambda: False)

    ok, reason = client.preflight(check_health=True)
    assert ok is False
    assert reason == "authority health check failed"


def test_preflight_succeeds_without_health_check(monkeypatch):
    client = AttestationAuthorityClient("127.0.0.1:50051")
    client._grpc = _FakeGrpc()  # type: ignore[attr-defined]
    client._pb2 = object()  # type: ignore[attr-defined]

    monkeypatch.setattr(client, "_get_channel", lambda: object())

    ok, reason = client.preflight(check_health=False)
    assert ok is True
    assert reason == "ok"
