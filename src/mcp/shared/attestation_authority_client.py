"""Client for centralized attestation authority (attestation-service).

This module is intentionally optional at runtime:
- If grpcio is unavailable, the client is disabled automatically.
- If TEE_MCP_ATTESTATION_SERVICE_ADDR is unset, the client is disabled.

When enabled, MCP Server can:
1. Query latest verifier verdict for a subject.
2. Subscribe to verdict updates for fast cache invalidation on revocation.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

ATTESTATION_ADDR_ENV = "TEE_MCP_ATTESTATION_SERVICE_ADDR"
ATTESTATION_TLS_ENABLED_ENV = "TEE_MCP_ATTESTATION_TLS"
ATTESTATION_TLS_CA_CERT_ENV = "TEE_MCP_ATTESTATION_CA_CERT"
ATTESTATION_TLS_CLIENT_CERT_ENV = "TEE_MCP_ATTESTATION_CLIENT_CERT"
ATTESTATION_TLS_CLIENT_KEY_ENV = "TEE_MCP_ATTESTATION_CLIENT_KEY"
ATTESTATION_TLS_SERVER_NAME_ENV = "TEE_MCP_ATTESTATION_SERVER_NAME"
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_RECONNECT_S = 1.0
MCP_PUBKEY_HASH_PREFIX = "__mcp_pubkey_sha256__:"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


@dataclass(frozen=True)
class AuthorityVerdict:
    """Latest verifier verdict for a subject."""

    subject: str
    verdict: str  # TrustVerdict value (str enum, backward-compatible)
    message: str
    policy_action: str  # none | alert | restart | kill
    attestation_token: str
    verified_at: int
    expires_at: int
    version: int
    source: str


@dataclass(frozen=True)
class AuthorityEvidenceResult:
    """Verifier result for one evidence verification request."""

    verdict: str  # TrustVerdict value (str enum, backward-compatible)
    message: str
    policy_action: str
    attestation_token: str


class AttestationAuthorityClient:
    """Optional gRPC client for attestation-service verdict APIs."""

    def __init__(
        self,
        address: str,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        reconnect_s: float = DEFAULT_RECONNECT_S,
        tls_enabled: bool = False,
        tls_ca_cert: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
        tls_server_name: str | None = None,
    ) -> None:
        self._address = address.strip()
        self._timeout_s = timeout_s
        self._reconnect_s = reconnect_s
        self._tls_enabled = tls_enabled
        self._tls_ca_cert = (tls_ca_cert or "").strip()
        self._tls_client_cert = (tls_client_cert or "").strip()
        self._tls_client_key = (tls_client_key or "").strip()
        self._tls_server_name = (tls_server_name or "").strip()
        self._channel: Any = None
        self._channel_lock = threading.Lock()

        try:
            import grpc  # type: ignore

            from mcp.shared.generated.v1 import attestation_pb2
        except Exception:
            self._grpc = None
            self._pb2 = None
        else:
            self._grpc = grpc
            self._pb2 = attestation_pb2

    @classmethod
    def from_env(cls) -> AttestationAuthorityClient | None:
        """Construct from environment, or None if not configured."""
        address = os.environ.get(ATTESTATION_ADDR_ENV, "").strip()
        if not address:
            return None
        client = cls(
            address,
            tls_enabled=_env_bool(ATTESTATION_TLS_ENABLED_ENV, default=False),
            tls_ca_cert=os.environ.get(ATTESTATION_TLS_CA_CERT_ENV, "").strip() or None,
            tls_client_cert=os.environ.get(ATTESTATION_TLS_CLIENT_CERT_ENV, "").strip() or None,
            tls_client_key=os.environ.get(ATTESTATION_TLS_CLIENT_KEY_ENV, "").strip() or None,
            tls_server_name=os.environ.get(ATTESTATION_TLS_SERVER_NAME_ENV, "").strip() or None,
        )
        if not client.enabled:
            logger.warning(
                "Attestation authority configured at %s but grpc runtime is unavailable",
                address,
            )
        return client

    @property
    def enabled(self) -> bool:
        """True when both address and gRPC runtime are available."""
        return bool(self._address) and self._grpc is not None and self._pb2 is not None

    def close(self) -> None:
        """Close underlying gRPC channel."""
        with self._channel_lock:
            if self._channel is not None:
                try:
                    self._channel.close()
                except Exception:
                    logger.debug("Failed to close attestation authority channel", exc_info=True)
                self._channel = None

    def _get_channel(self) -> Any | None:
        if not self.enabled:
            return None
        with self._channel_lock:
            if self._channel is None:
                self._channel = self._create_channel()
            return self._channel

    def _create_channel(self) -> Any | None:
        if not self.enabled:
            return None
        if not self._tls_enabled:
            return self._grpc.insecure_channel(self._address)

        try:
            root_certificates = self._read_file_bytes(self._tls_ca_cert)
            certificate_chain = self._read_file_bytes(self._tls_client_cert)
            private_key = self._read_file_bytes(self._tls_client_key)
        except OSError:
            logger.warning("Failed to read authority TLS certificate files", exc_info=True)
            return None

        if bool(certificate_chain) != bool(private_key):
            logger.warning(
                "Invalid authority TLS config: both %s and %s are required for mTLS",
                ATTESTATION_TLS_CLIENT_CERT_ENV,
                ATTESTATION_TLS_CLIENT_KEY_ENV,
            )
            return None

        credentials = self._grpc.ssl_channel_credentials(
            root_certificates=root_certificates,
            private_key=private_key,
            certificate_chain=certificate_chain,
        )
        options: list[tuple[str, str]] = []
        if self._tls_server_name:
            options.append(("grpc.ssl_target_name_override", self._tls_server_name))

        return self._grpc.secure_channel(self._address, credentials, options=options)

    def _read_file_bytes(self, path: str) -> bytes | None:
        normalized = path.strip()
        if not normalized:
            return None
        with open(normalized, "rb") as handle:
            return handle.read()

    def _get_latest_rpc(self) -> Any | None:
        channel = self._get_channel()
        if channel is None:
            return None
        return channel.unary_unary(
            "/attestation.v1.AttestationService/GetLatestVerdict",
            request_serializer=self._pb2.GetLatestVerdictRequest.SerializeToString,
            response_deserializer=self._pb2.GetLatestVerdictResponse.FromString,
        )

    def _get_watch_rpc(self) -> Any | None:
        channel = self._get_channel()
        if channel is None:
            return None
        return channel.unary_stream(
            "/attestation.v1.AttestationService/WatchVerdictUpdates",
            request_serializer=self._pb2.WatchVerdictUpdatesRequest.SerializeToString,
            response_deserializer=self._pb2.VerdictUpdate.FromString,
        )

    def _get_verify_rpc(self) -> Any | None:
        channel = self._get_channel()
        if channel is None:
            return None
        return channel.unary_unary(
            "/attestation.v1.AttestationService/VerifyContainerEvidence",
            request_serializer=self._pb2.VerifyRequest.SerializeToString,
            response_deserializer=self._pb2.VerifyResponse.FromString,
        )

    def _get_health_rpc(self) -> Any | None:
        channel = self._get_channel()
        if channel is None:
            return None
        return channel.unary_unary(
            "/attestation.v1.AttestationService/Health",
            request_serializer=self._pb2.HealthRequest.SerializeToString,
            response_deserializer=self._pb2.HealthResponse.FromString,
        )

    def _map_verdict(self, verdict: int) -> str:
        from mcp.shared.trust_verdict import TrustVerdict

        if verdict == self._pb2.VERDICT_TRUSTED:
            return TrustVerdict.TRUSTED
        if verdict == self._pb2.VERDICT_UNTRUSTED:
            return TrustVerdict.UNTRUSTED
        if verdict == self._pb2.VERDICT_STALE:
            return TrustVerdict.STALE
        return TrustVerdict.UNKNOWN

    def _to_authority_verdict(self, record: Any) -> AuthorityVerdict:
        return AuthorityVerdict(
            subject=getattr(record, "subject", ""),
            verdict=self._map_verdict(getattr(record, "verdict", 0)),
            message=getattr(record, "message", ""),
            policy_action=(getattr(record, "policy_action", "") or "none"),
            attestation_token=getattr(record, "attestation_token", ""),
            verified_at=int(getattr(record, "verified_at", 0) or 0),
            expires_at=int(getattr(record, "expires_at", 0) or 0),
            version=int(getattr(record, "version", 0) or 0),
            source=getattr(record, "source", ""),
        )

    def _to_evidence_result(self, record: Any) -> AuthorityEvidenceResult:
        return AuthorityEvidenceResult(
            verdict=self._map_verdict(getattr(record, "verdict", 0)),
            message=getattr(record, "message", ""),
            policy_action=(getattr(record, "policy_action", "") or "none"),
            attestation_token=getattr(record, "attestation_token", ""),
        )

    def get_latest_verdict(self, subject: str) -> AuthorityVerdict | None:
        """Fetch latest verdict for subject. Returns None on not found/error."""
        if not self.enabled or not subject:
            return None

        rpc = self._get_latest_rpc()
        if rpc is None:
            return None

        request = self._pb2.GetLatestVerdictRequest(subject=subject)
        try:
            response = rpc(request, timeout=self._timeout_s)
        except self._grpc.RpcError as error:  # type: ignore[union-attr]
            if error.code() == self._grpc.StatusCode.NOT_FOUND:
                return None
            logger.warning("GetLatestVerdict failed for %s: %s", subject, error)
            return None
        except Exception:
            logger.warning("GetLatestVerdict failed for %s", subject, exc_info=True)
            return None

        return self._to_authority_verdict(response)

    def verify_mcp_evidence(
        self,
        *,
        cgroup_path: str,
        rtmr3: bytes,
        nonce: bytes,
        quote: bytes,
        quote_report_data: bytes,
        public_key_bytes: bytes,
        initial_rtmr3: bytes | None = None,
    ) -> AuthorityEvidenceResult | None:
        """Verify MCP quote evidence through attestation-service."""
        if not self.enabled:
            return None

        rpc = self._get_verify_rpc()
        if rpc is None:
            return None

        if len(rtmr3) != 48:
            logger.warning("verify_mcp_evidence invalid RTMR3 length: %d", len(rtmr3))
            return None
        if len(quote_report_data) != 64:
            logger.warning("verify_mcp_evidence invalid reportdata length: %d", len(quote_report_data))
            return None

        pubkey_hash_hex = hashlib.sha256(public_key_bytes).hexdigest()
        request = self._pb2.VerifyRequest(
            cgroup_path=cgroup_path or "unknown",
            rtmr3=rtmr3.hex(),
            initial_rtmr3=(initial_rtmr3.hex() if initial_rtmr3 is not None else ("00" * 48)),
            nonce=nonce.hex(),
            report_data=quote_report_data.hex(),
            td_quote=quote,
            container_image=f"{MCP_PUBKEY_HASH_PREFIX}{pubkey_hash_hex}",
        )

        try:
            response = rpc(request, timeout=self._timeout_s)
        except self._grpc.RpcError as error:  # type: ignore[union-attr]
            logger.warning("VerifyContainerEvidence failed for cgroup=%s: %s", cgroup_path, error)
            return None
        except Exception:
            logger.warning("VerifyContainerEvidence failed for cgroup=%s", cgroup_path, exc_info=True)
            return None

        return self._to_evidence_result(response)

    def health_check(self) -> bool:
        """Return True when authority health endpoint responds successfully."""
        if not self.enabled:
            return False

        rpc = self._get_health_rpc()
        if rpc is None:
            return False

        try:
            response = rpc(self._pb2.HealthRequest(), timeout=self._timeout_s)
        except self._grpc.RpcError as error:  # type: ignore[union-attr]
            logger.warning("Authority health check failed: %s", error)
            return False
        except Exception:
            logger.warning("Authority health check failed", exc_info=True)
            return False

        status = (getattr(response, "status", "") or "").strip().lower()
        return status in {"ok", "healthy", "serving", "ready"}

    def preflight(self, *, check_health: bool = True) -> tuple[bool, str]:
        """Validate authority client configuration/readiness."""
        if not self.enabled:
            return False, "authority client is disabled"
        if self._get_channel() is None:
            return False, "authority channel setup failed"
        if check_health and not self.health_check():
            return False, "authority health check failed"
        return True, "ok"

    def start_watch(
        self,
        *,
        subjects: list[str],
        after_version: int,
        on_update: Callable[[AuthorityVerdict], None],
        stop_event: threading.Event,
    ) -> threading.Thread | None:
        """Start background watch loop. Returns thread or None if disabled."""
        if not self.enabled:
            return None

        filtered_subjects = [subject for subject in subjects if subject]
        rpc = self._get_watch_rpc()
        if rpc is None:
            return None

        def _run() -> None:
            cursor = max(0, after_version)
            while not stop_event.is_set():
                request = self._pb2.WatchVerdictUpdatesRequest(
                    subjects=filtered_subjects,
                    after_version=cursor,
                )
                try:
                    stream = rpc(request)
                    for update in stream:
                        if stop_event.is_set():
                            return
                        verdict = self._to_authority_verdict(update)
                        if verdict.version > cursor:
                            cursor = verdict.version
                        on_update(verdict)
                except self._grpc.RpcError as error:  # type: ignore[union-attr]
                    if stop_event.is_set():
                        return
                    logger.warning("WatchVerdictUpdates stream ended: %s", error)
                except Exception:
                    if stop_event.is_set():
                        return
                    logger.warning("WatchVerdictUpdates stream ended", exc_info=True)

                if not stop_event.is_set():
                    time.sleep(self._reconnect_s)

        thread = threading.Thread(
            target=_run,
            name="attestation-authority-watch",
            daemon=True,
        )
        thread.start()
        return thread


_DEFAULT_CLIENT_LOCK = threading.Lock()
_DEFAULT_CLIENT: AttestationAuthorityClient | None = None
_DEFAULT_CLIENT_INITIALIZED = False


def get_default_attestation_authority_client() -> AttestationAuthorityClient | None:
    """Get process-wide authority client from env (lazily initialized)."""
    global _DEFAULT_CLIENT, _DEFAULT_CLIENT_INITIALIZED
    with _DEFAULT_CLIENT_LOCK:
        if not _DEFAULT_CLIENT_INITIALIZED:
            _DEFAULT_CLIENT = AttestationAuthorityClient.from_env()
            _DEFAULT_CLIENT_INITIALIZED = True
        return _DEFAULT_CLIENT


def authority_verification_enabled() -> bool:
    """Whether authority-backed evidence verification is configured."""
    client = get_default_attestation_authority_client()
    return bool(client is not None and client.enabled)
