"""
Generic trusted service with TEE attestation.

For services that aren't MCP (e.g., Model Service / LLM inference).
Provides attestation and encryption without MCP protocol dependencies.

Usage for Model Service (e.g., sglang):

    from mcp.shared.trusted_service import TrustedService

    # Create service
    service = TrustedService(role="ms")

    # Handle attestation request from MCP Client
    @app.post("/attest")
    def attest(request):
        client_nonce = base64.b64decode(request.nonce)
        response = service.handle_attest_start(client_nonce)
        return response

    # Handle attestation completion
    @app.post("/attest/complete")
    def attest_complete(request):
        result = service.handle_attest_complete(request.evidence)
        return result

    # Decrypt incoming request (requires session key from ECDH bootstrap)
    plaintext = service.decrypt_request(encrypted_json)

    # Encrypt response
    encrypted = service.encrypt_response(response_bytes)
"""

import base64
import logging
from dataclasses import dataclass, field

from mcp.shared.crypto.envelope import SessionEncryptedMessage, session_decrypt, session_encrypt
from mcp.shared.secure_channel import (
    AttestationEvidence,
    AttestationResult,
    SecureEndpoint,
)

logger = logging.getLogger(__name__)


@dataclass
class TrustedService:
    """
    Generic trusted service with TEE attestation.

    Can be used by any service (Model Service, custom APIs, etc.)
    to provide mutual attestation and encrypted communication.
    """
    role: str
    allowed_client_rtmr3: list[str] | None = None
    _endpoint: SecureEndpoint = field(init=False)

    def __post_init__(self) -> None:
        self._endpoint = SecureEndpoint.create(
            role=self.role,
        )

    # =========================================================================
    # Attestation Protocol
    # =========================================================================

    def handle_attest_start(self, client_nonce: bytes, client_role: str = "client") -> dict:
        """
        Handle start of mutual attestation.

        Args:
            client_nonce: Nonce from MCP Client
            client_role: Role identifier for the client

        Returns:
            Dict with server evidence + server nonce for client
        """
        # Generate our attestation evidence
        evidence = self._endpoint.create_evidence(client_nonce)

        # Generate nonce for client to respond to
        server_nonce = self._endpoint.generate_nonce(peer_role=client_role)

        result = evidence.to_dict()
        result["server_nonce"] = base64.b64encode(server_nonce).decode()

        logger.info(f"Attestation started with {client_role}, awaiting client evidence")
        return result

    def handle_attest_complete(
        self,
        evidence_dict: dict,
        client_role: str = "client",
    ) -> dict:
        """
        Handle attestation completion - verify client's evidence.

        Args:
            evidence_dict: Client's attestation evidence
            client_role: Role identifier for the client

        Returns:
            Dict with success/failure status
        """
        try:
            evidence = AttestationEvidence.from_dict(evidence_dict)

            # Verify client
            result = self._endpoint.verify_peer(
                evidence,
                peer_role=client_role,
                allowed_rtmr3=self.allowed_client_rtmr3,
            )

            if result.valid:
                logger.info(f"Client attestation verified: role={client_role}, cgroup={evidence.cgroup}")
                return {
                    "success": True,
                    "message": "Mutual attestation complete",
                }
            else:
                logger.warning(f"Client attestation failed: {result.error}")
                return {
                    "success": False,
                    "error": result.error,
                }
        except Exception as e:
            logger.exception("Failed to verify client attestation")
            return {
                "success": False,
                "error": str(e),
            }

    def verify_client(
        self,
        evidence: AttestationEvidence,
        expected_nonce: bytes | None = None,
        client_role: str = "client",
    ) -> AttestationResult:
        """Verify a client's attestation evidence."""
        return self._endpoint.verify_peer(
            evidence,
            expected_nonce=expected_nonce,
            peer_role=client_role,
            allowed_rtmr3=self.allowed_client_rtmr3,
        )

    # =========================================================================
    # Encryption / Decryption (requires ECDH session key)
    # =========================================================================

    def decrypt_request(self, encrypted_json: str) -> bytes:
        """Decrypt an encrypted request from client using session key."""
        if self._endpoint.session_key is None:
            raise RuntimeError("Session key not established — complete ECDH bootstrap first")
        message = SessionEncryptedMessage.from_json(encrypted_json)
        return session_decrypt(self._endpoint.session_key, message)

    def encrypt_response(self, plaintext: bytes) -> str:
        """Encrypt a response for client using session key."""
        if self._endpoint.session_key is None:
            raise RuntimeError("Session key not established — complete ECDH bootstrap first")
        message = session_encrypt(self._endpoint.session_key, plaintext)
        return message.to_json()

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def public_key_bytes(self) -> bytes:
        """Get service's X25519 public key (32 raw bytes)."""
        return self._endpoint.public_key_bytes

    @property
    def is_client_attested(self) -> bool:
        """Check if any client has been attested."""
        return self._endpoint.is_attested

    def get_client_info(self, role: str = "client") -> dict | None:
        """Get attested client's information."""
        peer = self._endpoint.get_peer(role)
        if peer is None:
            return None
        return {
            "cgroup": peer.cgroup,
            "rtmr3": peer.rtmr3.hex(),
            "role": peer.role,
        }


@dataclass
class TrustedServiceClient:
    """
    Client for connecting to a TrustedService.

    Used by MCP Client to connect to Model Service.
    """
    role: str
    allowed_server_rtmr3: list[str] | None = None
    _endpoint: SecureEndpoint = field(init=False)
    _server_attested: bool = field(default=False, init=False)
    _mutual_attested: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self._endpoint = SecureEndpoint.create(
            role=self.role,
        )

    async def perform_attestation(
        self,
        attest_start_fn,
        attest_complete_fn,
    ) -> AttestationResult:
        """
        Perform mutual attestation with service.

        Args:
            attest_start_fn: Async function to call service's attest endpoint
                             Takes (nonce: str) -> dict
            attest_complete_fn: Async function to call service's attest/complete endpoint
                                Takes (evidence: dict) -> dict

        Returns:
            AttestationResult
        """
        # Step 1: Generate our nonce and call attest_start
        client_nonce = self._endpoint.generate_nonce(peer_role="server")
        client_nonce_b64 = base64.b64encode(client_nonce).decode()

        response = await attest_start_fn(client_nonce_b64)

        # Extract server's nonce
        server_nonce_b64 = response.pop("server_nonce", None)
        server_nonce = base64.b64decode(server_nonce_b64) if server_nonce_b64 else None

        # Step 2: Verify server's evidence
        server_evidence = AttestationEvidence.from_dict(response)
        result = self._endpoint.verify_peer(
            server_evidence,
            expected_nonce=client_nonce,
            peer_role="server",
            allowed_rtmr3=self.allowed_server_rtmr3,
        )

        if not result.valid:
            logger.error(f"Server attestation failed: {result.error}")
            return result

        self._server_attested = True
        logger.info(f"Server attestation verified: cgroup={server_evidence.cgroup}")

        # Step 3: Send our attestation if server provided nonce
        if server_nonce:
            client_evidence = self._endpoint.create_evidence(server_nonce)
            complete_response = await attest_complete_fn(client_evidence.to_dict())

            if not complete_response.get("success"):
                error = complete_response.get("error", "Unknown error")
                logger.error(f"Mutual attestation failed: {error}")
                return AttestationResult(valid=False, error=error)

            self._mutual_attested = True
            logger.info("Mutual attestation complete")

        return result

    def encrypt_request(self, plaintext: bytes) -> str:
        """Encrypt request for service using session key."""
        if not self._server_attested:
            raise RuntimeError("Server not attested yet")
        if self._endpoint.session_key is None:
            raise RuntimeError("Session key not established — complete ECDH bootstrap first")
        message = session_encrypt(self._endpoint.session_key, plaintext)
        return message.to_json()

    def decrypt_response(self, encrypted_json: str) -> bytes:
        """Decrypt response from service using session key."""
        if self._endpoint.session_key is None:
            raise RuntimeError("Session key not established — complete ECDH bootstrap first")
        message = SessionEncryptedMessage.from_json(encrypted_json)
        return session_decrypt(self._endpoint.session_key, message)

    @property
    def is_encrypted(self) -> bool:
        """Check if communication is encrypted."""
        return self._server_attested

    @property
    def is_mutual_attested(self) -> bool:
        """Check if mutual attestation is complete."""
        return self._mutual_attested

    @property
    def server_cgroup(self) -> str:
        """Get server's cgroup."""
        peer = self._endpoint.get_peer("server")
        return peer.cgroup if peer else ""

    @property
    def server_rtmr3(self) -> bytes:
        """Get server's RTMR3."""
        peer = self._endpoint.get_peer("server")
        return peer.rtmr3 if peer else bytes(48)
