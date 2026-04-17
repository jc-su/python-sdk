"""Secure channel with mutual TEE attestation for two-party trust.

Maps to IETF RATS (RFC 9334) architecture:
- Container running MCP code    → Attester
- SecureEndpoint.verify_peer_attestation()  → Verifier
- TrustedServerSession / TrustedClientSession → Relying Party
- TDX quote                     → Evidence
- AttestationResult             → Attestation Result
- attestation-service           → Verifier Authority

Attestation Model:
- Bootstrap (initialize): Background-Check Model (verifier-chosen nonce / challenge)
- Tool calls: Session-bound symmetric encryption (ECDH-derived session key)

Trust Model:
- MCP Client: Orchestrates agent, connects to MCP Server
- MCP Server: Provides tools, handles sensitive operations

Protocol:
1. MCP Client ↔ MCP Server: Mutual attestation during initialize (ECDH key exchange)
2. Session-key encryption + HMAC authentication on tools/call

Session-level channel binding (post-bootstrap):
- session_id = SHA256(client_pubkey || server_pubkey || init_nonce_client || init_nonce_server)
- nonce = HMAC-SHA256(session_id, entropy || counter)
- Prevents cross-session evidence relay and provides ordering guarantees

ECDH + HKDF provides message-level security:
- session_key for AES-256-GCM encryption
- mac_key for HMAC-SHA256 challenge authentication
TLS is still required alongside for metadata confidentiality.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from mcp.shared.crypto import x25519
from mcp.shared.crypto.envelope import EnvelopePayload
from mcp.shared.crypto.x25519 import X25519PublicKey
from mcp.shared.tdx import (
    generate_quote,
    get_container_rtmr3,
    get_current_cgroup,
    parse_quote,
)

logger = logging.getLogger(__name__)

NONCE_SIZE = 32
MAX_AGE_MS = 300_000  # 5 minutes


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class AttestationResult:
    """Result of attestation verification."""

    valid: bool
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = field(default_factory=lambda: bytes(48))


@dataclass
class AttestationEvidence:
    """TEE attestation evidence for a single party.

    The canonical subject is `workload_id` (stable across restarts). `cgroup`
    is retained for audit / legacy ingestion paths but is NOT used for trust
    decisions. `event_log` carries the kernel's per-container IMA log bytes
    that the verifier replays against reference values.
    """

    quote: bytes  # TDX quote
    public_key: bytes  # X25519 raw public key (32 bytes)
    nonce: bytes  # Nonce this evidence responds to
    cgroup: str  # Container cgroup (audit/trace only)
    rtmr3: bytes  # Container's virtual RTMR3 (audit/trace only)
    timestamp_ms: int
    role: str = ""  # Role: "client", "server"
    workload_id: str = ""  # Stable workload identity (primary subject)
    event_log: bytes = b""  # Kernel per-container event log bytes

    def to_dict(self) -> dict[str, Any]:
        evidence_dict = {
            "quote": base64.b64encode(self.quote).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "cgroup": self.cgroup,
            "rtmr3": self.rtmr3.hex(),
            "timestamp_ms": self.timestamp_ms,
            "role": self.role,
            "workload_id": self.workload_id,
            "event_log": base64.b64encode(self.event_log).decode(),
        }
        return evidence_dict

    @classmethod
    def from_dict(cls, data: dict) -> AttestationEvidence:
        event_log_b64 = data.get("event_log", "")
        event_log = base64.b64decode(event_log_b64) if event_log_b64 else b""
        return cls(
            quote=base64.b64decode(data["quote"]),
            public_key=base64.b64decode(data["public_key"]),
            nonce=base64.b64decode(data["nonce"]),
            cgroup=data["cgroup"],
            rtmr3=bytes.fromhex(data["rtmr3"]),
            timestamp_ms=data["timestamp_ms"],
            role=data.get("role", ""),
            workload_id=data.get("workload_id", ""),
            event_log=event_log,
        )


@dataclass
class PeerInfo:
    """Information about an attested peer."""

    public_key: X25519PublicKey
    public_key_bytes: bytes  # 32-byte raw key for session derivation
    cgroup: str
    rtmr3: bytes
    role: str


class RTMR3TransitionPolicy(enum.Enum):
    """Policy for handling RTMR3 changes between attestation calls."""

    ACCEPT = "accept"
    REJECT = "reject"
    LOG_AND_ACCEPT = "log_and_accept"


@dataclass
class PeerStateChange:
    """Record of a peer's RTMR3 state change between attestation calls."""

    peer_role: str
    old_rtmr3: bytes
    new_rtmr3: bytes
    old_cgroup: str
    new_cgroup: str
    timestamp_ms: int


# =============================================================================
# Helper Functions
# =============================================================================


def _bind_nonce_and_key(nonce: bytes, public_key_raw: bytes) -> bytes:
    """Compute reportdata binding nonce and public key.

    Args:
        nonce: Random nonce bytes.
        public_key_raw: Raw X25519 public key bytes (32 bytes).

    Returns:
        64 bytes: SHA256(nonce) || SHA256(public_key_raw)
    """
    return hashlib.sha256(nonce).digest() + hashlib.sha256(public_key_raw).digest()


def _verify_quote_via_authority(
    evidence: AttestationEvidence,
    *,
    expected_nonce: bytes,
    quote_reportdata: bytes,
) -> tuple[bool, str]:
    """Verify quote through attestation-service (when configured).

    Migrated to the canonical `VerifyWorkload` RPC. Evidence is keyed by the
    stable `workload_id` (from AttestationEvidence.workload_id; falls back
    to the cgroup path only if the evidence predates the migration, which
    will fail verification and is the intended "loud break" signal).
    """
    del quote_reportdata  # bound into the quote by trustd; AS re-derives
    try:
        from mcp.shared.attestation_authority_client import get_default_attestation_authority_client
    except Exception:
        return False, "Authority verifier client unavailable"

    client = get_default_attestation_authority_client()
    if client is None or not client.enabled:
        return False, "Authority verifier not configured"

    workload_id = getattr(evidence, "workload_id", "") or evidence.cgroup
    event_log = getattr(evidence, "event_log", b"") or b""

    result = client.verify_workload_evidence(
        workload_id=workload_id,
        td_quote=evidence.quote,
        event_log=event_log,
        nonce=expected_nonce,
        peer_pk=evidence.public_key,
    )
    if result is None:
        return False, "Authority verifier request failed"

    from mcp.shared.trust_verdict import TrustVerdict

    if result.verdict != TrustVerdict.TRUSTED:
        return False, f"Authority verifier verdict={result.verdict}: {result.message}"
    return True, ""


def _verify_attestation_evidence(
    evidence: AttestationEvidence,
    expected_nonce: bytes,
    allowed_rtmr3: list[str] | None = None,
) -> tuple[bool, str, bytes | None]:
    """Verify attestation evidence.

    Authority-only mode:
    - reportdata = SHA256(nonce) || SHA256(pubkey)
    - quote is always verified via attestation-service.

    Returns: (valid, error, public_key_raw)
    """
    # Check evidence freshness
    age = int(time.time() * 1000) - evidence.timestamp_ms
    if age > MAX_AGE_MS:
        return False, f"Evidence too old: {age}ms", None
    if age < -MAX_AGE_MS:
        return False, f"Evidence timestamp in future: {-age}ms ahead", None

    # Parse quote
    quote = parse_quote(evidence.quote)
    if quote is None:
        return False, "Failed to parse quote", None

    # Bind RTMR3 to quote measurements
    quote_rtmr3 = quote.measurements.rtmr3
    if evidence.rtmr3 != quote_rtmr3:
        return False, "RTMR3 mismatch between evidence and quote", None

    # Verify nonce-based reportdata binding.
    expected_reportdata = _bind_nonce_and_key(expected_nonce, evidence.public_key)
    if not hmac.compare_digest(quote.reportdata, expected_reportdata):
        return False, "Reportdata mismatch - nonce/key not bound correctly", None

    valid, err = _verify_quote_via_authority(
        evidence,
        expected_nonce=expected_nonce,
        quote_reportdata=quote.reportdata,
    )
    if not valid:
        return False, f"Authority quote verification failed: {err}", None

    # Check RTMR3 patterns (ALWAYS checked)
    if allowed_rtmr3:
        rtmr3_hex = quote_rtmr3.hex()
        if not any(rtmr3_hex.startswith(p.rstrip("*")) for p in allowed_rtmr3):
            return False, f"RTMR3 not in allowed list: {rtmr3_hex[:16]}...", None

    return True, "", evidence.public_key


# =============================================================================
# Secure Endpoint
# =============================================================================


@dataclass
class SecureEndpoint:
    """One endpoint of a secure channel with two-party mutual attestation.

    Each endpoint has its own X25519 key pair for ECDH key agreement.

    Attester-side mode:
    1. Fresh TDX quote for bootstrap attestation.
    2. Authority verification is required for bootstrap evidence.
    3. Post-bootstrap uses derived session keys (no more TDX quotes).
    """

    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey
    public_key_bytes: bytes = field(default=b"", repr=False)
    role: str = ""  # "client", "server"

    # Verified peers (after attestation)
    peers: dict[str, PeerInfo] = field(default_factory=dict)

    # RTMR3 transition detection
    rtmr3_transition_policy: RTMR3TransitionPolicy = RTMR3TransitionPolicy.LOG_AND_ACCEPT
    on_peer_state_change: Callable[[PeerStateChange], RTMR3TransitionPolicy] | None = None
    _peer_state_history: list[PeerStateChange] = field(default_factory=list, repr=False)

    # Session state
    session_id: bytes | None = field(default=None, repr=False)
    _send_counter: int = field(default=0, repr=False)
    _recv_counter: int = field(default=0, repr=False)

    # ECDH-derived keys
    kek: bytes | None = field(default=None, repr=False)  # key-encryption key (AES Key Wrap)
    mac_key: bytes | None = field(default=None, repr=False)  # HMAC-SHA256 for auth

    # Bootstrap challenge
    _bootstrap_challenge: bytes | None = field(default=None, repr=False)

    # Self-check: initial RTMR3 captured at session start (server only)
    _initial_rtmr3: bytes | None = field(default=None, repr=False)

    # Nonces for attestation
    _pending_nonces: dict[str, bytes] = field(default_factory=dict, repr=False)

    @classmethod
    def create(
        cls,
        role: str = "",
    ) -> SecureEndpoint:
        """Create endpoint with new X25519 key pair.

        Args:
            role: Role identifier ("client", "server")
        """
        keypair = x25519.generate_keypair()
        return cls(
            private_key=keypair.private_key,
            public_key=keypair.public_key,
            public_key_bytes=x25519.export_public_key(keypair.public_key),
            role=role,
        )

    def generate_nonce(self, peer_role: str = "default") -> bytes:
        """Generate nonce for attestation challenge."""
        nonce = secrets.token_bytes(NONCE_SIZE)
        self._pending_nonces[peer_role] = nonce
        return nonce

    def get_pending_nonce(self, peer_role: str = "default") -> bytes | None:
        """Get pending nonce for a peer."""
        return self._pending_nonces.get(peer_role)

    # =========================================================================
    # Session establishment
    # =========================================================================

    def establish_session(
        self,
        peer_pubkey_raw: bytes,
        my_init_nonce: bytes,
        peer_init_nonce: bytes,
    ) -> bytes:
        """Compute session_id and derive keys after bootstrap key exchange.

        1. X25519 ECDH → shared_secret
        2. HKDF-SHA256 → KEK (key-encryption key) + mac_key
        3. session_id = SHA256(client_pk || server_pk || client_init_nonce || server_init_nonce)

        Args:
            peer_pubkey_raw: Peer's raw X25519 public key (32 bytes).
            my_init_nonce: Our nonce from the initialize exchange.
            peer_init_nonce: Peer's nonce from the initialize exchange.

        Returns:
            The computed session_id (32 bytes).
        """
        peer_pub = x25519.load_public_key(peer_pubkey_raw)
        shared_secret = x25519.compute_shared_secret(self.private_key, peer_pub)

        # Canonical ordering: client first, server second
        if self.role == "client":
            client_pk = self.public_key_bytes
            server_pk = peer_pubkey_raw
            client_init_nonce = my_init_nonce
            server_init_nonce = peer_init_nonce
        else:
            client_pk = peer_pubkey_raw
            server_pk = self.public_key_bytes
            client_init_nonce = peer_init_nonce
            server_init_nonce = my_init_nonce

        keys = x25519.derive_keys(shared_secret, client_pk, server_pk)
        self.kek = keys.kek
        self.mac_key = keys.mac_key

        binding = client_pk + server_pk + client_init_nonce + server_init_nonce
        self.session_id = hashlib.sha256(binding).digest()
        self._send_counter = 0
        self._recv_counter = 0
        logger.debug("Session established: %s", self.session_id.hex()[:16])
        return self.session_id

    # =========================================================================
    # Counter management (replay protection)
    # =========================================================================

    def next_send_counter(self) -> int:
        """Get next send counter and increment."""
        counter = self._send_counter
        if counter >= 2**64 - 1:
            raise OverflowError("Send counter exhausted — reestablish session")
        self._send_counter += 1
        return counter

    def verify_recv_counter(self, counter: int) -> None:
        """Verify received counter is monotonically increasing.

        Raises:
            ValueError: If counter is stale (replay detected).
        """
        if counter < self._recv_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._recv_counter}")
        self._recv_counter = counter + 1

    # =========================================================================
    # Session authentication (for tools/list)
    # =========================================================================

    def create_session_auth(self, counter: int) -> bytes:
        """Create HMAC-SHA256(mac_key, counter) for session envelope authentication."""
        if self.mac_key is None:
            raise ValueError("MAC key not established")
        return hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()

    def verify_session_auth(self, counter: int, auth_tag: bytes) -> bool:
        """Verify session auth tag. Constant-time comparison."""
        if self.mac_key is None:
            return False
        expected = hmac.new(self.mac_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        return hmac.compare_digest(expected, auth_tag)

    # =========================================================================
    # Bootstrap challenge
    # =========================================================================

    def generate_bootstrap_challenge(self) -> bytes:
        """Generate a random challenge for bootstrap Background-Check Model.

        Returns:
            32-byte random challenge.
        """
        self._bootstrap_challenge = secrets.token_bytes(NONCE_SIZE)
        return self._bootstrap_challenge

    def consume_bootstrap_challenge(self) -> bytes | None:
        """Return and clear the pending bootstrap challenge (one-time use).

        Returns:
            The pending challenge bytes, or None if no challenge is pending.
        """
        challenge = self._bootstrap_challenge
        self._bootstrap_challenge = None
        return challenge

    # =========================================================================
    # HMAC challenge (Message 3 key possession proof)
    # =========================================================================

    def create_challenge_mac(self, challenge: bytes) -> bytes:
        """Create HMAC-SHA256(mac_key, challenge) for Message 3.

        Proves possession of the ECDH-derived mac_key.

        Raises:
            ValueError: If mac_key is not established.
        """
        if self.mac_key is None:
            raise ValueError("MAC key not established - call establish_session() first")
        return x25519.hmac_challenge(self.mac_key, challenge)

    def verify_challenge_mac(self, challenge: bytes, mac: bytes) -> bool:
        """Verify HMAC-SHA256 challenge MAC from Message 3.

        Raises:
            ValueError: If mac_key is not established.
        """
        if self.mac_key is None:
            raise ValueError("MAC key not established - call establish_session() first")
        return x25519.verify_challenge_mac(self.mac_key, challenge, mac)

    # =========================================================================
    # Envelope encryption (post-bootstrap) — per-message DEK + AES Key Wrap
    # =========================================================================

    def wrap_and_encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> EnvelopePayload:
        """Encrypt with per-message DEK wrapped by KEK.

        Returns:
            EnvelopePayload with wrapped_key, iv, and ciphertext.

        Raises:
            ValueError: If KEK is not established.
        """
        if self.kek is None:
            raise ValueError("KEK not established — complete bootstrap first")
        from mcp.shared.crypto.envelope import envelope_encrypt

        return envelope_encrypt(self.kek, plaintext, aad=aad)

    def unwrap_and_decrypt(self, payload: EnvelopePayload, *, aad: bytes | None = None) -> bytes:
        """Unwrap DEK and decrypt payload.

        Args:
            payload: EnvelopePayload with wrapped_key, iv, and ciphertext.

        Returns:
            Decrypted plaintext.

        Raises:
            ValueError: If KEK is not established.
        """
        if self.kek is None:
            raise ValueError("KEK not established — complete bootstrap first")
        from mcp.shared.crypto.envelope import envelope_decrypt

        return envelope_decrypt(self.kek, payload, aad=aad)

    # =========================================================================
    # Attestation evidence (bootstrap only)
    # =========================================================================

    def create_attestation(self, peer_nonce: bytes) -> AttestationEvidence:
        """Create attestation evidence responding to peer's nonce.

        Prefers the canonical trustd.AttestWorkload path when a workload_id
        is configured (env `TEE_MCP_WORKLOAD_ID` or pre-set on the channel):
        trustd bundles the TDX quote with the kernel's per-container event
        log in a single call, which is the only path that populates
        `event_log` correctly — the fork process cannot read securityfs
        directly (root-only 0440).

        Falls back to the legacy (quote-only, no event_log) path when no
        workload_id is available; AS.VerifyWorkload will then return
        Untrusted, which is the intended "loud break" signal.
        """
        workload_id = (getattr(self, "workload_id", "") or os.environ.get("TEE_MCP_WORKLOAD_ID", "")).strip()
        if workload_id:
            from mcp.shared.trustd_client import get_trustd_client

            client = get_trustd_client()
            if client is not None:
                try:
                    bundle = client.attest_workload(
                        workload_id=workload_id,
                        nonce=peer_nonce,
                        peer_pk=self.public_key_bytes,
                    )
                except Exception as e:
                    logger.warning("trustd.AttestWorkload failed; falling back: %s", e)
                else:
                    quote_bytes: bytes = bundle["td_quote"]
                    event_log: bytes = bundle.get("event_log", b"")
                    cgroup = bundle.get("cgroup_path", "")
                    rtmr3 = bytes(48)
                    parsed = parse_quote(quote_bytes)
                    if parsed is not None:
                        rtmr3 = parsed.measurements.rtmr3
                    return AttestationEvidence(
                        quote=quote_bytes,
                        public_key=self.public_key_bytes,
                        nonce=peer_nonce,
                        cgroup=cgroup,
                        rtmr3=rtmr3,
                        timestamp_ms=int(time.time() * 1000),
                        role=self.role,
                        workload_id=workload_id,
                        event_log=event_log,
                    )

        # Legacy / fallback: quote-only (no event_log).
        reportdata = _bind_nonce_and_key(peer_nonce, self.public_key_bytes)
        quote = generate_quote(reportdata)
        cgroup = get_current_cgroup()
        rtmr3 = get_container_rtmr3(cgroup)
        parsed = parse_quote(quote)
        if parsed is not None:
            rtmr3 = parsed.measurements.rtmr3

        return AttestationEvidence(
            quote=quote,
            public_key=self.public_key_bytes,
            nonce=peer_nonce,
            cgroup=cgroup,
            rtmr3=rtmr3,
            timestamp_ms=int(time.time() * 1000),
            role=self.role,
        )

    def verify_peer_attestation(
        self,
        evidence: AttestationEvidence,
        expected_nonce: bytes | None = None,
        peer_role: str = "default",
        allowed_rtmr3: list[str] | None = None,
    ) -> AttestationResult:
        """Verify peer's attestation evidence.

        On success, stores peer's info for session key derivation.
        """
        if expected_nonce is None:
            expected_nonce = self._pending_nonces.get(peer_role)
            if expected_nonce is None:
                return AttestationResult(valid=False, error=f"No pending nonce for {peer_role}")

        valid, err, peer_pubkey_bytes = _verify_attestation_evidence(
            evidence,
            expected_nonce,
            allowed_rtmr3,
        )
        if not valid:
            return AttestationResult(valid=False, error=err)

        # Treat explicit peer_role as canonical; evidence.role is metadata
        # from an untrusted peer and must not remap storage keys.
        effective_role = peer_role
        if peer_role != "default" and evidence.role and evidence.role != peer_role:
            return AttestationResult(
                valid=False,
                error=f"Peer role mismatch: expected {peer_role}, got {evidence.role}",
            )
        if peer_role == "default" and evidence.role:
            effective_role = evidence.role

        # RTMR3 transition detection: compare with existing peer before overwriting
        existing_peer = self.peers.get(effective_role)
        if existing_peer is not None and existing_peer.rtmr3 != evidence.rtmr3:
            change = PeerStateChange(
                peer_role=effective_role,
                old_rtmr3=existing_peer.rtmr3,
                new_rtmr3=evidence.rtmr3,
                old_cgroup=existing_peer.cgroup,
                new_cgroup=evidence.cgroup,
                timestamp_ms=int(time.time() * 1000),
            )
            self._peer_state_history.append(change)

            # Determine policy: callback overrides default
            if self.on_peer_state_change is not None:
                policy = self.on_peer_state_change(change)
            else:
                policy = self.rtmr3_transition_policy

            if policy == RTMR3TransitionPolicy.REJECT:
                logger.warning(
                    "RTMR3 transition rejected for peer %s: %s -> %s",
                    effective_role,
                    existing_peer.rtmr3.hex()[:16],
                    evidence.rtmr3.hex()[:16],
                )
                return AttestationResult(
                    valid=False,
                    error=f"RTMR3 changed for peer {effective_role}",
                )
            elif policy == RTMR3TransitionPolicy.LOG_AND_ACCEPT:
                logger.info(
                    "RTMR3 transition detected for peer %s: %s -> %s",
                    effective_role,
                    existing_peer.rtmr3.hex()[:16],
                    evidence.rtmr3.hex()[:16],
                )

        # Store peer info (peer_pubkey_bytes is guaranteed non-None after valid=True)
        assert peer_pubkey_bytes is not None
        peer_pubkey = x25519.load_public_key(peer_pubkey_bytes)
        peer_info = PeerInfo(
            public_key=peer_pubkey,
            public_key_bytes=peer_pubkey_bytes,
            cgroup=evidence.cgroup,
            rtmr3=evidence.rtmr3,
            role=effective_role,
        )
        self.peers[peer_info.role] = peer_info

        # Clear pending nonce
        self._pending_nonces.pop(peer_role, None)

        return AttestationResult(
            valid=True,
            cgroup=evidence.cgroup,
            rtmr3=evidence.rtmr3,
        )

    def get_peer(self, role: str) -> PeerInfo | None:
        """Get verified peer by role."""
        return self.peers.get(role)

    @property
    def peer_state_history(self) -> list[PeerStateChange]:
        """Get the history of RTMR3 state changes for peers."""
        return list(self._peer_state_history)

    @property
    def is_attested(self) -> bool:
        """Check if any peer has been attested."""
        return len(self.peers) > 0

    # =========================================================================
    # Convenience properties
    # =========================================================================

    @property
    def peer_cgroup(self) -> str:
        """Get first peer's cgroup."""
        if self.peers:
            return next(iter(self.peers.values())).cgroup
        return ""

    @property
    def peer_rtmr3(self) -> bytes:
        """Get first peer's RTMR3."""
        if self.peers:
            return next(iter(self.peers.values())).rtmr3
        return bytes(48)

    @property
    def server_cgroup(self) -> str:
        """Get peer's cgroup (for client use)."""
        return self.peer_cgroup

    @property
    def server_rtmr3(self) -> bytes:
        """Get peer's RTMR3 (for client use)."""
        return self.peer_rtmr3
