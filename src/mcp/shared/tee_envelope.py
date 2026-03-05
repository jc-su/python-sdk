"""Per-call TEE envelope: attestation + encryption in a single _meta.tee field.

Bootstrap flow (Messages 1 & 2 — with TDX quotes):
1. initialize request  — plaintext + evidence (key exchange)
2. initialize response — plaintext + evidence (key exchange + challenge)

Post-bootstrap flow (Message 3 + tools/call — no TDX quotes):
3. initialized notif   — HMAC challenge-response (key possession proof)
4+ tools/call only     — encrypted with session_key (AES-256-GCM)

Lightweight session envelope (no TDX quote):
- tools/list: session-bound sig_data + optional trust metadata
"""

from __future__ import annotations

import base64
import binascii
import hmac as hmac_mod
import json
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from mcp.shared.crypto.envelope import SessionEncryptedMessage

if TYPE_CHECKING:
    from mcp.shared.secure_channel import SecureEndpoint

logger = logging.getLogger(__name__)

SIG_DATA_SIZE = 32


# =============================================================================
# Bootstrap envelopes (Messages 1 & 2 — with TDX quote)
# =============================================================================


def create_request_envelope(
    endpoint: SecureEndpoint,
    params_dict: dict,
    peer_role: str = "server",
    *,
    workload_id: str | None = None,
    override_nonce: bytes | None = None,
) -> tuple[dict, None]:
    """Create a _meta.tee envelope for a bootstrap request (Message 1).

    Includes TDX quote + X25519 public key. Plaintext only (peer key not known yet).

    Args:
        endpoint: Our SecureEndpoint with X25519 key pair.
        params_dict: The full params dict for the JSON-RPC request.
        peer_role: Role of the peer we're sending to.
        workload_id: Optional workload identity for policy resolution.
        override_nonce: Optional nonce to use instead of random sig_data
            (for challenge-response during bootstrap).

    Returns:
        Tuple of (tee_dict to inject as _meta.tee, None).
    """
    session_id = getattr(endpoint, "session_id", None)

    # Use session-bound sig_data if available, otherwise random
    if override_nonce is not None:
        sig_data = override_nonce
    elif session_id is not None:
        entropy = secrets.token_bytes(SIG_DATA_SIZE)
        sig_data, counter = endpoint.derive_sig_data(entropy)
    else:
        sig_data = secrets.token_bytes(SIG_DATA_SIZE)
        entropy = None

    evidence = endpoint.create_evidence(sig_data)

    tee: dict = evidence.to_dict()
    tee["sig_data"] = base64.b64encode(sig_data).decode()

    # Include session binding fields if applicable
    if override_nonce is None and session_id is not None:
        tee["entropy"] = base64.b64encode(entropy).decode()  # type: ignore[arg-type]
        tee["counter"] = counter  # type: ignore[possibly-undefined]

    # Include workload_id if provided
    if workload_id is not None:
        tee["workload_id"] = workload_id

    return tee, None


def create_response_envelope(
    endpoint: SecureEndpoint,
    result_dict: dict,
    *,
    challenge: bytes | None = None,
) -> dict:
    """Create a _meta.tee envelope for a bootstrap response (Message 2).

    Includes TDX quote + X25519 public key + optional challenge. Plaintext only.

    Args:
        endpoint: Our SecureEndpoint.
        result_dict: The full result dict for the JSON-RPC response.
        challenge: Optional bootstrap challenge for the client to respond to.

    Returns:
        tee_dict to inject as _meta.tee in the response.
    """
    session_id = getattr(endpoint, "session_id", None)

    # Use session-bound sig_data if available, otherwise random
    if session_id is not None:
        entropy = secrets.token_bytes(SIG_DATA_SIZE)
        sig_data, counter = endpoint.derive_sig_data(entropy)
    else:
        sig_data = secrets.token_bytes(SIG_DATA_SIZE)
        entropy = None

    evidence = endpoint.create_evidence(sig_data)

    tee: dict = evidence.to_dict()
    tee["sig_data"] = base64.b64encode(sig_data).decode()

    # Include session binding fields if applicable
    if session_id is not None:
        tee["entropy"] = base64.b64encode(entropy).decode()  # type: ignore[arg-type]
        tee["counter"] = counter  # type: ignore[possibly-undefined]

    # Include bootstrap challenge for the client
    if challenge is not None:
        tee["challenge"] = base64.b64encode(challenge).decode()

    return tee


def open_request_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict,
    peer_role: str = "client",
    allowed_rtmr3: list[str] | None = None,
    *,
    allow_sessionless_challenge_response: bool = False,
) -> tuple[dict | None, None, bool, str]:
    """Open a bootstrap request's _meta.tee envelope (Message 1): verify evidence.

    Args:
        endpoint: Our SecureEndpoint (server side).
        tee_dict: The _meta.tee dict from the request.
        peer_role: Role of the sender.
        allowed_rtmr3: RTMR3 allowlist patterns.
        allow_sessionless_challenge_response: Allow challenge-response messages to
            omit session binding fields even when a session is established.

    Returns:
        Tuple of (None, None, valid, error). No decryption — bootstrap is plaintext.
    """
    from mcp.shared.secure_channel import AttestationEvidence

    # Extract and decode sig_data
    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return None, None, False, "Missing sig_data in tee envelope"

    try:
        sig_data = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return None, None, False, "Invalid base64 in sig_data"

    # Check for challenge_response (bootstrap challenge-response)
    challenge_response_b64 = tee_dict.get("challenge_response")
    if challenge_response_b64 is not None:
        try:
            tee_dict["_challenge_response_raw"] = base64.b64decode(challenge_response_b64)
        except (binascii.Error, TypeError):
            return None, None, False, "Invalid base64 in challenge_response"

    session_id = getattr(endpoint, "session_id", None)

    # If session-bound, recompute sig_data from entropy/counter
    entropy_b64 = tee_dict.get("entropy")
    counter = tee_dict.get("counter")
    has_session_binding = entropy_b64 is not None or counter is not None
    if has_session_binding and (entropy_b64 is None or counter is None):
        return None, None, False, "Both entropy and counter are required for session binding"

    if session_id is not None and not has_session_binding:
        if not (allow_sessionless_challenge_response and challenge_response_b64 is not None):
            return None, None, False, "Missing session binding fields in tee envelope"

    if has_session_binding:
        if session_id is None:
            return None, None, False, "Session binding fields provided before session establishment"
        if not isinstance(counter, int):
            return None, None, False, "Invalid counter type in tee envelope"
        try:
            entropy = base64.b64decode(entropy_b64)
        except (binascii.Error, TypeError):
            return None, None, False, "Invalid base64 in entropy"
        try:
            sig_data = endpoint.verify_derived_sig_data(entropy, counter)
        except ValueError as e:
            return None, None, False, f"Session binding failed: {e}"

    # Reconstruct evidence from tee_dict for verification
    evidence = AttestationEvidence.from_dict(tee_dict)

    # Verify using sig_data as the expected nonce
    result = endpoint.verify_peer(
        evidence,
        expected_nonce=sig_data,
        peer_role=peer_role,
        allowed_rtmr3=allowed_rtmr3,
    )

    if not result.valid:
        return None, None, False, result.error

    return None, None, True, ""


def open_response_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict,
    peer_role: str = "server",
    allowed_rtmr3: list[str] | None = None,
) -> tuple[dict | None, bool, str]:
    """Open a bootstrap response's _meta.tee envelope (Message 2): verify evidence.

    Args:
        endpoint: Our SecureEndpoint (client side).
        tee_dict: The _meta.tee dict from the response.
        peer_role: Role of the sender.
        allowed_rtmr3: RTMR3 allowlist patterns.

    Returns:
        Tuple of (None, valid, error). No decryption — bootstrap is plaintext.
    """
    from mcp.shared.secure_channel import AttestationEvidence

    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return None, False, "Missing sig_data in tee envelope"

    try:
        sig_data = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return None, False, "Invalid base64 in sig_data"

    session_id = getattr(endpoint, "session_id", None)

    # If session-bound, recompute sig_data from entropy/counter
    entropy_b64 = tee_dict.get("entropy")
    counter = tee_dict.get("counter")
    has_session_binding = entropy_b64 is not None or counter is not None
    if has_session_binding and (entropy_b64 is None or counter is None):
        return None, False, "Both entropy and counter are required for session binding"

    if session_id is not None and not has_session_binding:
        return None, False, "Missing session binding fields in tee envelope"

    if has_session_binding:
        if session_id is None:
            return None, False, "Session binding fields provided before session establishment"
        if not isinstance(counter, int):
            return None, False, "Invalid counter type in tee envelope"
        try:
            entropy = base64.b64decode(entropy_b64)
        except (binascii.Error, TypeError):
            return None, False, "Invalid base64 in entropy"
        try:
            sig_data = endpoint.verify_derived_sig_data(entropy, counter)
        except ValueError as e:
            return None, False, f"Session binding failed: {e}"

    evidence = AttestationEvidence.from_dict(tee_dict)

    result = endpoint.verify_peer(
        evidence,
        expected_nonce=sig_data,
        peer_role=peer_role,
        allowed_rtmr3=allowed_rtmr3,
    )

    if not result.valid:
        return None, False, result.error

    return None, True, ""


# =============================================================================
# Post-bootstrap tool envelopes (session-key only, no TDX quote)
# =============================================================================


def create_tool_request_envelope(
    endpoint: SecureEndpoint,
    params_dict: dict,
    *,
    upstream_tokens: list[dict[str, str]] | None = None,
) -> dict:
    """Create a _meta.tee envelope for a post-bootstrap tools/call request.

    Uses session-bound sig_data + AES-256-GCM encryption with session_key.
    No TDX quote — identity was proven during bootstrap.

    Args:
        endpoint: Our SecureEndpoint with session established.
        params_dict: The full params dict for the JSON-RPC request.
        upstream_tokens: Optional list of upstream attestation JWTs for multi-hop propagation.

    Returns:
        tee_dict to inject as _meta.tee.

    Raises:
        ValueError: If session is not established.
    """
    if endpoint.session_key is None:
        raise ValueError("Session key not established - complete bootstrap first")

    entropy = secrets.token_bytes(SIG_DATA_SIZE)
    sig_data, counter = endpoint.derive_sig_data(entropy)

    tee: dict[str, Any] = {
        "sig_data": base64.b64encode(sig_data).decode(),
        "entropy": base64.b64encode(entropy).decode(),
        "counter": counter,
    }

    # Encrypt params (minus _meta)
    plaintext_params = {k: v for k, v in params_dict.items() if k != "_meta"}
    if plaintext_params:
        plaintext_bytes = json.dumps(plaintext_params, separators=(",", ":")).encode()
        nonce, ciphertext = endpoint.encrypt_message(plaintext_bytes)
        tee["enc"] = SessionEncryptedMessage(nonce=nonce, ciphertext=ciphertext).to_dict()

    if upstream_tokens:
        tee["upstream_tokens"] = upstream_tokens

    return tee


def open_tool_request_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict,
) -> tuple[dict | None, bool, str]:
    """Open a post-bootstrap tools/call request envelope.

    Verifies session binding and decrypts with session_key.
    No quote verification — identity was proven during bootstrap.

    Args:
        endpoint: Our SecureEndpoint (server side) with session established.
        tee_dict: The _meta.tee dict from the request.

    Returns:
        Tuple of (decrypted_params or None, valid, error).
    """
    if endpoint.session_key is None:
        return None, False, "Session key not established"

    # Verify session binding
    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return None, False, "Missing sig_data in tool request envelope"

    entropy_b64 = tee_dict.get("entropy")
    counter = tee_dict.get("counter")
    if entropy_b64 is None or counter is None:
        return None, False, "Missing session binding fields in tool request envelope"
    if not isinstance(counter, int):
        return None, False, "Invalid counter type in tool request envelope"

    try:
        sig_data_received = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return None, False, "Invalid base64 in sig_data"

    try:
        entropy = base64.b64decode(entropy_b64)
    except (binascii.Error, TypeError):
        return None, False, "Invalid base64 in entropy"

    try:
        sig_data_expected = endpoint.verify_derived_sig_data(entropy, counter)
    except ValueError as e:
        return None, False, f"Session binding failed: {e}"

    if not hmac_mod.compare_digest(sig_data_received, sig_data_expected):
        return None, False, "sig_data mismatch — session binding verification failed"

    # Self-check RTMR3 before decrypt
    initial_rtmr3 = getattr(endpoint, "_initial_rtmr3", None)
    enc = tee_dict.get("enc")
    if initial_rtmr3 is not None and enc:
        try:
            from mcp.shared.tdx import get_container_rtmr3

            current_rtmr3 = get_container_rtmr3()
            if current_rtmr3 != initial_rtmr3:
                logger.error(
                    "Self-check failed: RTMR3 changed since session start. Refusing to decrypt. initial=%s current=%s",
                    initial_rtmr3.hex()[:16],
                    current_rtmr3.hex()[:16],
                )
                return None, False, "Self-check failed: container integrity changed"
        except Exception:
            logger.debug("Self-check RTMR3 read failed", exc_info=True)

    # Decrypt
    decrypted_params: dict | None = None
    if enc:
        try:
            enc_msg = SessionEncryptedMessage.from_dict(enc)
            plaintext_bytes = endpoint.decrypt_message(enc_msg.nonce, enc_msg.ciphertext)
            decrypted_params = json.loads(plaintext_bytes)
        except Exception:
            logger.debug("Decryption failed", exc_info=True)
            return None, False, "Decryption failed"

    return decrypted_params, True, ""


def create_tool_response_envelope(
    endpoint: SecureEndpoint,
    result_dict: dict,
) -> dict:
    """Create a _meta.tee envelope for a post-bootstrap tools/call response.

    Uses session-bound sig_data + AES-256-GCM encryption with session_key.
    No TDX quote.

    Args:
        endpoint: Our SecureEndpoint with session established.
        result_dict: The full result dict for the JSON-RPC response.

    Returns:
        tee_dict to inject as _meta.tee.

    Raises:
        ValueError: If session is not established.
    """
    if endpoint.session_key is None:
        raise ValueError("Session key not established - complete bootstrap first")

    entropy = secrets.token_bytes(SIG_DATA_SIZE)
    sig_data, counter = endpoint.derive_sig_data(entropy)

    tee: dict[str, Any] = {
        "sig_data": base64.b64encode(sig_data).decode(),
        "entropy": base64.b64encode(entropy).decode(),
        "counter": counter,
    }

    # Encrypt result (minus _meta)
    plaintext_result = {k: v for k, v in result_dict.items() if k != "_meta"}
    if plaintext_result:
        plaintext_bytes = json.dumps(plaintext_result, separators=(",", ":")).encode()
        nonce, ciphertext = endpoint.encrypt_message(plaintext_bytes)
        tee["enc"] = SessionEncryptedMessage(nonce=nonce, ciphertext=ciphertext).to_dict()

    return tee


def open_tool_response_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict,
) -> tuple[dict | None, bool, str]:
    """Open a post-bootstrap tools/call response envelope.

    Verifies session binding and decrypts with session_key.
    No quote verification.

    Args:
        endpoint: Our SecureEndpoint (client side) with session established.
        tee_dict: The _meta.tee dict from the response.

    Returns:
        Tuple of (decrypted_result or None, valid, error).
    """
    if endpoint.session_key is None:
        return None, False, "Session key not established"

    # Verify session binding
    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return None, False, "Missing sig_data in tool response envelope"

    entropy_b64 = tee_dict.get("entropy")
    counter = tee_dict.get("counter")
    if entropy_b64 is None or counter is None:
        return None, False, "Missing session binding fields in tool response envelope"
    if not isinstance(counter, int):
        return None, False, "Invalid counter type in tool response envelope"

    try:
        sig_data_received = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return None, False, "Invalid base64 in sig_data"

    try:
        entropy = base64.b64decode(entropy_b64)
    except (binascii.Error, TypeError):
        return None, False, "Invalid base64 in entropy"

    try:
        sig_data_expected = endpoint.verify_derived_sig_data(entropy, counter)
    except ValueError as e:
        return None, False, f"Session binding failed: {e}"

    if not hmac_mod.compare_digest(sig_data_received, sig_data_expected):
        return None, False, "sig_data mismatch — session binding verification failed"

    # Decrypt
    decrypted_result: dict | None = None
    enc = tee_dict.get("enc")
    if enc:
        try:
            enc_msg = SessionEncryptedMessage.from_dict(enc)
            plaintext_bytes = endpoint.decrypt_message(enc_msg.nonce, enc_msg.ciphertext)
            decrypted_result = json.loads(plaintext_bytes)
        except Exception:
            logger.debug("Decryption failed", exc_info=True)
            return None, False, "Decryption failed"

    return decrypted_result, True, ""


# =============================================================================
# Lightweight session envelope (no TDX quote) — used for tools/list
# =============================================================================


def create_session_envelope(
    endpoint: SecureEndpoint,
    *,
    trust_metadata: dict[str, Any] | None = None,
) -> dict:
    """Create a session-bound _meta.tee with optional trust metadata. No TDX quote.

    Used for tools/list responses where trust metadata is attached but a full
    TDX quote is not needed.

    Args:
        endpoint: Our SecureEndpoint with session_id established.
        trust_metadata: Optional ServerTrustInfo dict to include.

    Returns:
        tee_dict to inject as _meta.tee in the response.
    """
    session_id = getattr(endpoint, "session_id", None)

    tee: dict[str, Any] = {
        "timestamp_ms": int(time.time() * 1000),
    }

    if session_id is not None:
        entropy = secrets.token_bytes(SIG_DATA_SIZE)
        sig_data, counter = endpoint.derive_sig_data(entropy)
        tee["sig_data"] = base64.b64encode(sig_data).decode()
        tee["entropy"] = base64.b64encode(entropy).decode()
        tee["counter"] = counter
    else:
        sig_data = secrets.token_bytes(SIG_DATA_SIZE)
        tee["sig_data"] = base64.b64encode(sig_data).decode()

    if trust_metadata is not None:
        tee["server_trust"] = trust_metadata

    return tee


def verify_session_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict,
) -> tuple[bool, str]:
    """Verify session-bound sig_data. No quote verification.

    Used for tools/list where we only need to verify the message is from the
    established session, not a full attestation.

    Args:
        endpoint: Our SecureEndpoint with session_id established.
        tee_dict: The _meta.tee dict from the message.

    Returns:
        Tuple of (valid, error_message).
    """
    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return False, "Missing sig_data in session envelope"

    try:
        sig_data_received = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return False, "Invalid base64 in sig_data"

    session_id = getattr(endpoint, "session_id", None)

    entropy_b64 = tee_dict.get("entropy")
    counter = tee_dict.get("counter")
    has_session_binding = entropy_b64 is not None or counter is not None

    if has_session_binding and (entropy_b64 is None or counter is None):
        return False, "Both entropy and counter are required for session binding"

    if session_id is not None and not has_session_binding:
        return False, "Missing session binding fields in session envelope"

    if has_session_binding:
        if session_id is None:
            return False, "Session binding fields provided before session establishment"
        if not isinstance(counter, int):
            return False, "Invalid counter type in session envelope"
        try:
            entropy = base64.b64decode(entropy_b64)
        except (binascii.Error, TypeError):
            return False, "Invalid base64 in entropy"
        try:
            sig_data_expected = endpoint.verify_derived_sig_data(entropy, counter)
        except ValueError as e:
            return False, f"Session binding failed: {e}"
        if not hmac_mod.compare_digest(sig_data_received, sig_data_expected):
            return False, "sig_data mismatch in session envelope"

    return True, ""
