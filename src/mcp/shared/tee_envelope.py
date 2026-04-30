"""Per-call TEE envelope: attestation + envelope encryption in _meta.tee.

Three envelope types, matching the protocol phases:

1. Bootstrap envelope (Messages 1 & 2): TDX quote + X25519 key, plaintext.
   - create: create_bootstrap_envelope()
   - verify: verify_bootstrap_envelope()

2. Encrypted envelope (tools/call): per-message DEK + AES Key Wrap + AES-GCM.
   - create: create_encrypted_envelope()
   - verify: verify_encrypted_envelope()

3. Session envelope (tools/list): HMAC auth tag + counter, no encryption.
   - create: create_session_envelope()
   - verify: verify_session_envelope()
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from mcp.shared.crypto.envelope import EnvelopePayload

if TYPE_CHECKING:
    from mcp.shared.secure_channel import SecureEndpoint

logger = logging.getLogger(__name__)

NONCE_SIZE = 32


# =============================================================================
# _meta.tee injection / extraction helpers
# =============================================================================


def extract_tee(params: Any) -> dict | None:
    """Extract _meta.tee dict from a Pydantic params object or plain dict."""
    if params is None:
        return None
    meta = getattr(params, "meta", None)
    if meta is None:
        meta = getattr(params, "_meta", None)
    if meta is None:
        return None
    if isinstance(meta, dict):
        return meta.get("tee")
    # Legacy: Pydantic model with model_extra
    extra = getattr(meta, "model_extra", None) or {}
    tee_value = extra.get("tee")
    if tee_value is not None:
        return tee_value
    return getattr(meta, "tee", None)


def extract_tee_from_result(result_dict: dict) -> dict | None:
    """Extract _meta.tee from a JSON-RPC result dict."""
    if not result_dict:
        return None
    return (result_dict.get("_meta") or {}).get("tee")


def inject_tee(data_dict: dict[str, Any], tee_dict: dict[str, Any], *, params_level: bool = False) -> None:
    """Inject tee_dict into data_dict["_meta"]["tee"].

    If params_level=True, injects at data_dict["params"]["_meta"]["tee"].
    """
    if params_level:
        if "params" not in data_dict:
            data_dict["params"] = {}
        target = data_dict["params"]
    else:
        target = data_dict

    if "_meta" not in target:
        target["_meta"] = {}
    target["_meta"]["tee"] = tee_dict


def _tool_envelope_aad(counter: int, upstream_tokens: list[dict[str, str]] | None = None) -> bytes:
    """Serialize the authenticated outer metadata for tools/call."""
    aad: dict[str, Any] = {"counter": counter}
    if upstream_tokens:
        aad["upstream_tokens"] = upstream_tokens
    return json.dumps(aad, separators=(",", ":"), sort_keys=True).encode()


# =============================================================================
# 1. Bootstrap envelope (Messages 1 & 2) — TDX quote, plaintext
# =============================================================================


def create_bootstrap_envelope(
    endpoint: SecureEndpoint,
    *,
    challenge: bytes | None = None,
    workload_id: str | None = None,
    skip_quote: bool = False,
) -> dict[str, Any]:
    """Create a bootstrap _meta.tee with TDX quote + X25519 key.

    Used for initialize request (Message 1) and initialize response (Message 2).
    Plaintext only — no encryption (peer key not yet known).

    `skip_quote=True` (PSK-MCP comparator) builds an envelope without a TDX
    quote — only the X25519 public key + nonce. Saves ~13 ms of trustd
    AttestWorkload work per bootstrap.
    """
    nonce = secrets.token_bytes(NONCE_SIZE)
    evidence = endpoint.create_attestation(nonce, skip_quote=skip_quote)

    envelope: dict[str, Any] = {
        **evidence.to_dict(),
        "sig_data": base64.b64encode(nonce).decode(),
    }

    if challenge is not None:
        envelope["challenge"] = base64.b64encode(challenge).decode()
    if workload_id is not None:
        envelope["workload_id"] = workload_id

    return envelope


def verify_bootstrap_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict[str, Any],
    peer_role: str = "client",
    allowed_rtmr3: list[str] | None = None,
    *,
    allow_missing_for_challenge: bool = False,
    authority_enabled: bool = True,
    skip_quote: bool = False,
) -> tuple[bool, str]:
    """Verify a bootstrap envelope's TDX quote and key binding.

    `authority_enabled` is plumbed through to
    `endpoint.verify_peer_attestation` and ultimately
    `_verify_attestation_evidence`. Set False on F1/F2/F3 ablation paths
    where the authority hop is intentionally skipped.

    Returns:
        (valid, error).
    """
    from mcp.shared.secure_channel import AttestationEvidence

    # Extract sig_data (the nonce bound into the TDX quote)
    sig_data_b64 = tee_dict.get("sig_data")
    if not sig_data_b64:
        return False, "Missing sig_data in bootstrap envelope"
    try:
        nonce = base64.b64decode(sig_data_b64)
    except (binascii.Error, TypeError):
        return False, "Invalid base64 in sig_data"

    # Decode challenge_response if present (bootstrap Message 3)
    challenge_response_b64 = tee_dict.get("challenge_response")
    if challenge_response_b64 is not None:
        try:
            tee_dict["_challenge_response_raw"] = base64.b64decode(challenge_response_b64)
        except (binascii.Error, TypeError):
            return False, "Invalid base64 in challenge_response"

    evidence = AttestationEvidence.from_dict(tee_dict)
    result = endpoint.verify_peer_attestation(
        evidence,
        expected_nonce=nonce,
        peer_role=peer_role,
        allowed_rtmr3=allowed_rtmr3,
        authority_enabled=authority_enabled,
        skip_quote=skip_quote,
    )
    if not result.valid:
        return False, result.error

    return True, ""


# =============================================================================
# 2. Encrypted envelope (tools/call) — per-message DEK + AES Key Wrap
# =============================================================================


def create_encrypted_envelope(
    endpoint: SecureEndpoint,
    payload: dict[str, Any],
    *,
    upstream_tokens: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Create an envelope-encrypted _meta.tee for tools/call.

    Per-message DEK is wrapped with KEK (AES Key Wrap), then payload is
    encrypted with DEK (AES-256-GCM). KEK never touches plaintext.
    """
    if endpoint.kek is None:
        raise ValueError("KEK not established — complete bootstrap first")

    counter = endpoint.next_send_counter()
    aad = _tool_envelope_aad(counter, upstream_tokens)

    plaintext = {k: v for k, v in payload.items() if k != "_meta"}
    envelope: dict[str, Any] = {"counter": counter}

    if plaintext:
        plaintext_bytes = json.dumps(plaintext, separators=(",", ":")).encode()
        enc_payload = endpoint.wrap_and_encrypt(plaintext_bytes, aad=aad)
        envelope["enc"] = enc_payload.to_dict()

    if upstream_tokens:
        envelope["upstream_tokens"] = upstream_tokens

    return envelope


def verify_encrypted_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict[str, Any],
    *,
    self_check_rtmr3: bool = False,
) -> tuple[dict | None, bool, str]:
    """Verify and decrypt an envelope-encrypted tools/call message.

    Returns:
        (decrypted_payload, valid, error).
    """
    if endpoint.kek is None:
        return None, False, "KEK not established"

    # Verify counter (replay protection)
    counter = tee_dict.get("counter")
    if not isinstance(counter, int):
        return None, False, "Missing or invalid counter in tool envelope"
    try:
        endpoint.verify_recv_counter(counter)
    except ValueError as exc:
        return None, False, f"Replay detected: {exc}"

    # Self-check RTMR3 before decrypt (server side only)
    enc_dict = tee_dict.get("enc")
    aad = _tool_envelope_aad(counter, tee_dict.get("upstream_tokens"))
    if self_check_rtmr3 and enc_dict:
        initial_rtmr3 = getattr(endpoint, "_initial_rtmr3", None)
        if initial_rtmr3 is not None:
            try:
                from mcp.shared.tdx import get_container_rtmr3

                current_rtmr3 = get_container_rtmr3()
                if current_rtmr3 != initial_rtmr3:
                    logger.error(
                        "Self-check failed: RTMR3 changed since session start. "
                        "Refusing to decrypt. initial=%s current=%s",
                        initial_rtmr3.hex()[:16],
                        current_rtmr3.hex()[:16],
                    )
                    return None, False, "Self-check failed: container integrity changed"
            except Exception:
                logger.debug("Self-check RTMR3 read failed", exc_info=True)

    # Unwrap DEK and decrypt
    decrypted: dict | None = None
    if enc_dict:
        try:
            enc_payload = EnvelopePayload.from_dict(enc_dict)
            plaintext_bytes = endpoint.unwrap_and_decrypt(enc_payload, aad=aad)
            decrypted = json.loads(plaintext_bytes)
        except Exception:
            logger.debug("Envelope decryption failed", exc_info=True)
            return None, False, "Decryption failed"

    return decrypted, True, ""


# =============================================================================
# 3. Session envelope (tools/list) — HMAC auth + counter, no encryption
# =============================================================================


def create_session_envelope(
    endpoint: SecureEndpoint,
    *,
    trust_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a session-authenticated _meta.tee for tools/list.

    Uses HMAC(mac_key, counter) for authentication. No encryption, no TDX quote.
    """
    counter = endpoint.next_send_counter()
    auth_tag = endpoint.create_session_auth(counter)

    envelope: dict[str, Any] = {
        "counter": counter,
        "auth_tag": base64.b64encode(auth_tag).decode(),
        "timestamp_ms": int(time.time() * 1000),
    }

    if trust_metadata is not None:
        envelope["server_trust"] = trust_metadata

    return envelope


def verify_session_envelope(
    endpoint: SecureEndpoint,
    tee_dict: dict[str, Any],
) -> tuple[bool, str]:
    """Verify session-authenticated tools/list envelope.

    Checks counter monotonicity and HMAC auth tag.
    """
    counter = tee_dict.get("counter")
    if not isinstance(counter, int):
        return False, "Missing or invalid counter in session envelope"

    try:
        endpoint.verify_recv_counter(counter)
    except ValueError as exc:
        return False, f"Replay detected: {exc}"

    auth_tag_b64 = tee_dict.get("auth_tag")
    if not auth_tag_b64:
        return False, "Missing auth_tag in session envelope"

    try:
        auth_tag = base64.b64decode(auth_tag_b64)
    except (binascii.Error, TypeError):
        return False, "Invalid base64 in auth_tag"

    if not endpoint.verify_session_auth(counter, auth_tag):
        return False, "Invalid auth_tag — session authentication failed"

    return True, ""
