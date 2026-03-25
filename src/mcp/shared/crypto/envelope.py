"""Envelope encryption using AES Key Wrap + AES-256-GCM.

Per-message DEK (data encryption key) is randomly generated, used once,
then wrapped with the KEK (key-encryption key) derived from ECDH.

Encryption flow:
1. Generate random 32-byte DEK
2. Wrap DEK: wrapped_key = AES-KW(KEK, DEK)
3. Encrypt payload: AES-256-GCM(DEK, plaintext)
4. Send: wrapped_key + iv + ciphertext

Decryption flow:
1. Unwrap DEK: DEK = AES-KW-unwrap(KEK, wrapped_key)
2. Decrypt payload: AES-256-GCM(DEK, ciphertext)

Security properties:
- Per-message key isolation: compromising one DEK doesn't affect others
- Nonce-reuse tolerance: different DEK per message, so nonce collision is harmless
- KEK never touches plaintext directly
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from mcp.shared.crypto import aes

DEK_SIZE = 32  # AES-256


@dataclass
class EnvelopePayload:
    """Envelope-encrypted message: wrapped DEK + AES-256-GCM ciphertext."""

    wrapped_key: bytes  # AES-KW wrapped DEK (40 bytes for 32-byte DEK)
    iv: bytes  # AES-GCM initialization vector (12 bytes)
    ciphertext: bytes  # AES-GCM encrypted data + auth tag

    def to_dict(self) -> dict[str, Any]:
        return {
            "wrapped_key": base64.b64encode(self.wrapped_key).decode(),
            "iv": base64.b64encode(self.iv).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvelopePayload:
        return cls(
            wrapped_key=base64.b64decode(data["wrapped_key"]),
            iv=base64.b64decode(data["iv"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
        )


def envelope_encrypt(kek: bytes, plaintext: bytes, aad: bytes | None = None) -> EnvelopePayload:
    """Encrypt with per-message DEK wrapped by KEK.

    Args:
        kek: 32-byte key-encryption key (from HKDF).
        plaintext: Data to encrypt.
        aad: Additional authenticated data bound to the ciphertext.

    Returns:
        EnvelopePayload with wrapped DEK + AES-GCM ciphertext.
    """
    dek = secrets.token_bytes(DEK_SIZE)
    wrapped_key = aes_key_wrap(kek, dek)
    result = aes.encrypt(dek, plaintext, aad=aad)
    return EnvelopePayload(
        wrapped_key=wrapped_key,
        iv=result.nonce,
        ciphertext=result.ciphertext,
    )


def envelope_decrypt(kek: bytes, payload: EnvelopePayload, aad: bytes | None = None) -> bytes:
    """Decrypt by unwrapping DEK then decrypting payload.

    Args:
        kek: 32-byte key-encryption key (from HKDF).
        payload: Envelope with wrapped DEK + ciphertext.
        aad: Additional authenticated data that must match encryption.

    Returns:
        Decrypted plaintext.

    Raises:
        cryptography.hazmat.primitives.keywrap.InvalidUnwrap: If KEK is wrong.
        cryptography.exceptions.InvalidTag: If ciphertext is tampered.
    """
    dek = aes_key_unwrap(kek, payload.wrapped_key)
    return aes.decrypt(dek, payload.iv, payload.ciphertext, aad=aad)
