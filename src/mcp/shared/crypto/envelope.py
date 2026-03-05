"""
Session-key encryption using AES-256-GCM.

Post-bootstrap, all message encryption uses the ECDH-derived session_key.
No RSA key wrapping — the session key is established via X25519 ECDH + HKDF
during the bootstrap handshake.

Encryption flow:
1. Use session_key (32 bytes, from HKDF) directly as AES-256-GCM key
2. Encrypt message with fresh random nonce
3. Send: nonce + ciphertext (no encrypted_key field)

Decryption flow:
1. Use session_key to decrypt with AES-256-GCM
2. Return plaintext
"""

import base64
import json
from dataclasses import dataclass

from mcp.shared.crypto import aes


@dataclass
class SessionEncryptedMessage:
    """Session-key encrypted message (AES-256-GCM)."""

    nonce: bytes  # AES-GCM nonce (12 bytes)
    ciphertext: bytes  # AES-GCM encrypted data + tag

    def to_dict(self) -> dict:
        return {
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "SessionEncryptedMessage":
        return cls(
            nonce=base64.b64decode(data["nonce"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SessionEncryptedMessage":
        return cls.from_dict(json.loads(json_str))


def session_encrypt(session_key: bytes, plaintext: bytes) -> SessionEncryptedMessage:
    """
    Encrypt a message using the session key (AES-256-GCM).

    Args:
        session_key: 32-byte AES key (from HKDF derivation)
        plaintext: Data to encrypt

    Returns:
        SessionEncryptedMessage with nonce and ciphertext
    """
    result = aes.encrypt(session_key, plaintext)
    return SessionEncryptedMessage(
        nonce=result.nonce,
        ciphertext=result.ciphertext,
    )


def session_decrypt(session_key: bytes, message: SessionEncryptedMessage) -> bytes:
    """
    Decrypt a message using the session key (AES-256-GCM).

    Args:
        session_key: 32-byte AES key (from HKDF derivation)
        message: Encrypted message

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    return aes.decrypt(session_key, message.nonce, message.ciphertext)
