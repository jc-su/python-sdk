"""AES-256-GCM symmetric encryption."""

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
AES_KEY_SIZE = 32      # 256 bits
AES_NONCE_SIZE = 12    # 96 bits (recommended for GCM)
AES_TAG_SIZE = 16      # 128 bits


def generate_key() -> bytes:
    """Generate a random AES-256 key."""
    return secrets.token_bytes(AES_KEY_SIZE)


def generate_nonce() -> bytes:
    """Generate a random nonce for AES-GCM."""
    return secrets.token_bytes(AES_NONCE_SIZE)


@dataclass
class AesGcmResult:
    """Result of AES-GCM encryption."""
    nonce: bytes       # 12 bytes
    ciphertext: bytes  # includes 16-byte auth tag


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> AesGcmResult:
    """Encrypt data using AES-256-GCM.

    Args:
        key: 32-byte AES key
        plaintext: Data to encrypt
        aad: Additional authenticated data (optional)

    Returns:
        AesGcmResult with nonce and ciphertext
    """
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return AesGcmResult(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        key: 32-byte AES key
        nonce: 12-byte nonce used for encryption
        ciphertext: Encrypted data (includes auth tag)
        aad: Additional authenticated data (must match encryption)

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
