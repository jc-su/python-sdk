"""X25519 ECDH key agreement + HKDF key derivation.

Provides:
- X25519 ephemeral key pair generation
- ECDH shared secret computation
- HKDF-SHA256 derivation of KEK (key-encryption key) + mac_key
- HMAC-SHA256 challenge MAC for Message 3 key possession proof
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
X25519_KEY_SIZE = 32  # raw key bytes
KEK_INFO = b"tee-mcp-kek"
MAC_KEY_INFO = b"tee-mcp-mac-key"


@dataclass
class X25519KeyPair:
    """X25519 key pair."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclass
class DerivedKeys:
    """Keys derived from ECDH + HKDF."""

    kek: bytes  # 32 bytes — key-encryption key for AES Key Wrap
    mac_key: bytes  # 32 bytes — for HMAC-SHA256 challenge + session auth


def generate_keypair() -> X25519KeyPair:
    """Generate a new ephemeral X25519 key pair."""
    private_key = X25519PrivateKey.generate()
    return X25519KeyPair(
        private_key=private_key,
        public_key=private_key.public_key(),
    )


def export_public_key(public_key: X25519PublicKey) -> bytes:
    """Export public key as 32 raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def export_private_key(private_key: X25519PrivateKey) -> bytes:
    """Export private key as 32 raw bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_public_key(data: bytes) -> X25519PublicKey:
    """Load public key from 32 raw bytes."""
    return X25519PublicKey.from_public_bytes(data)


def load_private_key(data: bytes) -> X25519PrivateKey:
    """Load private key from 32 raw bytes."""
    return X25519PrivateKey.from_private_bytes(data)


def compute_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Compute X25519 ECDH shared secret (32 bytes)."""
    return private_key.exchange(peer_public_key)


def derive_keys(
    shared_secret: bytes,
    client_public_key: bytes,
    server_public_key: bytes,
) -> DerivedKeys:
    """Derive KEK and mac_key from ECDH shared secret via HKDF-SHA256.

    Args:
        shared_secret: 32-byte X25519 shared secret.
        client_public_key: 32-byte raw client X25519 public key.
        server_public_key: 32-byte raw server X25519 public key.

    Returns:
        DerivedKeys with kek (for AES Key Wrap) and mac_key (for HMAC-SHA256).
    """
    # Salt = SHA256(client_pk || server_pk) — canonical ordering
    salt = hashlib.sha256(client_public_key + server_public_key).digest()

    kek = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=KEK_INFO,
    ).derive(shared_secret)

    mac_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        info=MAC_KEY_INFO,
    ).derive(shared_secret)

    return DerivedKeys(kek=kek, mac_key=mac_key)


def hmac_challenge(mac_key: bytes, challenge: bytes) -> bytes:
    """Compute HMAC-SHA256(mac_key, challenge) for Message 3 key possession proof."""
    return hmac.new(mac_key, challenge, hashlib.sha256).digest()


def verify_challenge_mac(mac_key: bytes, challenge: bytes, mac: bytes) -> bool:
    """Verify HMAC-SHA256 challenge MAC. Constant-time comparison."""
    expected = hmac.new(mac_key, challenge, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac)
