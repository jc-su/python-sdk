"""Cryptographic primitives for TEE-MCP secure channels.

- AES-256-GCM symmetric encryption
- X25519 ECDH key agreement + HKDF key derivation
- Envelope encryption: AES Key Wrap + AES-256-GCM per-message DEK
"""

from mcp.shared.crypto import aes, x25519
from mcp.shared.crypto.envelope import (
    EnvelopePayload,
    envelope_decrypt,
    envelope_encrypt,
)

__all__ = [
    "aes",
    "x25519",
    "EnvelopePayload",
    "envelope_encrypt",
    "envelope_decrypt",
]
