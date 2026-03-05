"""
Cryptographic primitives for TEE-MCP secure channels.

This module provides:
- AES-256-GCM symmetric encryption
- X25519 ECDH key agreement + HKDF session key derivation
- Session-key envelope encryption combining ECDH and AES-GCM
"""

from mcp.shared.crypto import aes, x25519
from mcp.shared.crypto.envelope import (
    SessionEncryptedMessage,
    session_decrypt,
    session_encrypt,
)

__all__ = [
    "aes",
    "x25519",
    "SessionEncryptedMessage",
    "session_encrypt",
    "session_decrypt",
]
