"""Tests for session-key envelope encryption."""

import secrets

import pytest

from mcp.shared.crypto.aes import AES_KEY_SIZE
from mcp.shared.crypto.envelope import (
    SessionEncryptedMessage,
    session_decrypt,
    session_encrypt,
)


class TestSessionEncrypt:
    def test_encrypt_decrypt_round_trip(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        plaintext = b"hello, world"
        msg = session_encrypt(key, plaintext)
        result = session_decrypt(key, msg)
        assert result == plaintext

    def test_nonce_is_12_bytes(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"test")
        assert len(msg.nonce) == 12

    def test_unique_nonces(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg1 = session_encrypt(key, b"test")
        msg2 = session_encrypt(key, b"test")
        assert msg1.nonce != msg2.nonce

    def test_wrong_key_fails(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        wrong_key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"secret")
        with pytest.raises(Exception):
            session_decrypt(wrong_key, msg)

    def test_tampered_ciphertext_fails(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"secret")
        tampered = bytearray(msg.ciphertext)
        tampered[0] ^= 0xFF
        msg_tampered = SessionEncryptedMessage(nonce=msg.nonce, ciphertext=bytes(tampered))
        with pytest.raises(Exception):
            session_decrypt(key, msg_tampered)

    def test_empty_plaintext(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"")
        result = session_decrypt(key, msg)
        assert result == b""

    def test_large_plaintext(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        plaintext = secrets.token_bytes(1_000_000)
        msg = session_encrypt(key, plaintext)
        result = session_decrypt(key, msg)
        assert result == plaintext


class TestSessionEncryptedMessage:
    def test_to_dict_round_trip(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"test data")
        d = msg.to_dict()
        assert "nonce" in d
        assert "ciphertext" in d
        assert "key" not in d  # No RSA-wrapped key field
        restored = SessionEncryptedMessage.from_dict(d)
        result = session_decrypt(key, restored)
        assert result == b"test data"

    def test_to_json_round_trip(self) -> None:
        key = secrets.token_bytes(AES_KEY_SIZE)
        msg = session_encrypt(key, b"json test")
        json_str = msg.to_json()
        restored = SessionEncryptedMessage.from_json(json_str)
        result = session_decrypt(key, restored)
        assert result == b"json test"
