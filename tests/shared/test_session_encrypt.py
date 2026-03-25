"""Tests for envelope encryption (AES Key Wrap + AES-256-GCM)."""

import secrets

import pytest

from mcp.shared.crypto.aes import AES_KEY_SIZE
from mcp.shared.crypto.envelope import (
    EnvelopePayload,
    envelope_decrypt,
    envelope_encrypt,
)


class TestEnvelopeEncrypt:
    def test_round_trip(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        plaintext = b"hello, world"
        aad = b'{"counter":0}'
        payload = envelope_encrypt(kek, plaintext, aad=aad)
        result = envelope_decrypt(kek, payload, aad=aad)
        assert result == plaintext

    def test_wrapped_key_is_40_bytes(self) -> None:
        """AES-KW wrapping 32-byte DEK produces 40-byte wrapped key."""
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"test")
        assert len(payload.wrapped_key) == 40

    def test_iv_is_12_bytes(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"test")
        assert len(payload.iv) == 12

    def test_per_message_dek_isolation(self) -> None:
        """Each encryption uses a different DEK — different ciphertext for same plaintext."""
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload1 = envelope_encrypt(kek, b"same")
        payload2 = envelope_encrypt(kek, b"same")
        assert payload1.wrapped_key != payload2.wrapped_key
        assert payload1.ciphertext != payload2.ciphertext

    def test_wrong_kek_fails_unwrap(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        wrong_kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"secret")
        with pytest.raises(Exception):
            envelope_decrypt(wrong_kek, payload)

    def test_tampered_wrapped_key_fails(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"secret")
        tampered = bytearray(payload.wrapped_key)
        tampered[0] ^= 0xFF
        bad_payload = EnvelopePayload(wrapped_key=bytes(tampered), iv=payload.iv, ciphertext=payload.ciphertext)
        with pytest.raises(Exception):
            envelope_decrypt(kek, bad_payload)

    def test_tampered_ciphertext_fails(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"secret")
        tampered = bytearray(payload.ciphertext)
        tampered[0] ^= 0xFF
        bad_payload = EnvelopePayload(wrapped_key=payload.wrapped_key, iv=payload.iv, ciphertext=bytes(tampered))
        with pytest.raises(Exception):
            envelope_decrypt(kek, bad_payload)

    def test_empty_plaintext(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        aad = b'{"counter":0}'
        payload = envelope_encrypt(kek, b"", aad=aad)
        result = envelope_decrypt(kek, payload, aad=aad)
        assert result == b""

    def test_large_plaintext(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        plaintext = secrets.token_bytes(1_000_000)
        aad = b'{"counter":0}'
        payload = envelope_encrypt(kek, plaintext, aad=aad)
        result = envelope_decrypt(kek, payload, aad=aad)
        assert result == plaintext

    def test_wrong_aad_fails(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"secret", aad=b'{"counter":0}')
        with pytest.raises(Exception):
            envelope_decrypt(kek, payload, aad=b'{"counter":1}')


class TestEnvelopePayloadSerialization:
    def test_to_dict_includes_wrapped_key(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"test data")
        serialized = payload.to_dict()
        assert "wrapped_key" in serialized
        assert "iv" in serialized
        assert "ciphertext" in serialized

    def test_to_dict_round_trip(self) -> None:
        kek = secrets.token_bytes(AES_KEY_SIZE)
        payload = envelope_encrypt(kek, b"test data")
        serialized = payload.to_dict()
        restored = EnvelopePayload.from_dict(serialized)
        result = envelope_decrypt(kek, restored)
        assert result == b"test data"
