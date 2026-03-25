"""Tests for X25519 ECDH + HKDF key derivation module."""

import secrets

import pytest

from mcp.shared.crypto.x25519 import (
    DerivedKeys,
    X25519KeyPair,
    compute_shared_secret,
    derive_keys,
    export_private_key,
    export_public_key,
    generate_keypair,
    hmac_challenge,
    load_private_key,
    load_public_key,
    verify_challenge_mac,
)


class TestKeypairGeneration:
    def test_generate_keypair_returns_pair(self) -> None:
        kp = generate_keypair()
        assert isinstance(kp, X25519KeyPair)
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_generate_keypair_unique(self) -> None:
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        pub1 = export_public_key(kp1.public_key)
        pub2 = export_public_key(kp2.public_key)
        assert pub1 != pub2

    def test_export_public_key_is_32_bytes(self) -> None:
        kp = generate_keypair()
        raw = export_public_key(kp.public_key)
        assert len(raw) == 32

    def test_export_private_key_is_32_bytes(self) -> None:
        kp = generate_keypair()
        raw = export_private_key(kp.private_key)
        assert len(raw) == 32

    def test_public_key_round_trip(self) -> None:
        kp = generate_keypair()
        raw = export_public_key(kp.public_key)
        loaded = load_public_key(raw)
        assert export_public_key(loaded) == raw

    def test_private_key_round_trip(self) -> None:
        kp = generate_keypair()
        raw = export_private_key(kp.private_key)
        loaded = load_private_key(raw)
        assert export_private_key(loaded) == raw


class TestECDH:
    def test_shared_secret_agreement(self) -> None:
        """Both sides compute the same shared secret."""
        alice = generate_keypair()
        bob = generate_keypair()
        secret_ab = compute_shared_secret(alice.private_key, bob.public_key)
        secret_ba = compute_shared_secret(bob.private_key, alice.public_key)
        assert secret_ab == secret_ba
        assert len(secret_ab) == 32

    def test_different_peers_different_secrets(self) -> None:
        alice = generate_keypair()
        bob = generate_keypair()
        carol = generate_keypair()
        secret_ab = compute_shared_secret(alice.private_key, bob.public_key)
        secret_ac = compute_shared_secret(alice.private_key, carol.public_key)
        assert secret_ab != secret_ac


class TestHKDF:
    def test_derive_keys_returns_session_keys(self) -> None:
        alice = generate_keypair()
        bob = generate_keypair()
        shared = compute_shared_secret(alice.private_key, bob.public_key)
        client_pk = export_public_key(alice.public_key)
        server_pk = export_public_key(bob.public_key)
        keys = derive_keys(shared, client_pk, server_pk)
        assert isinstance(keys, DerivedKeys)
        assert len(keys.kek) == 32
        assert len(keys.mac_key) == 32

    def test_session_key_differs_from_mac_key(self) -> None:
        alice = generate_keypair()
        bob = generate_keypair()
        shared = compute_shared_secret(alice.private_key, bob.public_key)
        client_pk = export_public_key(alice.public_key)
        server_pk = export_public_key(bob.public_key)
        keys = derive_keys(shared, client_pk, server_pk)
        assert keys.kek != keys.mac_key

    def test_deterministic_derivation(self) -> None:
        """Same inputs produce same keys."""
        alice = generate_keypair()
        bob = generate_keypair()
        shared = compute_shared_secret(alice.private_key, bob.public_key)
        client_pk = export_public_key(alice.public_key)
        server_pk = export_public_key(bob.public_key)
        keys1 = derive_keys(shared, client_pk, server_pk)
        keys2 = derive_keys(shared, client_pk, server_pk)
        assert keys1.kek == keys2.kek
        assert keys1.mac_key == keys2.mac_key

    def test_swapped_roles_produce_different_keys(self) -> None:
        """Swapping client/server public keys changes derived keys (salt changes)."""
        alice = generate_keypair()
        bob = generate_keypair()
        shared = compute_shared_secret(alice.private_key, bob.public_key)
        client_pk = export_public_key(alice.public_key)
        server_pk = export_public_key(bob.public_key)
        keys_normal = derive_keys(shared, client_pk, server_pk)
        keys_swapped = derive_keys(shared, server_pk, client_pk)
        assert keys_normal.kek != keys_swapped.kek

    def test_both_sides_derive_same_keys(self) -> None:
        """Full protocol: both sides derive identical session keys."""
        client = generate_keypair()
        server = generate_keypair()
        client_pk = export_public_key(client.public_key)
        server_pk = export_public_key(server.public_key)

        # Client side
        shared_client = compute_shared_secret(client.private_key, server.public_key)
        keys_client = derive_keys(shared_client, client_pk, server_pk)

        # Server side
        shared_server = compute_shared_secret(server.private_key, client.public_key)
        keys_server = derive_keys(shared_server, client_pk, server_pk)

        assert keys_client.kek == keys_server.kek
        assert keys_client.mac_key == keys_server.mac_key


class TestHMACChallenge:
    def test_hmac_challenge_round_trip(self) -> None:
        mac_key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        mac = hmac_challenge(mac_key, challenge)
        assert len(mac) == 32
        assert verify_challenge_mac(mac_key, challenge, mac)

    def test_wrong_key_fails(self) -> None:
        mac_key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        mac = hmac_challenge(mac_key, challenge)
        assert not verify_challenge_mac(wrong_key, challenge, mac)

    def test_wrong_challenge_fails(self) -> None:
        mac_key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        wrong_challenge = secrets.token_bytes(32)
        mac = hmac_challenge(mac_key, challenge)
        assert not verify_challenge_mac(mac_key, wrong_challenge, mac)

    def test_tampered_mac_fails(self) -> None:
        mac_key = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)
        mac = hmac_challenge(mac_key, challenge)
        tampered = bytearray(mac)
        tampered[0] ^= 0xFF
        assert not verify_challenge_mac(mac_key, challenge, bytes(tampered))

    def test_integrated_with_session_keys(self) -> None:
        """Challenge MAC works with HKDF-derived mac_key."""
        client = generate_keypair()
        server = generate_keypair()
        client_pk = export_public_key(client.public_key)
        server_pk = export_public_key(server.public_key)

        shared = compute_shared_secret(client.private_key, server.public_key)
        keys = derive_keys(shared, client_pk, server_pk)

        challenge = secrets.token_bytes(32)
        mac = hmac_challenge(keys.mac_key, challenge)
        assert verify_challenge_mac(keys.mac_key, challenge, mac)


class TestEdgeCases:
    def test_load_public_key_wrong_size_raises(self) -> None:
        with pytest.raises(Exception):
            load_public_key(b"too_short")

    def test_load_private_key_wrong_size_raises(self) -> None:
        with pytest.raises(Exception):
            load_private_key(b"too_short")

    def test_empty_challenge_works(self) -> None:
        mac_key = secrets.token_bytes(32)
        mac = hmac_challenge(mac_key, b"")
        assert verify_challenge_mac(mac_key, b"", mac)
