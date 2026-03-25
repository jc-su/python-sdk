"""Tests for session-level channel binding (Part A).

Post-refactor: session binding uses counter monotonicity + HMAC auth tags.
No more HMAC-derived sig_data / derive_message_nonce / verify_message_nonce.
"""

import secrets
from unittest.mock import patch

from mcp.shared.crypto.x25519 import export_public_key, generate_keypair
from mcp.shared.secure_channel import SecureEndpoint


class TestEstablishSession:
    """Session ID computation after bootstrap key exchange."""

    def test_deterministic_session_id(self):
        """Same inputs produce same session_id."""
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        my_nonce = b"A" * 32
        peer_nonce = b"B" * 32

        sid1 = ep.establish_session(peer_pk, my_nonce, peer_nonce)
        sid2 = ep.establish_session(peer_pk, my_nonce, peer_nonce)
        assert sid1 == sid2
        assert len(sid1) == 32

    def test_different_inputs_different_session_id(self):
        """Different inputs produce different session_id."""
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)

        sid1 = ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        sid2 = ep.establish_session(peer_pk, b"C" * 32, b"D" * 32)
        assert sid1 != sid2

    def test_canonical_ordering(self):
        """Client and server with same material produce same session_id."""
        client_kp = generate_keypair()
        server_kp = generate_keypair()
        client_pk = export_public_key(client_kp.public_key)
        server_pk = export_public_key(server_kp.public_key)
        client_nonce = b"A" * 32
        server_nonce = b"B" * 32

        ep_client = SecureEndpoint(
            private_key=client_kp.private_key,
            public_key=client_kp.public_key,
            public_key_bytes=client_pk,
            role="client",
        )
        ep_server = SecureEndpoint(
            private_key=server_kp.private_key,
            public_key=server_kp.public_key,
            public_key_bytes=server_pk,
            role="server",
        )

        # Client: my_init_nonce=client_nonce, peer_init_nonce=server_nonce
        sid_client = ep_client.establish_session(server_pk, client_nonce, server_nonce)
        # Server: my_init_nonce=server_nonce, peer_init_nonce=client_nonce
        sid_server = ep_server.establish_session(client_pk, server_nonce, client_nonce)
        assert sid_client == sid_server

    def test_session_resets_counters(self):
        """Establishing session resets send/recv counters."""
        ep = SecureEndpoint.create(role="client")
        ep._send_counter = 42
        ep._recv_counter = 10

        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        assert ep._send_counter == 0
        assert ep._recv_counter == 0

    def test_session_derives_keys(self):
        """Establishing session derives kek and mac_key."""
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        assert ep.kek is not None
        assert len(ep.kek) == 32
        assert ep.mac_key is not None
        assert len(ep.mac_key) == 32
        assert ep.kek != ep.mac_key


class TestSendCounter:
    """Counter-based replay protection: next_send_counter."""

    def _setup_ep(self):
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        return ep

    def test_counter_starts_at_zero(self):
        """First call returns counter 0."""
        ep = self._setup_ep()
        assert ep.next_send_counter() == 0

    def test_counter_increments(self):
        """Counter increments monotonically."""
        ep = self._setup_ep()

        counters = []
        for _ in range(10):
            counters.append(ep.next_send_counter())

        assert counters == list(range(10))

    def test_counter_overflow_raises(self):
        """Counter at 2^64-1 raises OverflowError."""
        ep = self._setup_ep()
        ep._send_counter = 2**64 - 1

        try:
            ep.next_send_counter()
            assert False, "Should raise OverflowError"
        except OverflowError as e:
            assert "exhausted" in str(e)


class TestRecvCounter:
    """Counter-based replay protection: verify_recv_counter."""

    def _setup_ep(self):
        ep = SecureEndpoint.create(role="server")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        return ep

    def test_monotonic_counters_accepted(self):
        """Sequential counters are accepted."""
        ep = self._setup_ep()
        ep.verify_recv_counter(0)
        ep.verify_recv_counter(1)
        ep.verify_recv_counter(2)

    def test_gap_accepted(self):
        """Counter gaps are accepted (counter 0, then 5)."""
        ep = self._setup_ep()
        ep.verify_recv_counter(0)
        ep.verify_recv_counter(5)  # Gap is fine

    def test_stale_counter_rejected(self):
        """Counter must be monotonically increasing."""
        ep = self._setup_ep()
        ep.verify_recv_counter(0)
        ep.verify_recv_counter(1)

        try:
            ep.verify_recv_counter(0)  # Stale
            assert False, "Should raise ValueError"
        except ValueError as e:
            assert "Stale counter" in str(e)


class TestSessionAuth:
    """HMAC-based session authentication (for tools/list)."""

    def _setup_pair(self):
        """Create client/server pair with same keys."""
        client_kp = generate_keypair()
        server_kp = generate_keypair()
        client_pk = export_public_key(client_kp.public_key)
        server_pk = export_public_key(server_kp.public_key)

        client = SecureEndpoint(
            private_key=client_kp.private_key,
            public_key=client_kp.public_key,
            public_key_bytes=client_pk,
            role="client",
        )
        server = SecureEndpoint(
            private_key=server_kp.private_key,
            public_key=server_kp.public_key,
            public_key_bytes=server_pk,
            role="server",
        )

        client.establish_session(server_pk, b"A" * 32, b"B" * 32)
        server.establish_session(client_pk, b"B" * 32, b"A" * 32)

        return client, server

    def test_auth_round_trip(self):
        """Auth tag created by one side is verified by the other."""
        client, server = self._setup_pair()

        counter = client.next_send_counter()
        auth_tag = client.create_session_auth(counter)
        assert server.verify_session_auth(counter, auth_tag) is True

    def test_wrong_counter_auth_fails(self):
        """Auth tag for wrong counter fails verification."""
        client, server = self._setup_pair()

        counter = client.next_send_counter()
        auth_tag = client.create_session_auth(counter)
        # Verify with wrong counter
        assert server.verify_session_auth(counter + 1, auth_tag) is False

    def test_tampered_auth_tag_fails(self):
        """Tampered auth tag fails verification."""
        client, server = self._setup_pair()

        counter = client.next_send_counter()
        auth_tag = client.create_session_auth(counter)
        tampered = bytearray(auth_tag)
        tampered[0] ^= 0xFF
        assert server.verify_session_auth(counter, bytes(tampered)) is False

    def test_auth_without_mac_key_raises(self):
        """create_session_auth raises without mac_key."""
        ep = SecureEndpoint.create(role="client")
        try:
            ep.create_session_auth(0)
            assert False, "Should raise ValueError"
        except ValueError as e:
            assert "MAC key not established" in str(e)


class TestBackwardCompatibility:
    """Session binding is optional -- backward compatible with raw random nonce."""

    def test_no_session_uses_random(self):
        """Without session_id, nonce is just random (existing behavior)."""
        ep = SecureEndpoint.create(role="client")
        assert ep.session_id is None

        with (
            patch("mcp.shared.secure_channel.generate_quote", return_value=b"\x04\x00" + b"\x00" * 1020),
            patch("mcp.shared.secure_channel.parse_quote", return_value=None),
            patch("mcp.shared.secure_channel.get_current_cgroup", return_value="/docker/test"),
            patch("mcp.shared.secure_channel.get_container_rtmr3", return_value=bytes(48)),
        ):
            nonce = secrets.token_bytes(32)
            evidence = ep.create_attestation(nonce)
            assert evidence.nonce == nonce
