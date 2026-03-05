"""Tests for session-level channel binding (Part A)."""

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
        my_sd = b"A" * 32
        peer_sd = b"B" * 32

        sid1 = ep.establish_session(peer_pk, my_sd, peer_sd)
        sid2 = ep.establish_session(peer_pk, my_sd, peer_sd)
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
        client_sd = b"A" * 32
        server_sd = b"B" * 32

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

        # Client: my_init_sig_data=client_sd, peer_init_sig_data=server_sd
        sid_client = ep_client.establish_session(server_pk, client_sd, server_sd)
        # Server: my_init_sig_data=server_sd, peer_init_sig_data=client_sd
        sid_server = ep_server.establish_session(client_pk, server_sd, client_sd)
        assert sid_client == sid_server

    def test_session_resets_counters(self):
        """Establishing session resets call counters."""
        ep = SecureEndpoint.create(role="client")
        ep._call_counter = 42
        ep._peer_call_counter = 10

        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        assert ep._call_counter == 0
        assert ep._peer_call_counter == 0

    def test_session_derives_keys(self):
        """Establishing session derives session_key and mac_key."""
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        assert ep.session_key is not None
        assert len(ep.session_key) == 32
        assert ep.mac_key is not None
        assert len(ep.mac_key) == 32
        assert ep.session_key != ep.mac_key


class TestDeriveSigData:
    """HMAC-based sig_data derivation."""

    def _setup_ep(self):
        ep = SecureEndpoint.create(role="client")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)
        return ep

    def test_unique_per_counter(self):
        """Each call produces different sig_data (different counter)."""
        ep = self._setup_ep()

        entropy = secrets.token_bytes(32)
        sd1, c1 = ep.derive_sig_data(entropy)
        sd2, c2 = ep.derive_sig_data(entropy)

        assert c1 == 0
        assert c2 == 1
        assert sd1 != sd2

    def test_different_entropy_different_sig_data(self):
        """Different entropy with same counter would produce different sig_data."""
        ep = self._setup_ep()

        sd1, _ = ep.derive_sig_data(secrets.token_bytes(32))
        ep._call_counter = 0  # Reset to reuse same counter
        sd2, _ = ep.derive_sig_data(secrets.token_bytes(32))

        assert sd1 != sd2

    def test_requires_session(self):
        """derive_sig_data fails without session."""
        ep = SecureEndpoint.create(role="client")
        try:
            ep.derive_sig_data(b"x" * 32)
            assert False, "Should raise ValueError"
        except ValueError as e:
            assert "Session not established" in str(e)

    def test_counter_increments(self):
        """Counter increments monotonically."""
        ep = self._setup_ep()

        counters = []
        for _ in range(10):
            _, c = ep.derive_sig_data(secrets.token_bytes(32))
            counters.append(c)

        assert counters == list(range(10))

    def test_counter_overflow_raises(self):
        """Counter at 2^64-1 raises OverflowError."""
        ep = self._setup_ep()
        ep._call_counter = 2**64 - 1

        try:
            ep.derive_sig_data(secrets.token_bytes(32))
            assert False, "Should raise OverflowError"
        except OverflowError as e:
            assert "exhausted" in str(e)


class TestVerifyDerivedSigData:
    """Verification of session-bound sig_data."""

    def test_correct_recomputation(self):
        """Verifier recomputes same sig_data as sender."""
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

        client_sd = b"A" * 32
        server_sd = b"B" * 32

        client.establish_session(server_pk, client_sd, server_sd)
        server.establish_session(client_pk, server_sd, client_sd)

        assert client.session_id == server.session_id

        entropy = secrets.token_bytes(32)
        sig_data, counter = client.derive_sig_data(entropy)

        recomputed = server.verify_derived_sig_data(entropy, counter)
        assert recomputed == sig_data

    def test_different_session_ids_fail(self):
        """Mismatched session_id produces different sig_data."""
        peer1_kp = generate_keypair()
        peer2_kp = generate_keypair()
        peer1_pk = export_public_key(peer1_kp.public_key)
        peer2_pk = export_public_key(peer2_kp.public_key)

        ep1 = SecureEndpoint.create(role="client")
        ep2 = SecureEndpoint.create(role="client")

        ep1.establish_session(peer1_pk, b"A" * 32, b"B" * 32)
        ep2.establish_session(peer2_pk, b"C" * 32, b"D" * 32)

        entropy = secrets.token_bytes(32)
        sd1, c1 = ep1.derive_sig_data(entropy)
        sd2 = ep2.verify_derived_sig_data(entropy, c1)

        assert sd1 != sd2  # Different session_id → different sig_data

    def test_stale_counter_rejected(self):
        """Counter must be monotonically increasing."""
        ep = SecureEndpoint.create(role="server")
        peer_kp = generate_keypair()
        peer_pk = export_public_key(peer_kp.public_key)
        ep.establish_session(peer_pk, b"A" * 32, b"B" * 32)

        ep.verify_derived_sig_data(b"x" * 32, 0)
        ep.verify_derived_sig_data(b"y" * 32, 1)

        try:
            ep.verify_derived_sig_data(b"z" * 32, 0)  # Stale
            assert False, "Should raise ValueError"
        except ValueError as e:
            assert "Stale counter" in str(e)

    def test_requires_session(self):
        """verify_derived_sig_data fails without session."""
        ep = SecureEndpoint.create(role="server")
        try:
            ep.verify_derived_sig_data(b"x" * 32, 0)
            assert False, "Should raise ValueError"
        except ValueError as e:
            assert "Session not established" in str(e)


class TestBackwardCompatibility:
    """Session binding is optional — backward compatible with raw random sig_data."""

    def test_no_session_uses_random(self):
        """Without session_id, sig_data is just random (existing behavior)."""
        ep = SecureEndpoint.create(role="client")
        assert ep.session_id is None

        # create_evidence_with_random_sig still works
        with (
            patch("mcp.shared.secure_channel.generate_quote", return_value=b"\x04\x00" + b"\x00" * 1020),
            patch("mcp.shared.secure_channel.parse_quote", return_value=None),
            patch("mcp.shared.secure_channel.get_current_cgroup", return_value="/docker/test"),
            patch("mcp.shared.secure_channel.get_container_rtmr3", return_value=bytes(48)),
        ):
            evidence, sig_data = ep.create_evidence_with_random_sig()
            assert len(sig_data) == 32
            assert evidence.nonce == sig_data
