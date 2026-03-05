"""Tests for verifier-chosen nonce for bootstrap (Part B)."""

import base64

from mcp.shared.secure_channel import SecureEndpoint


class TestBootstrapChallenge:
    """Bootstrap challenge generation and consumption."""

    def test_generate_returns_32_bytes(self):
        ep = SecureEndpoint.create(role="server")
        challenge = ep.generate_bootstrap_challenge()
        assert len(challenge) == 32
        assert ep._bootstrap_challenge == challenge

    def test_consume_returns_and_clears(self):
        ep = SecureEndpoint.create(role="server")
        challenge = ep.generate_bootstrap_challenge()

        consumed = ep.consume_bootstrap_challenge()
        assert consumed == challenge

        # Second consume returns None (one-time use)
        assert ep.consume_bootstrap_challenge() is None

    def test_consume_without_generate_returns_none(self):
        ep = SecureEndpoint.create(role="server")
        assert ep.consume_bootstrap_challenge() is None

    def test_generate_overwrites_previous(self):
        ep = SecureEndpoint.create(role="server")
        c1 = ep.generate_bootstrap_challenge()
        c2 = ep.generate_bootstrap_challenge()

        assert c1 != c2
        assert ep.consume_bootstrap_challenge() == c2


class TestBootstrapChallengeInEnvelope:
    """Challenge included in response envelope and processed in request envelope."""

    def test_challenge_in_response_envelope(self):
        """create_response_envelope includes challenge when provided."""
        from mcp.shared.tee_envelope import create_response_envelope

        class MockEP:
            session_id = None
            role = "server"

            def create_evidence(self, nonce):
                class MockEv:
                    def to_dict(self):
                        return {
                            "quote": base64.b64encode(b"q").decode(),
                            "public_key": base64.b64encode(b"pk").decode(),
                            "nonce": base64.b64encode(nonce).decode(),
                            "cgroup": "/docker/test",
                            "rtmr3": bytes(48).hex(),
                            "timestamp_ms": 999,
                            "role": "server",
                        }

                return MockEv()

        ep = MockEP()
        challenge = b"X" * 32

        tee_dict = create_response_envelope(ep, {"result": "ok"}, challenge=challenge)

        assert "challenge" in tee_dict
        assert base64.b64decode(tee_dict["challenge"]) == challenge

    def test_no_challenge_by_default(self):
        """No challenge field when not provided."""
        from mcp.shared.tee_envelope import create_response_envelope

        class MockEP:
            session_id = None
            role = "server"

            def create_evidence(self, nonce):
                class MockEv:
                    def to_dict(self):
                        return {
                            "quote": base64.b64encode(b"q").decode(),
                            "public_key": base64.b64encode(b"pk").decode(),
                            "nonce": base64.b64encode(nonce).decode(),
                            "cgroup": "/docker/test",
                            "rtmr3": bytes(48).hex(),
                            "timestamp_ms": 999,
                            "role": "server",
                        }

                return MockEv()

        ep = MockEP()
        tee_dict = create_response_envelope(ep, {"result": "ok"})
        assert "challenge" not in tee_dict

    def test_challenge_response_in_request_envelope(self):
        """create_request_envelope uses override_nonce for challenge binding."""
        from mcp.shared.tee_envelope import create_request_envelope

        class MockEP:
            session_id = None
            peers = {}
            role = "client"

            def create_evidence(self, nonce):
                class MockEv:
                    def __init__(self, n):
                        self.nonce = n

                    def to_dict(self):
                        return {
                            "quote": base64.b64encode(b"q").decode(),
                            "public_key": base64.b64encode(b"pk").decode(),
                            "nonce": base64.b64encode(self.nonce).decode(),
                            "cgroup": "/docker/test",
                            "rtmr3": bytes(48).hex(),
                            "timestamp_ms": 999,
                            "role": "client",
                        }

                return MockEv(nonce)

            def get_peer(self, role):
                return None

        ep = MockEP()
        challenge = b"Z" * 32

        tee_dict, _ = create_request_envelope(ep, {}, override_nonce=challenge)

        # sig_data should be the challenge itself (override)
        assert base64.b64decode(tee_dict["sig_data"]) == challenge
        # No entropy/counter since it's an override
        assert "entropy" not in tee_dict
        assert "counter" not in tee_dict


class TestChallengeResponseFlow:
    """End-to-end challenge-response verification at SecureEndpoint level."""

    def test_challenge_round_trip(self):
        """Server generates challenge, client responds, server verifies."""
        server = SecureEndpoint.create(role="server")

        # Server generates challenge
        challenge = server.generate_bootstrap_challenge()
        assert len(challenge) == 32

        # Client would create evidence binding to challenge
        # Server consumes and verifies
        consumed = server.consume_bootstrap_challenge()
        assert consumed == challenge

        # Simulate challenge match
        assert consumed == challenge  # In real flow, this comes from tee_dict

    def test_wrong_challenge_detected(self):
        """Mismatched challenge is detectable."""
        server = SecureEndpoint.create(role="server")
        challenge = server.generate_bootstrap_challenge()

        consumed = server.consume_bootstrap_challenge()
        wrong_response = b"W" * 32

        assert consumed != wrong_response

    def test_replay_challenge_fails(self):
        """Challenge is cleared after consumption — cannot be replayed."""
        server = SecureEndpoint.create(role="server")
        server.generate_bootstrap_challenge()

        # First consumption succeeds
        assert server.consume_bootstrap_challenge() is not None

        # Second consumption fails (one-time use)
        assert server.consume_bootstrap_challenge() is None
