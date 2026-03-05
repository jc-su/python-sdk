"""Tests for unified per-call TEE envelope."""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from mcp.shared.tee_envelope import (
    SIG_DATA_SIZE,
    create_request_envelope,
    create_response_envelope,
    open_request_envelope,
    open_response_envelope,
)

# =============================================================================
# Mock Classes
# =============================================================================


@dataclass
class MockAttestationEvidence:
    """Mock attestation evidence for testing."""

    quote: bytes = b"mock_quote"
    public_key: bytes = b"mock_public_key"
    cgroup: str = "/docker/container"
    rtmr3: bytes = bytes(48)
    timestamp_ms: int = 1234567890000
    nonce: bytes = b"\x00" * 32
    role: str = "client"

    def to_dict(self) -> dict:
        d = {
            "quote": base64.b64encode(self.quote).decode(),
            "public_key": base64.b64encode(self.public_key).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "cgroup": self.cgroup,
            "rtmr3": self.rtmr3.hex(),
            "timestamp_ms": self.timestamp_ms,
            "role": self.role,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "MockAttestationEvidence":
        return cls(
            quote=base64.b64decode(data["quote"]),
            public_key=base64.b64decode(data["public_key"]),
            cgroup=data["cgroup"],
            rtmr3=bytes.fromhex(data["rtmr3"]),
            timestamp_ms=data["timestamp_ms"],
            role=data.get("role", "client"),
        )


@dataclass
class MockVerifyResult:
    valid: bool = True
    error: str = ""
    cgroup: str = ""
    rtmr3: bytes = bytes(48)


@dataclass
class MockPeer:
    public_key: object = None
    cgroup: str = "/docker/container"
    rtmr3: bytes = bytes(48)
    role: str = "server"


class MockSecureEndpoint:
    """Mock SecureEndpoint for testing tee_envelope."""

    def __init__(self, role: str = "client"):
        self.role = role
        self.peers: dict[str, MockPeer] = {}
        self.private_key = "mock_private_key"
        self.session_id: bytes | None = None
        self._verify_valid = True
        self._verify_error = ""

    def create_evidence(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer(
        self,
        evidence: MockAttestationEvidence,
        expected_nonce: bytes | None = None,
        peer_role: str = "default",
        allowed_rtmr3: list[str] | None = None,
    ) -> MockVerifyResult:
        if self._verify_valid:
            self.peers[peer_role] = MockPeer(cgroup=evidence.cgroup, rtmr3=evidence.rtmr3, role=evidence.role)
        return MockVerifyResult(valid=self._verify_valid, error=self._verify_error)

    def get_peer(self, role: str) -> MockPeer | None:
        return self.peers.get(role)


class MockSessionEndpoint(MockSecureEndpoint):
    """MockSecureEndpoint with session binding support."""

    def __init__(self, role: str = "client"):
        super().__init__(role)
        self.session_id: bytes | None = None
        self._call_counter = 0
        self._peer_call_counter = 0

    def derive_sig_data(self, entropy: bytes) -> tuple[bytes, int]:
        if self.session_id is None:
            raise ValueError("Session not established")
        counter = self._call_counter
        self._call_counter += 1
        counter_bytes = counter.to_bytes(8, "big")
        sig_data = hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()
        return sig_data, counter

    def verify_derived_sig_data(self, entropy: bytes, counter: int) -> bytes:
        if self.session_id is None:
            raise ValueError("Session not established")
        if counter < self._peer_call_counter:
            raise ValueError(f"Stale counter: got {counter}, expected >= {self._peer_call_counter}")
        self._peer_call_counter = counter + 1
        counter_bytes = counter.to_bytes(8, "big")
        return hmac.new(self.session_id, entropy + counter_bytes, hashlib.sha256).digest()


# =============================================================================
# Tests for create_request_envelope
# =============================================================================


class TestCreateRequestEnvelope:
    def test_basic_evidence_round_trip(self):
        """Evidence is created and includes sig_data."""
        endpoint = MockSecureEndpoint(role="client")
        params = {"name": "test_tool", "arguments": {"key": "value"}}

        tee_dict, response_key = create_request_envelope(endpoint, params, peer_role="server")

        assert "sig_data" in tee_dict
        sig_data = base64.b64decode(tee_dict["sig_data"])
        assert len(sig_data) == SIG_DATA_SIZE
        assert "quote" in tee_dict
        assert "public_key" in tee_dict
        assert "role" in tee_dict
        # No encryption without peer key
        assert "enc" not in tee_dict
        assert response_key is None

    def test_no_encryption_without_peer(self):
        """Without a known peer, no encryption happens."""
        endpoint = MockSecureEndpoint(role="client")
        params = {"name": "tool"}

        tee_dict, response_key = create_request_envelope(endpoint, params)

        assert "enc" not in tee_dict
        assert response_key is None


# =============================================================================
# Tests for create_response_envelope
# =============================================================================


class TestCreateResponseEnvelope:
    def test_basic_evidence(self):
        """Response envelope has evidence and sig_data."""
        endpoint = MockSecureEndpoint(role="server")
        result = {"content": [], "isError": False}

        tee_dict = create_response_envelope(endpoint, result)

        assert "sig_data" in tee_dict
        assert "quote" in tee_dict
        assert "role" in tee_dict
        assert "enc" not in tee_dict

    def test_no_encryption_in_bootstrap(self):
        """Bootstrap response has no enc field (plaintext only)."""
        endpoint = MockSecureEndpoint(role="server")
        result = {"content": []}

        tee_dict = create_response_envelope(endpoint, result)

        assert "enc" not in tee_dict


# =============================================================================
# Tests for open_request_envelope
# =============================================================================


class TestOpenRequestEnvelope:
    def test_valid_verification(self):
        """Valid evidence passes verification."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            decrypted, resp_key, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is True
        assert error == ""
        assert decrypted is None  # No enc field
        assert resp_key is None

    def test_missing_sig_data_fails(self):
        """Missing sig_data fails verification."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        # No sig_data

        decrypted, resp_key, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "sig_data" in error

    def test_tampered_sig_data_fails_verification(self):
        """When verify_peer returns invalid, the envelope fails."""
        endpoint = MockSecureEndpoint(role="server")
        endpoint._verify_valid = False
        endpoint._verify_error = "Invalid quote"

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"tampered" * 4).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            decrypted, resp_key, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid quote" in error


# =============================================================================
# Tests for open_response_envelope
# =============================================================================


class TestOpenResponseEnvelope:
    def test_valid_verification(self):
        """Valid response evidence passes verification."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            decrypted, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is True
        assert error == ""
        assert decrypted is None

    def test_missing_sig_data_fails(self):
        """Missing sig_data in response fails."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()

        decrypted, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "sig_data" in error

    def test_verification_failure(self):
        """Verification failure is propagated."""
        endpoint = MockSecureEndpoint(role="client")
        endpoint._verify_valid = False
        endpoint._verify_error = "Bad quote"

        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            decrypted, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Bad quote" in error


# =============================================================================
# Tests for sig_data randomness
# =============================================================================


class TestSigDataRandomness:
    def test_different_sig_data_per_call(self):
        """Each call generates different sig_data."""
        endpoint = MockSecureEndpoint(role="client")

        tee1, _ = create_request_envelope(endpoint, {"name": "tool"})
        tee2, _ = create_request_envelope(endpoint, {"name": "tool"})

        assert tee1["sig_data"] != tee2["sig_data"]

    def test_request_and_response_different_sig_data(self):
        """Request and response envelopes have different sig_data."""
        endpoint = MockSecureEndpoint(role="server")
        params = {"name": "tool"}
        result = {"content": []}

        req_tee, _ = create_request_envelope(endpoint, params)
        resp_tee = create_response_envelope(endpoint, result)

        assert req_tee["sig_data"] != resp_tee["sig_data"]


# =============================================================================
# Adversarial input tests (malformed base64, types, etc.)
# =============================================================================


class TestMalformedBase64:
    """Verify that malformed base64 in untrusted tee_dict is rejected."""

    def test_invalid_sig_data_base64_request(self):
        """Malformed base64 in sig_data is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = "!!!not-valid-base64!!!"

        _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid base64 in sig_data" in error

    def test_invalid_sig_data_base64_response(self):
        """Malformed base64 in sig_data rejected on response side."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = "!!!not-valid-base64!!!"

        _, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Invalid base64 in sig_data" in error

    def test_invalid_entropy_base64_request(self):
        """Malformed base64 in entropy field is rejected."""
        endpoint = MockSessionEndpoint(role="server")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = "!!!bad-base64!!!"
        tee_dict["counter"] = 0

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid base64 in entropy" in error

    def test_invalid_entropy_base64_response(self):
        """Malformed base64 in entropy rejected on response side."""
        endpoint = MockSessionEndpoint(role="client")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = "!!!bad-base64!!!"
        tee_dict["counter"] = 0

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Invalid base64 in entropy" in error

    def test_invalid_challenge_response_base64(self):
        """Malformed base64 in challenge_response is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["challenge_response"] = "!!!bad-base64!!!"

        _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid base64 in challenge_response" in error


class TestInvalidCounterType:
    """Verify that non-integer counter values are rejected."""

    def test_string_counter_request(self):
        """String counter value is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = base64.b64encode(b"y" * 32).decode()
        tee_dict["counter"] = "not_an_int"

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid counter type" in error

    def test_float_counter_request(self):
        """Float counter value is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = base64.b64encode(b"y" * 32).decode()
        tee_dict["counter"] = 3.14

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid counter type" in error

    def test_list_counter_request(self):
        """List counter value is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = base64.b64encode(b"y" * 32).decode()
        tee_dict["counter"] = [1, 2, 3]

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid counter type" in error

    def test_string_counter_response(self):
        """String counter rejected on response side."""
        endpoint = MockSecureEndpoint(role="client")
        endpoint.session_id = b"x" * 32

        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = base64.b64encode(b"y" * 32).decode()
        tee_dict["counter"] = "not_an_int"

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Invalid counter type" in error


# =============================================================================
# Session binding tests
# =============================================================================


class TestSessionBinding:
    """Test session-bound sig_data derivation in envelopes."""

    def test_request_includes_entropy_counter_when_session_bound(self):
        """When session_id is set, envelope includes entropy and counter."""
        endpoint = MockSessionEndpoint(role="client")
        endpoint.session_id = secrets.token_bytes(32)

        tee_dict, _ = create_request_envelope(endpoint, {"name": "tool"})

        assert "entropy" in tee_dict
        assert "counter" in tee_dict
        assert tee_dict["counter"] == 0  # First call

    def test_counter_increments_per_call(self):
        """Counter increments on each envelope creation."""
        endpoint = MockSessionEndpoint(role="client")
        endpoint.session_id = secrets.token_bytes(32)

        tee1, _ = create_request_envelope(endpoint, {"name": "tool"})
        tee2, _ = create_request_envelope(endpoint, {"name": "tool"})

        assert tee1["counter"] == 0
        assert tee2["counter"] == 1

    def test_session_bound_envelope_verifiable(self):
        """Session-bound request envelope can be verified by receiver."""
        session_id = secrets.token_bytes(32)

        sender = MockSessionEndpoint(role="client")
        sender.session_id = session_id

        receiver = MockSessionEndpoint(role="server")
        receiver.session_id = session_id

        tee_dict, _ = create_request_envelope(sender, {"name": "tool"})

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(receiver, tee_dict, peer_role="client")

        assert valid is True, f"Verification failed: {error}"

    def test_stale_counter_rejected(self):
        """Counter replay (stale counter) is rejected."""
        session_id = secrets.token_bytes(32)

        sender = MockSessionEndpoint(role="client")
        sender.session_id = session_id

        receiver = MockSessionEndpoint(role="server")
        receiver.session_id = session_id

        # Create two envelopes
        tee1, _ = create_request_envelope(sender, {"name": "tool"})
        tee2, _ = create_request_envelope(sender, {"name": "tool"})

        # Verify second one first (counter=1)
        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, _ = open_request_envelope(receiver, tee2, peer_role="client")
        assert valid is True

        # Now try first one (counter=0) — should fail as stale
        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(receiver, tee1, peer_role="client")
        assert valid is False
        assert "Session binding failed" in error

    def test_response_includes_entropy_counter(self):
        """Response envelope also includes session binding fields."""
        endpoint = MockSessionEndpoint(role="server")
        endpoint.session_id = secrets.token_bytes(32)

        tee_dict = create_response_envelope(endpoint, {"content": []})

        assert "entropy" in tee_dict
        assert "counter" in tee_dict

    def test_request_missing_session_binding_rejected(self):
        """When a session exists, missing entropy/counter is rejected."""
        endpoint = MockSessionEndpoint(role="server")
        endpoint.session_id = secrets.token_bytes(32)

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Missing session binding fields" in error

    def test_response_missing_session_binding_rejected(self):
        """When a session exists, response must include entropy/counter."""
        endpoint = MockSessionEndpoint(role="client")
        endpoint.session_id = secrets.token_bytes(32)

        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, valid, error = open_response_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Missing session binding fields" in error

    def test_binding_fields_without_session_rejected(self):
        """Session binding fields are invalid before session establishment."""
        endpoint = MockSessionEndpoint(role="server")

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["entropy"] = base64.b64encode(b"y" * 32).decode()
        tee_dict["counter"] = 0

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            _, _, valid, error = open_request_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "before session establishment" in error

    def test_no_session_fields_without_session(self):
        """Without session_id, no entropy/counter in envelope."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict, _ = create_request_envelope(endpoint, {"name": "tool"})

        assert "entropy" not in tee_dict
        assert "counter" not in tee_dict


# =============================================================================
# Override nonce (bootstrap challenge) tests
# =============================================================================


class TestOverrideNonce:
    """Test override_nonce parameter for bootstrap challenge-response."""

    def test_override_nonce_used_as_sig_data(self):
        """When override_nonce is provided, it's used as sig_data."""
        endpoint = MockSecureEndpoint(role="client")
        challenge = secrets.token_bytes(32)

        tee_dict, _ = create_request_envelope(
            endpoint, {"name": "tool"}, override_nonce=challenge
        )

        actual_sig_data = base64.b64decode(tee_dict["sig_data"])
        assert actual_sig_data == challenge

    def test_override_nonce_skips_session_binding(self):
        """Override nonce skips entropy/counter even if session is established."""
        endpoint = MockSessionEndpoint(role="client")
        endpoint.session_id = secrets.token_bytes(32)
        challenge = secrets.token_bytes(32)

        tee_dict, _ = create_request_envelope(
            endpoint, {"name": "tool"}, override_nonce=challenge
        )

        # No session binding fields when using override nonce
        assert "entropy" not in tee_dict
        assert "counter" not in tee_dict


# =============================================================================
# Workload ID tests
# =============================================================================


class TestWorkloadId:
    """Test workload_id propagation in envelopes."""

    def test_workload_id_included(self):
        """Workload ID is included in envelope when provided."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict, _ = create_request_envelope(
            endpoint, {"name": "tool"}, workload_id="my-agent-v1"
        )

        assert tee_dict["workload_id"] == "my-agent-v1"

    def test_no_workload_id_by_default(self):
        """No workload_id field when not provided."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict, _ = create_request_envelope(endpoint, {"name": "tool"})

        assert "workload_id" not in tee_dict


# =============================================================================
# Challenge in response envelope tests
# =============================================================================


class TestBootstrapChallenge:
    """Test challenge field in response envelopes."""

    def test_challenge_included_in_response(self):
        """Bootstrap challenge is base64-encoded in response envelope."""
        endpoint = MockSecureEndpoint(role="server")
        challenge = secrets.token_bytes(32)

        tee_dict = create_response_envelope(
            endpoint, {"content": []}, challenge=challenge
        )

        assert "challenge" in tee_dict
        decoded = base64.b64decode(tee_dict["challenge"])
        assert decoded == challenge

    def test_no_challenge_by_default(self):
        """No challenge field when not provided."""
        endpoint = MockSecureEndpoint(role="server")

        tee_dict = create_response_envelope(endpoint, {"content": []})

        assert "challenge" not in tee_dict
