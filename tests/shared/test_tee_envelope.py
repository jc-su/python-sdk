"""Tests for unified per-call TEE envelope (bootstrap path)."""

import base64
import secrets
from dataclasses import dataclass
from unittest.mock import patch

from mcp.shared.tee_envelope import (
    NONCE_SIZE,
    create_bootstrap_envelope,
    verify_bootstrap_envelope,
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

    def create_attestation(self, nonce: bytes) -> MockAttestationEvidence:
        return MockAttestationEvidence(role=self.role, nonce=nonce)

    def verify_peer_attestation(
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


# =============================================================================
# Tests for create_bootstrap_envelope
# =============================================================================


class TestCreateRequestEnvelope:
    def test_basic_evidence_round_trip(self):
        """Evidence is created and includes nonce."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "sig_data" in tee_dict
        nonce = base64.b64decode(tee_dict["sig_data"])
        assert len(nonce) == NONCE_SIZE
        assert "quote" in tee_dict
        assert "public_key" in tee_dict
        assert "role" in tee_dict
        # No encryption without peer key
        assert "enc" not in tee_dict

    def test_no_encryption_without_peer(self):
        """Without a known peer, no encryption happens."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "enc" not in tee_dict

    def test_bootstrap_has_no_counter_or_entropy(self):
        """Bootstrap envelopes never have counter or entropy fields."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "counter" not in tee_dict
        assert "entropy" not in tee_dict


# =============================================================================
# Tests for create_bootstrap_envelope (response)
# =============================================================================


class TestCreateResponseEnvelope:
    def test_basic_evidence(self):
        """Response envelope has evidence and nonce."""
        endpoint = MockSecureEndpoint(role="server")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "sig_data" in tee_dict
        assert "quote" in tee_dict
        assert "role" in tee_dict
        assert "enc" not in tee_dict

    def test_no_encryption_in_bootstrap(self):
        """Bootstrap response has no enc field (plaintext only)."""
        endpoint = MockSecureEndpoint(role="server")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "enc" not in tee_dict


# =============================================================================
# Tests for verify_bootstrap_envelope
# =============================================================================


class TestOpenRequestEnvelope:
    def test_valid_verification(self):
        """Valid evidence passes verification."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is True
        assert error == ""

    def test_missing_sig_data_fails(self):
        """Missing sig_data fails verification."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        # No nonce

        valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "sig_data" in error

    def test_tampered_sig_data_fails_verification(self):
        """When verify_peer_attestation returns invalid, the envelope fails."""
        endpoint = MockSecureEndpoint(role="server")
        endpoint._verify_valid = False
        endpoint._verify_error = "Invalid quote"

        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"tampered" * 4).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid quote" in error


# =============================================================================
# Tests for verify_bootstrap_envelope (response)
# =============================================================================


class TestOpenResponseEnvelope:
    def test_valid_verification(self):
        """Valid response evidence passes verification."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()

        with patch("mcp.shared.secure_channel.AttestationEvidence", MockAttestationEvidence):
            valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is True
        assert error == ""

    def test_missing_sig_data_fails(self):
        """Missing sig_data in response fails."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()

        valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="server")

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
            valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Bad quote" in error


# =============================================================================
# Adversarial input tests (malformed base64, types, etc.)
# =============================================================================


class TestMalformedBase64:
    """Verify that malformed base64 in untrusted tee_dict is rejected."""

    def test_invalid_sig_data_base64_request(self):
        """Malformed base64 in nonce is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = "!!!not-valid-base64!!!"

        valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid base64 in sig_data" in error

    def test_invalid_sig_data_base64_response(self):
        """Malformed base64 in nonce rejected on response side."""
        endpoint = MockSecureEndpoint(role="client")
        evidence = MockAttestationEvidence(role="server")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = "!!!not-valid-base64!!!"

        valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="server")

        assert valid is False
        assert "Invalid base64 in sig_data" in error

    def test_invalid_challenge_response_base64(self):
        """Malformed base64 in challenge_response is rejected."""
        endpoint = MockSecureEndpoint(role="server")
        evidence = MockAttestationEvidence(role="client")
        tee_dict = evidence.to_dict()
        tee_dict["sig_data"] = base64.b64encode(b"x" * 32).decode()
        tee_dict["challenge_response"] = "!!!bad-base64!!!"

        valid, error = verify_bootstrap_envelope(endpoint, tee_dict, peer_role="client")

        assert valid is False
        assert "Invalid base64 in challenge_response" in error


# =============================================================================
# Nonce randomness tests
# =============================================================================


class TestSigDataRandomness:
    """Verify nonce is random and unique per envelope."""

    def test_sig_data_is_random_per_call(self):
        """Each bootstrap envelope gets a unique random nonce."""
        endpoint = MockSecureEndpoint(role="client")
        tee1 = create_bootstrap_envelope(endpoint)
        tee2 = create_bootstrap_envelope(endpoint)
        assert tee1["sig_data"] != tee2["sig_data"]


# =============================================================================
# Workload ID tests
# =============================================================================


class TestWorkloadId:
    """Test workload_id propagation in envelopes."""

    def test_workload_id_included(self):
        """Workload ID is included in envelope when provided."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict = create_bootstrap_envelope(endpoint, workload_id="my-agent-v1")

        assert tee_dict["workload_id"] == "my-agent-v1"

    def test_no_workload_id_by_default(self):
        """No workload_id field when not provided."""
        endpoint = MockSecureEndpoint(role="client")

        tee_dict = create_bootstrap_envelope(endpoint)

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

        tee_dict = create_bootstrap_envelope(endpoint, challenge=challenge)

        assert "challenge" in tee_dict
        decoded = base64.b64decode(tee_dict["challenge"])
        assert decoded == challenge

    def test_no_challenge_by_default(self):
        """No challenge field when not provided."""
        endpoint = MockSecureEndpoint(role="server")

        tee_dict = create_bootstrap_envelope(endpoint)

        assert "challenge" not in tee_dict
