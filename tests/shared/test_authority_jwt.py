"""Tests for AuthorityJWTVerifier — JWKS-based JWT verification."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from mcp.shared.authority_jwt import (
    AuthorityJWTVerifier,
    JWTVerificationResult,
    get_default_jwt_verifier,
)

# =============================================================================
# Helpers: generate RSA key and sign JWTs for testing
# =============================================================================


def _generate_rsa_key_pair():
    """Generate an RSA key pair for test JWT signing."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


def _make_jwks_response(private_key) -> dict:
    """Build a JWKS JSON response from an RSA private key."""
    import jwt

    public_key = private_key.public_key()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = "test-key-1"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


def _sign_jwt(private_key, claims: dict, headers: dict | None = None) -> str:
    """Sign a JWT with the test RSA key."""
    import jwt

    default_headers = {"kid": "test-key-1"}
    if headers:
        default_headers.update(headers)
    return jwt.encode(claims, private_key, algorithm="RS256", headers=default_headers)


def _make_verifier_with_mock_jwks(private_key, *, algorithms: list[str] | None = None) -> AuthorityJWTVerifier:
    """Create an AuthorityJWTVerifier with mocked JWKS fetching."""
    import jwt as pyjwt

    verifier = AuthorityJWTVerifier(
        "https://authority.example.com/.well-known/jwks.json",
        algorithms=algorithms or ["RS256"],
        clock_skew_s=30,
    )
    # Replace the JWKS client with a mock that returns our test key
    jwks_data = _make_jwks_response(private_key)

    mock_client = MagicMock(spec=pyjwt.PyJWKClient)

    def get_signing_key(token: str) -> MagicMock:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        for key_data in jwks_data["keys"]:
            if key_data.get("kid") == kid:
                public_key = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
                result = MagicMock()
                result.key = public_key
                return result
        raise pyjwt.PyJWKClientError(f"Key not found: {kid}")

    mock_client.get_signing_key_from_jwt = get_signing_key
    verifier._jwks_client = mock_client
    return verifier


# =============================================================================
# Tests
# =============================================================================


class TestJWTVerificationResult:
    """Tests for JWTVerificationResult dataclass."""

    def test_valid_result(self) -> None:
        result = JWTVerificationResult(valid=True, claims={"sub": "test"}, expires_at=1000.0)
        assert result.valid is True
        assert result.error == ""
        assert result.claims == {"sub": "test"}
        assert result.expires_at == 1000.0

    def test_invalid_result(self) -> None:
        result = JWTVerificationResult(valid=False, error="Token expired")
        assert result.valid is False
        assert result.error == "Token expired"
        assert result.claims == {}
        assert result.expires_at == 0.0

    def test_frozen(self) -> None:
        result = JWTVerificationResult(valid=True)
        with pytest.raises(AttributeError):
            result.valid = False  # type: ignore[misc]


class TestAuthorityJWTVerifier:
    """Tests for AuthorityJWTVerifier."""

    def test_happy_path(self) -> None:
        """Valid JWT with correct signature and claims."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "cgroup:///docker/server-abc",
                "iat": int(now),
                "exp": int(now) + 3600,
                "rtmr3": "aa" * 48,
            },
        )

        result = verifier.verify_attestation_token(token)
        assert result.valid is True
        assert result.error == ""
        assert result.claims["sub"] == "cgroup:///docker/server-abc"
        assert result.expires_at == pytest.approx(now + 3600, abs=1)

    def test_expired_token(self) -> None:
        """Expired JWT returns valid=False."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "test",
                "iat": int(now) - 7200,
                "exp": int(now) - 3600,
            },
        )

        result = verifier.verify_attestation_token(token)
        assert result.valid is False
        assert "expired" in result.error.lower()

    def test_wrong_signature(self) -> None:
        """JWT signed with wrong key returns valid=False."""
        private_key = _generate_rsa_key_pair()
        wrong_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        # Sign with wrong key but use the same kid
        token = _sign_jwt(
            wrong_key,
            {
                "sub": "test",
                "iat": int(now),
                "exp": int(now) + 3600,
            },
        )

        result = verifier.verify_attestation_token(token)
        assert result.valid is False

    def test_missing_required_claims(self) -> None:
        """JWT missing exp/iat returns valid=False."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        # Missing exp and iat
        import jwt

        token = jwt.encode({"sub": "test"}, private_key, algorithm="RS256", headers={"kid": "test-key-1"})

        result = verifier.verify_attestation_token(token)
        assert result.valid is False
        assert "failed" in result.error.lower() or "missing" in result.error.lower()

    def test_subject_mismatch_cross_check(self) -> None:
        """Subject cross-check mismatch returns valid=False."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "cgroup:///docker/server-abc",
                "iat": int(now),
                "exp": int(now) + 3600,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_subject="cgroup:///docker/different-container",
        )
        assert result.valid is False
        assert "subject mismatch" in result.error.lower()
        # Claims should still be populated
        assert result.claims["sub"] == "cgroup:///docker/server-abc"

    def test_subject_match_passes(self) -> None:
        """Subject cross-check with matching value passes."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "cgroup:///docker/server-abc",
                "iat": int(now),
                "exp": int(now) + 3600,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_subject="cgroup:///docker/server-abc",
        )
        assert result.valid is True

    def test_subject_not_in_jwt_fails(self) -> None:
        """When JWT has no sub claim but expected_subject is given, cross-check fails."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "iat": int(now),
                "exp": int(now) + 3600,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_subject="cgroup:///docker/server-abc",
        )
        assert result.valid is False
        assert "no 'sub' claim" in result.error

    def test_rtmr3_mismatch_cross_check(self) -> None:
        """RTMR3 cross-check mismatch returns valid=False."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "test",
                "iat": int(now),
                "exp": int(now) + 3600,
                "rtmr3": "aa" * 48,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_rtmr3="bb" * 48,
        )
        assert result.valid is False
        assert "rtmr3 mismatch" in result.error.lower()

    def test_rtmr3_match_passes(self) -> None:
        """RTMR3 cross-check with matching value passes."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "test",
                "iat": int(now),
                "exp": int(now) + 3600,
                "rtmr3": "aa" * 48,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_rtmr3="aa" * 48,
        )
        assert result.valid is True

    def test_rtmr3_not_in_jwt_fails(self) -> None:
        """When JWT has no rtmr3 claim but expected_rtmr3 is given, cross-check fails."""
        private_key = _generate_rsa_key_pair()
        verifier = _make_verifier_with_mock_jwks(private_key)

        now = time.time()
        token = _sign_jwt(
            private_key,
            {
                "sub": "test",
                "iat": int(now),
                "exp": int(now) + 3600,
            },
        )

        result = verifier.verify_attestation_token(
            token,
            expected_rtmr3="bb" * 48,
        )
        assert result.valid is False
        assert "no 'rtmr3' claim" in result.error

    def test_jwks_endpoint_unreachable(self) -> None:
        """JWKS endpoint failure returns valid=False with error."""
        import jwt as pyjwt

        verifier = AuthorityJWTVerifier(
            "https://unreachable.example.com/.well-known/jwks.json",
            algorithms=["RS256"],
        )
        # Mock the JWKS client to raise
        mock_client = MagicMock(spec=pyjwt.PyJWKClient)
        mock_client.get_signing_key_from_jwt.side_effect = pyjwt.PyJWKClientError("Connection refused")
        verifier._jwks_client = mock_client

        result = verifier.verify_attestation_token("eyJ.fake.token")
        assert result.valid is False
        assert "JWKS" in result.error

    def test_enabled_property(self) -> None:
        """enabled property reflects JWKS URL configuration."""
        verifier = AuthorityJWTVerifier("https://example.com/jwks", algorithms=["RS256"])
        assert verifier.enabled is True


class TestFromEnv:
    """Tests for AuthorityJWTVerifier.from_env()."""

    def test_no_jwks_url_returns_none(self) -> None:
        """Returns None when TEE_MCP_AUTHORITY_JWKS_URL is not set."""
        with patch.dict("os.environ", {}, clear=True):
            result = AuthorityJWTVerifier.from_env()
            assert result is None

    def test_empty_jwks_url_returns_none(self) -> None:
        """Returns None when TEE_MCP_AUTHORITY_JWKS_URL is empty."""
        with patch.dict("os.environ", {"TEE_MCP_AUTHORITY_JWKS_URL": "  "}, clear=True):
            result = AuthorityJWTVerifier.from_env()
            assert result is None

    def test_configured_jwks_url(self) -> None:
        """Returns verifier when JWKS URL is set."""
        env = {"TEE_MCP_AUTHORITY_JWKS_URL": "https://authority.example.com/.well-known/jwks.json"}
        with patch.dict("os.environ", env, clear=True):
            result = AuthorityJWTVerifier.from_env()
            assert result is not None
            assert result.enabled is True
            assert result._algorithms == ["RS256", "ES256"]
            assert result._clock_skew_s == 30

    def test_custom_algorithms(self) -> None:
        """Custom algorithms from env."""
        env = {
            "TEE_MCP_AUTHORITY_JWKS_URL": "https://example.com/jwks",
            "TEE_MCP_AUTHORITY_JWT_ALGORITHMS": "ES384,PS256",
        }
        with patch.dict("os.environ", env, clear=True):
            result = AuthorityJWTVerifier.from_env()
            assert result is not None
            assert result._algorithms == ["ES384", "PS256"]

    def test_custom_clock_skew(self) -> None:
        """Custom clock skew from env."""
        env = {
            "TEE_MCP_AUTHORITY_JWKS_URL": "https://example.com/jwks",
            "TEE_MCP_AUTHORITY_JWT_CLOCK_SKEW_S": "60",
        }
        with patch.dict("os.environ", env, clear=True):
            result = AuthorityJWTVerifier.from_env()
            assert result is not None
            assert result._clock_skew_s == 60


class TestGetDefaultJWTVerifier:
    """Tests for get_default_jwt_verifier() lazy singleton."""

    def test_returns_none_when_not_configured(self) -> None:
        """Returns None when env vars are not set."""
        import mcp.shared.authority_jwt as mod

        # Reset singleton state
        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False

        with patch.dict("os.environ", {}, clear=True):
            result = get_default_jwt_verifier()
            assert result is None

        # Reset for other tests
        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False

    def test_returns_verifier_when_configured(self) -> None:
        """Returns verifier when env vars are set."""
        import mcp.shared.authority_jwt as mod

        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False

        env = {"TEE_MCP_AUTHORITY_JWKS_URL": "https://example.com/jwks"}
        with patch.dict("os.environ", env, clear=True):
            result = get_default_jwt_verifier()
            assert result is not None
            assert isinstance(result, AuthorityJWTVerifier)

        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False

    def test_singleton_initialized_once(self) -> None:
        """Verifier is only created once (lazy singleton)."""
        import mcp.shared.authority_jwt as mod

        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False

        env = {"TEE_MCP_AUTHORITY_JWKS_URL": "https://example.com/jwks"}
        with patch.dict("os.environ", env, clear=True):
            v1 = get_default_jwt_verifier()
            v2 = get_default_jwt_verifier()
            assert v1 is v2

        mod._DEFAULT_VERIFIER = None
        mod._DEFAULT_VERIFIER_INITIALIZED = False
