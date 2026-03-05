"""JWKS-based JWT verification for attestation authority tokens.

Verifies JWTs issued by the attestation authority (e.g. attestation-service)
for server/client trust decisions. Supports local signature verification,
expiry checking, and cross-checking against bootstrap-attested values.

Environment variables:
    TEE_MCP_AUTHORITY_JWKS_URL: JWKS endpoint for the attestation authority
    TEE_MCP_AUTHORITY_JWT_ALGORITHMS: Accepted JWT signing algorithms (default: RS256,ES256)
    TEE_MCP_AUTHORITY_JWT_CLOCK_SKEW_S: Clock skew tolerance in seconds (default: 30)
    TEE_MCP_AUTHORITY_JWT_ISSUER: Expected JWT issuer (optional)
    TEE_MCP_AUTHORITY_JWT_AUDIENCE: Expected JWT audience (optional)
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class JWTVerificationResult:
    """Result of JWT attestation token verification."""

    valid: bool
    error: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    expires_at: float = 0.0  # from JWT exp claim


class AuthorityJWTVerifier:
    """JWKS-based JWT verification for attestation authority tokens."""

    def __init__(
        self,
        jwks_url: str,
        *,
        algorithms: list[str] | None = None,
        clock_skew_s: int = 30,
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        import jwt

        self._jwks_url = jwks_url
        self._algorithms = algorithms or ["RS256", "ES256"]
        self._clock_skew_s = clock_skew_s
        self._issuer = issuer
        self._audience = audience
        self._jwks_client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300)

    @classmethod
    def from_env(cls) -> AuthorityJWTVerifier | None:
        """Construct from environment variables. Returns None if JWKS URL is not set."""
        jwks_url = os.environ.get("TEE_MCP_AUTHORITY_JWKS_URL", "").strip()
        if not jwks_url:
            return None

        algorithms_str = os.environ.get("TEE_MCP_AUTHORITY_JWT_ALGORITHMS", "RS256,ES256").strip()
        algorithms = [a.strip() for a in algorithms_str.split(",") if a.strip()]

        clock_skew_s = int(os.environ.get("TEE_MCP_AUTHORITY_JWT_CLOCK_SKEW_S", "30"))
        issuer = os.environ.get("TEE_MCP_AUTHORITY_JWT_ISSUER", "").strip() or None
        audience = os.environ.get("TEE_MCP_AUTHORITY_JWT_AUDIENCE", "").strip() or None

        return cls(jwks_url, algorithms=algorithms, clock_skew_s=clock_skew_s, issuer=issuer, audience=audience)

    def verify_attestation_token(
        self,
        token: str,
        *,
        expected_subject: str | None = None,
        expected_rtmr3: str | None = None,
    ) -> JWTVerificationResult:
        """Verify JWT: decode header, fetch JWKS, verify sig, validate exp, cross-check claims."""
        import jwt

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except (jwt.PyJWKClientError, jwt.DecodeError) as e:
            return JWTVerificationResult(valid=False, error=f"JWKS key retrieval failed: {e}")

        decode_options: dict[str, Any] = {"require": ["exp", "iat"]}
        decode_kwargs: dict[str, Any] = {
            "algorithms": self._algorithms,
            "options": decode_options,
            "leeway": self._clock_skew_s,
        }
        if self._issuer is not None:
            decode_kwargs["issuer"] = self._issuer
        if self._audience is not None:
            decode_kwargs["audience"] = self._audience

        try:
            claims = jwt.decode(token, signing_key.key, **decode_kwargs)
        except jwt.ExpiredSignatureError:
            return JWTVerificationResult(valid=False, error="Token expired")
        except jwt.InvalidIssuerError:
            return JWTVerificationResult(valid=False, error="Invalid issuer")
        except jwt.InvalidAudienceError:
            return JWTVerificationResult(valid=False, error="Invalid audience")
        except jwt.InvalidTokenError as e:
            return JWTVerificationResult(valid=False, error=f"Token validation failed: {e}")

        expires_at = float(claims.get("exp", 0))

        # Cross-check: subject
        if expected_subject is not None:
            jwt_sub = claims.get("sub")
            if jwt_sub is None:
                return JWTVerificationResult(
                    valid=False,
                    error=f"Subject expected ({expected_subject!r}) but JWT has no 'sub' claim",
                    claims=claims,
                    expires_at=expires_at,
                )
            if jwt_sub != expected_subject:
                return JWTVerificationResult(
                    valid=False,
                    error=f"Subject mismatch: JWT sub={jwt_sub!r}, expected={expected_subject!r}",
                    claims=claims,
                    expires_at=expires_at,
                )

        # Cross-check: RTMR3
        if expected_rtmr3 is not None:
            jwt_rtmr3 = claims.get("rtmr3")
            if jwt_rtmr3 is None:
                return JWTVerificationResult(
                    valid=False,
                    error=f"RTMR3 expected ({expected_rtmr3!r}) but JWT has no 'rtmr3' claim",
                    claims=claims,
                    expires_at=expires_at,
                )
            if jwt_rtmr3 != expected_rtmr3:
                return JWTVerificationResult(
                    valid=False,
                    error=f"RTMR3 mismatch: JWT rtmr3={jwt_rtmr3!r}, expected={expected_rtmr3!r}",
                    claims=claims,
                    expires_at=expires_at,
                )

        return JWTVerificationResult(valid=True, claims=claims, expires_at=expires_at)

    @property
    def enabled(self) -> bool:
        """Whether this verifier is configured and usable."""
        return bool(self._jwks_url)


# =============================================================================
# Module-level lazy singleton (same pattern as attestation_authority_client.py)
# =============================================================================

_DEFAULT_VERIFIER_LOCK = threading.Lock()
_DEFAULT_VERIFIER: AuthorityJWTVerifier | None = None
_DEFAULT_VERIFIER_INITIALIZED = False


def get_default_jwt_verifier() -> AuthorityJWTVerifier | None:
    """Get process-wide JWT verifier from env (lazily initialized)."""
    global _DEFAULT_VERIFIER, _DEFAULT_VERIFIER_INITIALIZED  # noqa: PLW0603
    with _DEFAULT_VERIFIER_LOCK:
        if not _DEFAULT_VERIFIER_INITIALIZED:
            _DEFAULT_VERIFIER = AuthorityJWTVerifier.from_env()
            _DEFAULT_VERIFIER_INITIALIZED = True
        return _DEFAULT_VERIFIER
