"""Environment-variable overrides for TrustedMCP / TrustedServerSession ctor args.

Lets the operator flip TEE-layer behaviour from the container runtime (trustd
passes env through to the MCP process) without touching Python code. Used for
ablation studies where we sweep combinations of (tee_enabled, quote_mode,
authority, rtmr3_policy, policy_registry) without rebuilding the image.

Env vars recognised (all optional; when unset the ctor arg wins):

    TEE_MCP_ENABLED                      true | false
    TEE_MCP_REQUIRE_CLIENT_ATTESTATION   true | false
    TEE_MCP_QUOTE_MODE                   none | session | per_tool_first | per_tool_every
    TEE_MCP_AUTHORITY_ENABLED            true | false
    TEE_MCP_RTMR3_POLICY                 accept | reject | log_and_accept
    TEE_MCP_POLICY_REGISTRY              /path/to/policy.yaml
    TEE_MCP_ALLOWED_CLIENT_RTMR3         comma-separated list of RTMR3 hex values

The module is stateless — import-time is free; reads happen on each
`resolve_from_env()` call so tests can mutate os.environ between cases without
module reload.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_VALID_QUOTE_MODES = frozenset({"none", "session", "per_tool_first", "per_tool_every"})
_VALID_RTMR3_POLICIES = frozenset({"accept", "reject", "log_and_accept"})


def _parse_bool(raw: str) -> bool | None:
    s = raw.strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return None


def resolve_from_env(
    *,
    tee_enabled: bool,
    require_client_attestation: bool,
    quote_mode: str,
    authority_enabled: bool,
    rtmr3_transition_policy: str,
    policy_registry: Any | None,
    allowed_client_rtmr3: list[str] | None,
) -> dict[str, Any]:
    """Apply TEE_MCP_* env overrides on top of the supplied defaults.

    Returns a dict with the final values; callers assign back to their
    instance attributes. Invalid env values are logged and ignored (the ctor
    default is kept) so a typo doesn't silently disable attestation.
    """
    out: dict[str, Any] = {
        "tee_enabled": tee_enabled,
        "require_client_attestation": require_client_attestation,
        "quote_mode": quote_mode,
        "authority_enabled": authority_enabled,
        "rtmr3_transition_policy": rtmr3_transition_policy,
        "policy_registry": policy_registry,
        "allowed_client_rtmr3": allowed_client_rtmr3,
    }

    if (v := os.environ.get("TEE_MCP_ENABLED")) is not None:
        parsed = _parse_bool(v)
        if parsed is None:
            logger.warning("TEE_MCP_ENABLED=%r invalid; keeping default", v)
        else:
            out["tee_enabled"] = parsed

    if (v := os.environ.get("TEE_MCP_REQUIRE_CLIENT_ATTESTATION")) is not None:
        parsed = _parse_bool(v)
        if parsed is None:
            logger.warning("TEE_MCP_REQUIRE_CLIENT_ATTESTATION=%r invalid; keeping default", v)
        else:
            out["require_client_attestation"] = parsed

    if (v := os.environ.get("TEE_MCP_QUOTE_MODE")) is not None:
        if v in _VALID_QUOTE_MODES:
            out["quote_mode"] = v
        else:
            logger.warning(
                "TEE_MCP_QUOTE_MODE=%r invalid; expected one of %s; keeping default",
                v, sorted(_VALID_QUOTE_MODES),
            )

    if (v := os.environ.get("TEE_MCP_AUTHORITY_ENABLED")) is not None:
        parsed = _parse_bool(v)
        if parsed is None:
            logger.warning("TEE_MCP_AUTHORITY_ENABLED=%r invalid; keeping default", v)
        else:
            out["authority_enabled"] = parsed

    if (v := os.environ.get("TEE_MCP_RTMR3_POLICY")) is not None:
        if v in _VALID_RTMR3_POLICIES:
            out["rtmr3_transition_policy"] = v
        else:
            logger.warning(
                "TEE_MCP_RTMR3_POLICY=%r invalid; expected one of %s; keeping default",
                v, sorted(_VALID_RTMR3_POLICIES),
            )

    if (v := os.environ.get("TEE_MCP_POLICY_REGISTRY")) is not None and v:
        # Import here to avoid circular; PolicyRegistry is under mcp.shared.
        from mcp.shared.attestation_policy import PolicyRegistry

        try:
            out["policy_registry"] = PolicyRegistry.from_yaml(v)
        except FileNotFoundError:
            logger.warning("TEE_MCP_POLICY_REGISTRY=%r not found; keeping default", v)
        except Exception as exc:  # noqa: BLE001 — we don't want a bad YAML to blow up start
            logger.warning("TEE_MCP_POLICY_REGISTRY=%r failed to load (%s); keeping default", v, exc)

    if (v := os.environ.get("TEE_MCP_ALLOWED_CLIENT_RTMR3")) is not None and v:
        out["allowed_client_rtmr3"] = [s.strip() for s in v.split(",") if s.strip()]

    return out
