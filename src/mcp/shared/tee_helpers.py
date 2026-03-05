"""Shared helpers for TEE envelope injection/extraction.

Used by both TrustedClientSession and TrustedServerSession to avoid
duplicating _meta.tee manipulation patterns.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def extract_tee_dict(params: Any) -> dict | None:
    """Extract _meta.tee dict from a Pydantic params object.

    Handles the model_extra lookup chain:
    params.meta -> getattr(meta, "model_extra", {}) -> .get("tee")
    """
    if params is None:
        return None
    meta = getattr(params, "meta", None)
    if meta is None:
        meta = getattr(params, "_meta", None)
    if meta is None:
        return None
    # Meta can be a plain dict (current upstream) or a Pydantic model (legacy)
    if isinstance(meta, dict):
        return meta.get("tee")
    extra = getattr(meta, "model_extra", None) or {}
    tee = extra.get("tee")
    if tee is not None:
        return tee
    return getattr(meta, "tee", None)


def inject_tee(data_dict: dict, tee_dict: dict, *, params_level: bool = False) -> None:
    """Inject tee_dict into data_dict's _meta.tee, creating keys as needed.

    Args:
        data_dict: The dict to inject into.
        tee_dict: The TEE envelope dict.
        params_level: If True, inject at data_dict["params"]["_meta"]["tee"].
            If False, inject at data_dict["_meta"]["tee"].
    """
    if params_level:
        if "params" not in data_dict:
            data_dict["params"] = {}
        target = data_dict["params"]
    else:
        target = data_dict

    if "_meta" not in target:
        target["_meta"] = {}
    target["_meta"]["tee"] = tee_dict


def extract_tee_from_result(result_dict: dict) -> dict | None:
    """Extract _meta.tee from a JSON-RPC result dict."""
    if not result_dict:
        return None
    return (result_dict.get("_meta") or {}).get("tee")
