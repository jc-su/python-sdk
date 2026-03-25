"""TDX (Trust Domain Extensions) attestation support.

Provides:
- TDX quote generation via trustd
- Quote parsing
- Per-container RTMR3 via trustd

MCP is intentionally unprivileged. All quote/state access must go through trustd.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class TdxError(Exception):
    """Base exception for TDX operations."""
    pass


class TdxNotAvailableError(TdxError):
    """Raised when TDX hardware is not available."""
    pass


class TdxQuoteError(TdxError):
    """Raised when TDX quote generation fails."""
    pass


SHA384_SIZE = 48
SHA256_SIZE = 32
REPORTDATA_SIZE = 64


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TdxMeasurements:
    """TDX measurement registers from quote."""
    mrtd: bytes      # 48 bytes - TD measurement
    rtmr0: bytes     # 48 bytes
    rtmr1: bytes     # 48 bytes
    rtmr2: bytes     # 48 bytes
    rtmr3: bytes     # 48 bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "mrtd": self.mrtd.hex(),
            "rtmr0": self.rtmr0.hex(),
            "rtmr1": self.rtmr1.hex(),
            "rtmr2": self.rtmr2.hex(),
            "rtmr3": self.rtmr3.hex(),
        }


@dataclass
class TdxQuote:
    """Parsed TDX quote."""
    version: int
    reportdata: bytes       # 64 bytes - user data bound in quote
    measurements: TdxMeasurements
    raw: bytes


@dataclass
class ContainerMeasurement:
    """Single measurement from container's log."""
    digest: bytes    # 48 bytes SHA384
    filename: str

    def to_dict(self) -> dict[str, Any]:
        return {"digest": self.digest.hex(), "file": self.filename}


@dataclass
class ContainerState:
    """Per-container state from kernel JSONL interface."""
    cgroup: str
    baseline: bytes          # 48 bytes - RTMR2 at container start
    rtmr3: bytes             # 48 bytes - current virtual RTMR3
    count: int               # measurement count
    measurements: list[ContainerMeasurement]

    def to_dict(self) -> dict[str, Any]:
        return {
            "cgroup": self.cgroup,
            "baseline": self.baseline.hex(),
            "rtmr3": self.rtmr3.hex(),
            "count": self.count,
            "measurements": [m.to_dict() for m in self.measurements],
        }


# =============================================================================
# TDX Device Functions
# =============================================================================


def generate_quote(reportdata: bytes) -> bytes:
    """Generate TDX quote with reportdata binding via trustd.

    Args:
        reportdata: Data to bind into quote (up to 64 bytes)

    Returns:
        TDX quote bytes

    Raises:
        TdxNotAvailableError: If TDX hardware is not available
        TdxQuoteError: If quote generation fails
    """
    # Pad/truncate reportdata to 64 bytes
    if len(reportdata) < REPORTDATA_SIZE:
        padded_reportdata = reportdata + bytes(REPORTDATA_SIZE - len(reportdata))
    else:
        padded_reportdata = reportdata[:REPORTDATA_SIZE]

    try:
        from mcp.shared.trustd_client import get_trustd_client

        client = get_trustd_client()
        if client is None:
            raise TdxNotAvailableError("trustd client unavailable")
        return client.get_td_quote(padded_reportdata)
    except TdxNotAvailableError:
        raise
    except Exception as e:
        raise TdxQuoteError(f"Failed to generate TDX quote via trustd: {e}") from e


def parse_quote(quote_data: bytes) -> TdxQuote | None:
    """Parse a TDX quote."""
    if len(quote_data) < 48 + 584:
        return None

    try:
        version = struct.unpack_from('<H', quote_data, 0)[0]
        body_offset = 48

        measurements = TdxMeasurements(
            mrtd=quote_data[body_offset+136:body_offset+184],
            rtmr0=quote_data[body_offset+328:body_offset+376],
            rtmr1=quote_data[body_offset+376:body_offset+424],
            rtmr2=quote_data[body_offset+424:body_offset+472],
            rtmr3=quote_data[body_offset+472:body_offset+520],
        )

        reportdata = quote_data[body_offset+520:body_offset+584]

        return TdxQuote(
            version=version,
            reportdata=reportdata,
            measurements=measurements,
            raw=quote_data,
        )
    except Exception:
        logger.exception("Failed to parse quote")
        return None


# =============================================================================
# Container RTMR Functions (Kernel JSONL Interface)
# =============================================================================

def get_current_cgroup() -> str:
    """Get current process's cgroup path."""
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                cgroup_parts = line.strip().split(":")
                if len(cgroup_parts) >= 3:
                    return cgroup_parts[2]
    except Exception:
        pass
    return "/"


def read_container_state(cgroup: str) -> ContainerState | None:
    """Read container state from trustd.

    trustd is the only supported source for container RTMR state in MCP.
    """
    try:
        from mcp.shared.trustd_client import get_trustd_client

        client = get_trustd_client()
        if client is not None:
            result = client.get_container_state(cgroup)
            if result is not None:
                return ContainerState(
                    cgroup=result["cgroup_path"],
                    baseline=bytes(SHA384_SIZE),  # trustd doesn't expose baseline
                    rtmr3=bytes.fromhex(result["rtmr3"]),
                    count=result.get("measurement_count", 0),
                    measurements=[],  # trustd doesn't expose measurements
                )
            return None
    except Exception:
        logger.warning("Failed to read container state via trustd", exc_info=True)
    return None


def get_container_rtmr3(cgroup: str | None = None) -> bytes:
    """Get container's virtual RTMR3 value.

    Returns zero bytes if container state not available.
    """
    if cgroup is None:
        cgroup = get_current_cgroup()
    state = read_container_state(cgroup)
    return state.rtmr3 if state else bytes(SHA384_SIZE)


