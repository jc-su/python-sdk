"""
TDX (Trust Domain Extensions) attestation support.

Provides:
- TDX quote generation (via /dev/tdx_guest)
- Quote parsing
- Per-container RTMR3 from kernel (JSONL format)

Requires real TDX hardware - no simulation mode.
"""

import ctypes
import fcntl
import hashlib
import json
import logging
import os
import struct
from dataclasses import dataclass
from typing import Optional

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


# =============================================================================
# Constants
# =============================================================================

TDX_GUEST_DEVICE = "/dev/tdx_guest"
TDX_ATTEST_DEVICE = "/dev/tdx-attest"
CONTAINER_RTMR_PATH = "/sys/kernel/security/ima/container_rtmr"

SHA384_SIZE = 48
SHA256_SIZE = 32
REPORTDATA_SIZE = 64
MAX_QUOTE_SIZE = 8192

# TDX ioctl: _IOWR('T', cmd, size)
def _IOWR(type_char: str, nr: int, size: int) -> int:
    return (3 << 30) | (size << 16) | (ord(type_char) << 8) | nr

TDX_REPORT_REQ_SIZE = 64 + 1024
TDX_CMD_GET_REPORT = _IOWR('T', 1, TDX_REPORT_REQ_SIZE)
TDX_QUOTE_REQ_SIZE = 64 + 4 + 8
TDX_CMD_GET_QUOTE = _IOWR('T', 2, TDX_QUOTE_REQ_SIZE)


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

    def to_dict(self) -> dict:
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

    def to_dict(self) -> dict:
        return {"digest": self.digest.hex(), "file": self.filename}


@dataclass
class ContainerState:
    """Per-container state from kernel JSONL interface."""
    cgroup: str
    baseline: bytes          # 48 bytes - RTMR2 at container start
    rtmr3: bytes             # 48 bytes - current virtual RTMR3
    count: int               # measurement count
    measurements: list[ContainerMeasurement]

    def to_dict(self) -> dict:
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

def is_tdx_available() -> bool:
    """Check if TDX is available (via trustd or direct device access)."""
    # Try trustd first (privileged daemon with TDX access)
    try:
        from mcp.shared.trustd_client import get_trustd_client

        client = get_trustd_client()
        if client is not None:
            client.ping()
            return True
    except Exception:
        pass

    # Fallback to direct device access
    return os.path.exists(TDX_GUEST_DEVICE) or os.path.exists(TDX_ATTEST_DEVICE)


def require_tdx() -> None:
    """Raise TdxNotAvailableError if TDX is not available."""
    if not is_tdx_available():
        raise TdxNotAvailableError(
            "TDX hardware not available. "
            f"Expected {TDX_GUEST_DEVICE} or {TDX_ATTEST_DEVICE}"
        )


def generate_quote(reportdata: bytes) -> bytes:
    """
    Generate TDX quote with reportdata binding.

    Tries trustd Unix socket first (privileged daemon), falls back to direct
    device access if trustd is unavailable.

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
        rd = reportdata + bytes(REPORTDATA_SIZE - len(reportdata))
    else:
        rd = reportdata[:REPORTDATA_SIZE]

    # Try trustd first
    try:
        from mcp.shared.trustd_client import get_trustd_client

        client = get_trustd_client()
        if client is not None:
            return client.get_td_quote(rd)
    except Exception:
        logger.debug("trustd quote generation failed, falling back to direct access", exc_info=True)

    # Fallback to direct device access
    require_tdx()

    dev_path = TDX_GUEST_DEVICE if os.path.exists(TDX_GUEST_DEVICE) else TDX_ATTEST_DEVICE

    try:
        quote_buffer = ctypes.create_string_buffer(MAX_QUOTE_SIZE)
        quote_addr = ctypes.addressof(quote_buffer)

        req = bytearray(TDX_QUOTE_REQ_SIZE)
        req[0:64] = rd
        struct.pack_into('<I', req, 64, MAX_QUOTE_SIZE)
        struct.pack_into('<Q', req, 68, quote_addr)

        with open(dev_path, 'rb') as fd:
            fcntl.ioctl(fd.fileno(), TDX_CMD_GET_QUOTE, bytes(req))

        quote_size = struct.unpack_from('<I', req, 64)[0]
        return quote_buffer.raw[:quote_size]

    except OSError as e:
        raise TdxQuoteError(f"Failed to generate TDX quote: {e}") from e
    except Exception as e:
        raise TdxQuoteError(f"Unexpected error generating TDX quote: {e}") from e


def parse_quote(quote_data: bytes) -> Optional[TdxQuote]:
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
        with open("/proc/self/cgroup", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return "/"


def read_container_state(cgroup: str) -> Optional[ContainerState]:
    """
    Read container state from trustd or kernel JSONL interface.

    Tries trustd Unix socket first (privileged daemon with cached state),
    falls back to direct kernel access if trustd is unavailable.

    Format: {"cgroup":"/docker/abc","baseline":"hex","rtmr3":"hex","count":N,"measurements":[...]}
    """
    # Try trustd first
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
        logger.debug("trustd container state failed, falling back to direct access", exc_info=True)

    # Fallback to direct kernel access
    try:
        with open(CONTAINER_RTMR_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("cgroup") == cgroup:
                        measurements = [
                            ContainerMeasurement(
                                digest=bytes.fromhex(m["digest"]),
                                filename=m.get("file", ""),
                            )
                            for m in entry.get("measurements", [])
                        ]
                        return ContainerState(
                            cgroup=entry["cgroup"],
                            baseline=bytes.fromhex(entry["baseline"]),
                            rtmr3=bytes.fromhex(entry["rtmr3"]),
                            count=entry.get("count", len(measurements)),
                            measurements=measurements,
                        )
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.debug("Container RTMR interface not available")
    except Exception:
        logger.warning("Failed to read container state", exc_info=True)
    return None


def get_container_rtmr3(cgroup: Optional[str] = None) -> bytes:
    """
    Get container's virtual RTMR3 value.

    Returns zero bytes if container state not available.
    """
    if cgroup is None:
        cgroup = get_current_cgroup()
    state = read_container_state(cgroup)
    return state.rtmr3 if state else bytes(SHA384_SIZE)


def replay_measurements(measurements: list[ContainerMeasurement], baseline: bytes) -> bytes:
    """
    Replay measurements to compute expected RTMR3.

    Formula: rtmr = SHA384(rtmr || measurement) for each measurement
    """
    rtmr = baseline
    for m in measurements:
        digest = m.digest
        if len(digest) < SHA384_SIZE:
            digest = digest + bytes(SHA384_SIZE - len(digest))
        rtmr = hashlib.sha384(rtmr + digest).digest()
    return rtmr


def verify_container(cgroup: str, allowed_files: Optional[list[str]] = None) -> tuple[bool, str]:
    """
    Verify container's RTMR3 by replaying measurements.

    Args:
        cgroup: Container's cgroup path
        allowed_files: Optional glob patterns for allowed files

    Returns:
        (valid, error_message)
    """
    import fnmatch

    state = read_container_state(cgroup)
    if state is None:
        return False, f"Container not found: {cgroup}"

    # Replay and compare
    computed = replay_measurements(state.measurements, state.baseline)
    if computed != state.rtmr3:
        return False, f"RTMR3 mismatch: computed={computed.hex()[:16]}... kernel={state.rtmr3.hex()[:16]}..."

    # Check allowed files
    if allowed_files:
        for m in state.measurements:
            if not any(fnmatch.fnmatch(m.filename, pat) for pat in allowed_files):
                return False, f"Untrusted file: {m.filename}"

    return True, ""
