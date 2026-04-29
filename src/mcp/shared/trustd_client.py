"""Synchronous client for trustd JSON-over-Unix-socket API.

Provides access to TDX hardware operations (quote generation, container state)
through the privileged trustd daemon. MCP Server processes are unprivileged
and cannot access /dev/tdx_guest or securityfs directly.

Protocol: newline-delimited JSON over Unix domain socket.
Each request is a single line, each response is a single line.

Usage:
    client = get_trustd_client()
    if client is not None:
        state = client.get_container_state("/docker/abc")
        quote = client.get_td_quote(report_data_64_bytes)
"""

import json
import logging
import os
import socket
import threading
from typing import Any

logger = logging.getLogger(__name__)

TRUSTD_SOCKET_ENV = "TEE_MCP_TRUSTD_SOCKET"
DEFAULT_SOCKET_PATH = "/run/trustd.sock"


class TrustdError(Exception):
    """Error communicating with trustd."""


class TrustdClient:
    """Synchronous client for trustd JSON-over-Unix-socket API.

    Creates a new connection per call (~0.1ms for Unix sockets).
    No reconnection logic needed.
    """

    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path

    def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send request, read response. Creates new connection per call."""
        request = json.dumps({"method": method, "params": params}, separators=(",", ":"))
        request_bytes = (request + "\n").encode()

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(10.0)
            sock.connect(self._socket_path)
            sock.sendall(request_bytes)

            # Read response (newline-delimited)
            response_buffer = b""
            while b"\n" not in response_buffer:
                chunk = sock.recv(65536)
                if not chunk:
                    raise TrustdError("connection closed before response")
                response_buffer += chunk

            line = response_buffer.split(b"\n", 1)[0]
            response = json.loads(line)

            if not response.get("ok"):
                error = response.get("error", "unknown error")
                raise TrustdError(f"trustd error: {error}")

            return response.get("result", {})
        except OSError as e:
            raise TrustdError(f"socket error: {e}") from e
        except json.JSONDecodeError as e:
            raise TrustdError(f"invalid response: {e}") from e
        finally:
            sock.close()

    def get_container_state(self, cgroup_path: str) -> dict[str, Any] | None:
        """Get container state from trustd's StateManager cache.

        Returns:
            Dict with keys: cgroup_path, rtmr3, initial_rtmr3, measurement_count.
            None if container not found.
        """
        try:
            return self._call("GetContainerState", {"cgroup_path": cgroup_path})
        except TrustdError as e:
            if "not found" in str(e):
                return None
            raise

    def get_td_quote(self, report_data: bytes) -> bytes:
        """Generate TDX quote via trustd.

        Args:
            report_data: Exactly 64 bytes of report data.

        Returns:
            TDX quote bytes.
        """
        import base64

        if len(report_data) != 64:
            raise ValueError(f"report_data must be exactly 64 bytes, got {len(report_data)}")

        b64_data = base64.b64encode(report_data).decode()
        result = self._call("GetTDQuote", {"report_data": b64_data})
        return base64.b64decode(result["td_quote"])

    def restart_container(self, cgroup_path: str) -> dict[str, Any]:
        """Restart container via trustd. Sends SIGTERM then SIGKILL after grace period.

        Returns:
            Dict with keys: cgroup_path, signaled_pids, force_killed_pids.
        """
        return self._call("RestartContainer", {"cgroup_path": cgroup_path})

    def attest_workload(
        self,
        workload_id: str,
        nonce: bytes,
        peer_pk: bytes = b"",
    ) -> dict[str, Any]:
        """Produce a canonical attestation bundle for `workload_id`.

        Mirrors trustd.AttestWorkload gRPC: looks up the current cgroup from
        the workload's stable name, reads the kernel's per-container event
        log, and generates a TDX quote whose report_data binds `nonce` and
        (optionally) `peer_pk`. The fork's process cannot read securityfs
        directly (root-only, 0440), so this hop via the privileged trustd
        daemon is the only path to assemble verifier-ready evidence.

        Returns a dict with the exact fields of AttestWorkloadResponse:
            workload_id, cgroup_path, nonce_hex, td_quote (bytes),
            event_log (bytes), report_data_hex, timestamp.
        """
        import base64

        if not workload_id:
            raise ValueError("workload_id is required")
        if not nonce:
            raise ValueError("nonce is required")

        params: dict[str, Any] = {
            "workload_id": workload_id,
            "nonce_hex": nonce.hex(),
        }
        if peer_pk:
            params["peer_pk"] = base64.b64encode(peer_pk).decode()

        result = self._call("AttestWorkload", params)
        result["td_quote"] = base64.b64decode(result.get("td_quote", ""))
        result["event_log"] = base64.b64decode(result.get("event_log", ""))
        return result

    def verify_rtmr3(
        self,
        workload_id: str,
        expected_rtmr3: str | bytes,
    ) -> dict[str, Any]:
        """Fast per-tool RTMR3 verification without quote regeneration.

        Calls trustd.VerifyRtmr3 — trustd reads the current RTMR3 from
        /sys/kernel/security/ima/container_rtmr/<cgroup> (cached for the
        workload_id) and compares to `expected_rtmr3`. No QGS round-trip.
        Used by the per-tool attestation path where we only need to
        detect container drift mid-session, not produce verifier-ready
        evidence.

        Args:
            workload_id: stable workload name (as passed to AttestWorkload).
            expected_rtmr3: hex string or 48-byte digest to compare against.

        Returns:
            {"match": bool, "current_rtmr3_hex": str, "workload_id": str}
            When match=False, `current_rtmr3_hex` tells the caller what the
            container actually measures as; callers apply their
            rtmr3_transition_policy to decide whether to accept/reject/log.
        """
        if not workload_id:
            raise ValueError("workload_id is required")

        if isinstance(expected_rtmr3, bytes):
            if len(expected_rtmr3) != 48:
                raise ValueError(
                    f"expected_rtmr3 bytes must be exactly 48, got {len(expected_rtmr3)}"
                )
            expected_hex = expected_rtmr3.hex()
        else:
            expected_hex = expected_rtmr3.strip().lower()
            # light sanity-check so a 32-hex PCR doesn't silently compare
            # against a 48-hex RTMR3 and look "not matching".
            if len(expected_hex) != 96:
                raise ValueError(
                    f"expected_rtmr3 hex must be 96 chars (48 bytes), got {len(expected_hex)}"
                )

        return self._call(
            "VerifyRtmr3",
            {"workload_id": workload_id, "expected_rtmr3_hex": expected_hex},
        )

    def ping(self) -> dict[str, Any]:
        """Ping trustd. Returns version, uptime_seconds, containers_tracked."""
        return self._call("Ping", {})


# Lazy singleton
_trustd_client: TrustdClient | None = None
_trustd_client_checked = False
_trustd_client_lock = threading.Lock()


def get_trustd_client() -> TrustdClient | None:
    """Get trustd client if socket exists. Lazy singleton.

    Checks TEE_MCP_TRUSTD_SOCKET env var first, then default path.
    Returns None if no socket is available.
    """
    global _trustd_client, _trustd_client_checked  # noqa: PLW0603

    with _trustd_client_lock:
        if _trustd_client_checked:
            return _trustd_client

        socket_path = os.environ.get(TRUSTD_SOCKET_ENV, "")
        if not socket_path:
            socket_path = DEFAULT_SOCKET_PATH

        if os.path.exists(socket_path):
            _trustd_client = TrustdClient(socket_path)
            logger.info("trustd client initialized: %s", socket_path)
        else:
            _trustd_client = None
            logger.debug("trustd socket not found at %s", socket_path)

        _trustd_client_checked = True
        return _trustd_client


def reset_trustd_client() -> None:
    """Reset the singleton (for testing)."""
    global _trustd_client, _trustd_client_checked
    with _trustd_client_lock:
        _trustd_client = None
        _trustd_client_checked = False
