"""Tests for trustd Unix socket client."""

import base64
import json
import os
import socket
import tempfile
import threading

import pytest

from mcp.shared.trustd_client import (
    TrustdClient,
    TrustdError,
    get_trustd_client,
    reset_trustd_client,
)


class MockTrustdServer:
    """Mock trustd server for testing.

    Listens on a Unix socket and handles JSON-over-newline requests.
    """

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._handlers: dict[str, object] = {
            "GetContainerState": self._handle_get_container_state,
            "GetTDQuote": self._handle_get_td_quote,
            "RestartContainer": self._handle_restart_container,
            "Ping": self._handle_ping,
        }
        self.containers: dict[str, dict] = {}
        self.quote_response: bytes = b"fake_quote_data"
        self.quote_available: bool = True
        self.restart_calls: list[str] = []

    def start(self) -> None:
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)
        self._server_socket.listen(5)
        self._server_socket.settimeout(2.0)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        if self._thread:
            self._thread.join(timeout=3.0)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, _ = self._server_socket.accept()  # type: ignore[union-attr]
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except (socket.timeout, OSError):
                continue

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk

            line = buf.split(b"\n", 1)[0]
            request = json.loads(line)
            method = request.get("method", "")
            params = request.get("params", {})

            handler = self._handlers.get(method)
            if handler:
                response = handler(params)
            else:
                response = {"ok": False, "error": f"unknown method: {method}"}

            conn.sendall(json.dumps(response).encode() + b"\n")
        except Exception:
            pass
        finally:
            conn.close()

    def _handle_get_container_state(self, params: dict) -> dict:
        cgroup_path = params.get("cgroup_path", "")
        if not cgroup_path:
            return {"ok": False, "error": "missing required param: cgroup_path"}
        state = self.containers.get(cgroup_path)
        if state is None:
            return {"ok": False, "error": f"container not found: {cgroup_path}"}
        return {"ok": True, "result": state}

    def _handle_get_td_quote(self, params: dict) -> dict:
        if not self.quote_available:
            return {"ok": False, "error": "TDX quotes are unavailable on this host"}
        report_data_b64 = params.get("report_data", "")
        try:
            report_data = base64.b64decode(report_data_b64)
        except Exception:
            return {"ok": False, "error": "invalid base64"}
        if len(report_data) != 64:
            return {"ok": False, "error": f"report_data must be exactly 64 bytes, got {len(report_data)}"}
        return {"ok": True, "result": {"td_quote": base64.b64encode(self.quote_response).decode()}}

    def _handle_restart_container(self, params: dict) -> dict:
        cgroup_path = params.get("cgroup_path", "")
        if not cgroup_path:
            return {"ok": False, "error": "missing required param: cgroup_path"}
        self.restart_calls.append(cgroup_path)
        return {
            "ok": True,
            "result": {
                "cgroup_path": cgroup_path,
                "signaled_pids": 2,
                "force_killed_pids": 0,
            },
        }

    def _handle_ping(self, params: dict) -> dict:
        return {
            "ok": True,
            "result": {"version": "0.1.0-test", "uptime_seconds": 42, "containers_tracked": len(self.containers)},
        }


@pytest.fixture()
def mock_server(tmp_path):
    """Create and start a mock trustd server."""
    socket_path = str(tmp_path / "trustd.sock")
    server = MockTrustdServer(socket_path)
    server.containers["/docker/abc"] = {
        "cgroup_path": "/docker/abc",
        "rtmr3": "aa" * 48,
        "initial_rtmr3": "bb" * 48,
        "measurement_count": 5,
    }
    server.start()
    yield server
    server.stop()


@pytest.fixture()
def client(mock_server):
    """Create a TrustdClient connected to mock server."""
    return TrustdClient(mock_server.socket_path)


class TestTrustdClient:
    def test_ping(self, client: TrustdClient) -> None:
        result = client.ping()
        assert result["version"] == "0.1.0-test"
        assert result["uptime_seconds"] == 42
        assert result["containers_tracked"] == 1

    def test_get_container_state(self, client: TrustdClient) -> None:
        result = client.get_container_state("/docker/abc")
        assert result is not None
        assert result["cgroup_path"] == "/docker/abc"
        assert result["rtmr3"] == "aa" * 48
        assert result["initial_rtmr3"] == "bb" * 48
        assert result["measurement_count"] == 5

    def test_get_container_state_not_found(self, client: TrustdClient) -> None:
        result = client.get_container_state("/docker/nonexistent")
        assert result is None

    def test_get_td_quote(self, client: TrustdClient, mock_server: MockTrustdServer) -> None:
        mock_server.quote_response = b"quote_bytes_here"
        report_data = bytes(64)
        result = client.get_td_quote(report_data)
        assert result == b"quote_bytes_here"

    def test_get_td_quote_wrong_size(self, client: TrustdClient) -> None:
        with pytest.raises(ValueError, match="64 bytes"):
            client.get_td_quote(bytes(32))

    def test_restart_container(self, client: TrustdClient, mock_server: MockTrustdServer) -> None:
        result = client.restart_container("/docker/abc")
        assert result["cgroup_path"] == "/docker/abc"
        assert result["signaled_pids"] == 2
        assert result["force_killed_pids"] == 0
        assert mock_server.restart_calls == ["/docker/abc"]

    def test_restart_container_missing_param(self, client: TrustdClient) -> None:
        with pytest.raises(TrustdError, match="cgroup_path"):
            client.restart_container("")

    def test_get_td_quote_unavailable(self, client: TrustdClient, mock_server: MockTrustdServer) -> None:
        mock_server.quote_available = False
        with pytest.raises(TrustdError, match="unavailable"):
            client.get_td_quote(bytes(64))

    def test_connection_refused(self) -> None:
        client = TrustdClient("/tmp/nonexistent_trustd_socket_12345.sock")
        with pytest.raises(TrustdError, match="socket error"):
            client.ping()


class TestGetTrustdClient:
    def setup_method(self) -> None:
        reset_trustd_client()

    def teardown_method(self) -> None:
        reset_trustd_client()
        os.environ.pop("TEE_MCP_TRUSTD_SOCKET", None)

    def test_returns_none_when_no_socket(self) -> None:
        os.environ["TEE_MCP_TRUSTD_SOCKET"] = "/tmp/nonexistent_path_12345.sock"
        result = get_trustd_client()
        assert result is None

    def test_returns_client_when_socket_exists(self, mock_server: MockTrustdServer) -> None:
        os.environ["TEE_MCP_TRUSTD_SOCKET"] = mock_server.socket_path
        result = get_trustd_client()
        assert result is not None
        assert isinstance(result, TrustdClient)

    def test_singleton_behavior(self, mock_server: MockTrustdServer) -> None:
        os.environ["TEE_MCP_TRUSTD_SOCKET"] = mock_server.socket_path
        first = get_trustd_client()
        second = get_trustd_client()
        assert first is second

    def test_reset_clears_singleton(self, mock_server: MockTrustdServer) -> None:
        os.environ["TEE_MCP_TRUSTD_SOCKET"] = mock_server.socket_path
        first = get_trustd_client()
        reset_trustd_client()
        os.environ["TEE_MCP_TRUSTD_SOCKET"] = "/tmp/nonexistent_path_12345.sock"
        second = get_trustd_client()
        assert first is not second
        assert second is None
