"""Unix Domain Socket JSON-RPC framing for opsctl / ops-approve / opsd."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

DEFAULT_SOCKET_PATH = "/var/run/sshops/ops.sock"
DEFAULT_ADMIN_SOCKET_PATH = "/var/run/sshops/admin.sock"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024  # 4 MiB


class ProtocolError(RuntimeError):
    """Raised on socket or message framing errors."""


def resolve_socket_path(explicit: str | None = None) -> Path:
    return Path(explicit or os.environ.get("OPS_SOCKET") or DEFAULT_SOCKET_PATH)


def resolve_admin_socket_path(explicit: str | None = None) -> Path:
    return Path(explicit or os.environ.get("OPS_ADMIN_SOCKET") or DEFAULT_ADMIN_SOCKET_PATH)


def read_json_line(conn: socket.socket, max_bytes: int = MAX_MESSAGE_BYTES) -> dict[str, Any]:
    """Read a single newline-delimited JSON object from a socket."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ProtocolError(f"Message exceeds limit of {max_bytes} bytes.")
        nl_idx = chunk.find(b"\n")
        if nl_idx != -1:
            chunks.append(chunk[:nl_idx])
            break
        chunks.append(chunk)
    raw = b"".join(chunks).strip()
    if not raw:
        raise ProtocolError("Empty message received.")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"Invalid JSON payload: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("JSON payload must be an object.")
    return obj


def write_json_line(conn: socket.socket, payload: dict[str, Any]) -> None:
    """Serialize a dict as a single UTF-8 JSON line and send it."""
    encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Response exceeds maximum message size.")
    conn.sendall(encoded)


def send_request(
    socket_path: Path | str,
    method: str,
    params: dict[str, Any] | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Connect to a Unix Domain Socket, send a request, and return the response dict."""
    path_str = str(socket_path)
    if not os.path.exists(path_str):
        raise ProtocolError(
            f"Socket not found at '{path_str}'. Is opsd running?"
        )
    req = {"method": method, "params": params or {}}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect(path_str)
        except PermissionError as exc:
            raise ProtocolError(
                f"Permission denied connecting to '{path_str}'."
            ) from exc
        except OSError as exc:
            raise ProtocolError(
                f"Failed to connect to '{path_str}': {exc}"
            ) from exc
        write_json_line(sock, req)
        return read_json_line(sock)
