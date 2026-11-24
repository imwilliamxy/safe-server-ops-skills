"""Optional thin MCP adapter forwarding tool calls to the isolated opsd Unix socket.

Install optional dependency: pip install '.[mcp]'
This adapter holds ZERO credentials and simply proxies to ops.sock.
"""

from __future__ import annotations

import json
from typing import Any

from ..protocol import resolve_socket_path, send_request

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - optional dependency
    raise SystemExit(
        "Optional dependency 'mcp' is not installed. Run: pip install '.[mcp]'"
    ) from exc

mcp = FastMCP("safe-server-ops")


def _forward(method: str, params: dict[str, Any] | None = None) -> str:
    resp = send_request(resolve_socket_path(), method, params or {})
    return json.dumps(resp, ensure_ascii=False, indent=2)


@mcp.tool()
def list_capabilities() -> str:
    """List allowed server aliases, logs, Docker targets, configs, and sync targets."""
    return _forward("capabilities")


@mcp.tool()
def read_logs(server: str, log_id: str, lines: int = 100, keyword: str | None = None) -> str:
    """Read tail lines from a whitelisted log source (redacted)."""
    return _forward("logs", {"server": server, "log_id": log_id, "lines": lines, "keyword": keyword})


@mcp.tool()
def docker_status(server: str, target: str | None = None) -> str:
    """Inspect status/health of whitelisted Docker targets (never returns Env)."""
    return _forward("docker.status", {"server": server, "target": target})


@mcp.tool()
def docker_restart_plan(server: str, target: str, reason: str) -> str:
    """Create a Docker restart plan requiring human approval via ops-approve."""
    return _forward("docker.restart_plan", {"server": server, "target": target, "reason": reason})


@mcp.tool()
def docker_restart_apply(plan_token: str) -> str:
    """Apply a human-approved Docker restart plan."""
    return _forward("docker.restart_apply", {"plan_token": plan_token})


@mcp.tool()
def rsync_preview(target: str) -> str:
    """Dry-run rsync preview with symlink check and manifest hash."""
    return _forward("rsync.preview", {"target": target})


@mcp.tool()
def rsync_apply(plan_token: str) -> str:
    """Apply a human-approved rsync plan after TOCTOU verification."""
    return _forward("rsync.apply", {"plan_token": plan_token})


@mcp.tool()
def config_read(server: str, config_id: str) -> str:
    """Read a whitelisted config file with secrets masked."""
    return _forward("config.read", {"server": server, "config_id": config_id})


@mcp.tool()
def config_plan(
    server: str,
    config_id: str,
    draft_content: str,
    base_sha256: str,
    reason: str,
) -> str:
    """Validate draft config and generate redacted Unified Diff + plan_token."""
    return _forward(
        "config.plan",
        {
            "server": server,
            "config_id": config_id,
            "draft_content": draft_content,
            "base_sha256": base_sha256,
            "reason": reason,
        },
    )


@mcp.tool()
def config_apply(plan_token: str) -> str:
    """Apply a human-approved config change with automatic backup and rollback on reload failure."""
    return _forward("config.apply", {"plan_token": plan_token})


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
