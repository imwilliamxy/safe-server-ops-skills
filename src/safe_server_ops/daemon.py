"""opsd: Credential-isolated dual-socket daemon for safe-server-ops."""

from __future__ import annotations

import argparse
import grp
import os
import signal
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .audit import AuditLogger
from .config import (
    DEFAULT_DAEMON_CONFIG_PATH,
    OpsPolicy,
    ServerProfile,
    load_daemon_config,
    load_policy,
    load_server_profiles,
)
from .executors.config_ops import (
    config_apply,
    config_backups,
    config_plan,
    config_read,
    config_rollback_apply,
    config_rollback_plan,
)
from .executors.docker_ops import docker_restart_apply, docker_restart_plan
from .executors.logs import docker_status, read_logs
from .executors.rsync_ops import rsync_apply, rsync_preview
from .executors.ssh_exec import CommandRunner, ExecutionError, SSHExecutor
from .planner import PlanError, PlanStore
from .protocol import (
    DEFAULT_ADMIN_SOCKET_PATH,
    DEFAULT_SOCKET_PATH,
    ProtocolError,
    read_json_line,
    write_json_line,
)
from .redactor import Redactor, SecretPlaceholderError


class OpsEngine:
    """Core policy-enforced execution engine shared by Unix sockets (and optional MCP adapter)."""

    def __init__(
        self,
        *,
        profiles: dict[str, ServerProfile],
        policy: OpsPolicy,
        audit: AuditLogger,
        runner: CommandRunner | None = None,
        post_restart_wait: float = 2.0,
    ) -> None:
        self._profiles = profiles
        self._policy = policy
        self._audit = audit
        self._redactor = Redactor(profiles)
        self._ssh = SSHExecutor(policy.global_cfg, runner=runner)
        self._planner = PlanStore(ttl_seconds=policy.global_cfg.plan_ttl_seconds)
        self._post_restart_wait = post_restart_wait

    def capabilities(self) -> dict[str, Any]:
        """Expose logical IDs ONLY (never IPs, hosts, users, ports, keys, or remote paths)."""
        servers_out: dict[str, Any] = {}
        for alias, spol in self._policy.servers.items():
            compose_targets: list[str] = []
            for stack_id, stack in spol.docker.allowed_compose.items():
                for svc in stack.services:
                    compose_targets.append(f"{stack_id}:{svc}")
            servers_out[alias] = {
                "description": spol.description,
                "logs": {
                    lid: {"type": lp.source_type, "max_lines": lp.max_lines}
                    for lid, lp in spol.logs.items()
                },
                "docker_targets": list(spol.docker.allowed_containers) + compose_targets,
                "configs": {
                    cid: {
                        "has_validator": bool(cp.validator),
                        "has_reload": bool(cp.reload_action),
                    }
                    for cid, cp in spol.configs.items()
                },
            }

        sync_out: dict[str, Any] = {}
        for tid, tpol in self._policy.sync_targets.items():
            sync_out[tid] = {
                "server": tpol.server,
                "direction": tpol.direction,
                "description": tpol.description,
                "allow_delete": tpol.allow_delete,
                "max_files": tpol.max_files,
                "max_size_mb": tpol.max_size_mb,
            }

        return {
            "servers": servers_out,
            "sync_targets": sync_out,
            "plan_ttl_seconds": self._policy.global_cfg.plan_ttl_seconds,
        }

    def handle_client_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Handle requests arriving on the non-privileged client socket (ops.sock).

        Admin/approval methods are strictly rejected here to prevent AI self-approval.
        """
        started = time.monotonic()
        server_arg = params.get("server")
        target_arg = params.get("target") or params.get("log_id") or params.get("config_id")
        token_arg = params.get("plan_token")
        ok = False
        exit_code: int | None = None
        approved_by: str | None = None
        summary = ""

        try:
            if method.startswith("admin."):
                raise PermissionError(
                    "Approval methods are forbidden on the client socket. Use ops-approve via admin socket."
                )

            if method == "capabilities":
                data = self.capabilities()
            elif method == "logs":
                data = read_logs(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    server=str(params["server"]),
                    log_id=str(params["log_id"]),
                    lines=int(params.get("lines", 100)),
                    keyword=params.get("keyword"),
                )
                exit_code = data.get("exit_code")
            elif method == "docker.status":
                data = docker_status(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    server=str(params["server"]),
                    target=params.get("target"),
                )
            elif method == "docker.restart_plan":
                data = docker_restart_plan(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    server=str(params["server"]),
                    target=str(params["target"]),
                    reason=str(params.get("reason", "")),
                )
                token_arg = data.get("plan_token")
            elif method == "docker.restart_apply":
                data = docker_restart_apply(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    plan_token=str(params["plan_token"]),
                    post_wait_seconds=self._post_restart_wait,
                )
                server_arg = data.get("server")
                target_arg = data.get("target")
                exit_code = data.get("exit_code")
                approved_by = data.get("approved_by")
            elif method == "rsync.preview":
                data = rsync_preview(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    target_id=str(params["target"]),
                )
                server_arg = data.get("server")
                token_arg = data.get("plan_token")
                summary = str(data.get("summary", ""))
            elif method == "rsync.apply":
                data = rsync_apply(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    plan_token=str(params["plan_token"]),
                )
                server_arg = data.get("server")
                target_arg = data.get("target")
                exit_code = data.get("exit_code")
                approved_by = data.get("approved_by")
            elif method == "config.read":
                data = config_read(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    server=str(params["server"]),
                    config_id=str(params["config_id"]),
                )
            elif method == "config.plan":
                data = config_plan(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    server=str(params["server"]),
                    config_id=str(params["config_id"]),
                    draft_content=str(params["draft_content"]),
                    base_sha256=str(params["base_sha256"]),
                    reason=str(params.get("reason", "")),
                )
                token_arg = data.get("plan_token")
                summary = str(data.get("summary", ""))
            elif method == "config.apply":
                data = config_apply(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    plan_token=str(params["plan_token"]),
                )
                server_arg = data.get("server")
                target_arg = data.get("config_id")
                exit_code = data.get("exit_code")
                approved_by = data.get("approved_by")
            elif method == "config.backups":
                data = config_backups(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    server=str(params["server"]),
                    config_id=str(params["config_id"]),
                )
            elif method == "config.rollback_plan":
                data = config_rollback_plan(
                    policy=self._policy,
                    profiles=self._profiles,
                    planner=self._planner,
                    server=str(params["server"]),
                    config_id=str(params["config_id"]),
                    backup_id=str(params["backup_id"]),
                    reason=str(params.get("reason", "")),
                )
                token_arg = data.get("plan_token")
            elif method == "config.rollback_apply":
                data = config_rollback_apply(
                    policy=self._policy,
                    profiles=self._profiles,
                    ssh=self._ssh,
                    redactor=self._redactor,
                    planner=self._planner,
                    plan_token=str(params["plan_token"]),
                )
                server_arg = data.get("server")
                target_arg = data.get("config_id")
                exit_code = data.get("exit_code")
                approved_by = data.get("approved_by")
            else:
                raise ExecutionError(f"Unknown method: '{method}'")

            ok = True
            return {"ok": True, "data": data}
        except (
            KeyError,
            ValueError,
            PermissionError,
            ExecutionError,
            PlanError,
            SecretPlaceholderError,
        ) as exc:
            safe_err = self._redactor.redact(str(exc))
            summary = safe_err
            return {"ok": False, "error": safe_err}
        except Exception as exc:  # pragma: no cover - defensive fallback
            safe_err = self._redactor.redact(f"Internal opsd error: {exc}")
            summary = safe_err
            return {"ok": False, "error": safe_err}
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            self._audit.record(
                action=method,
                ok=ok,
                server=str(server_arg) if server_arg else None,
                target=str(target_arg) if target_arg else None,
                plan_token_id=str(token_arg) if token_arg else None,
                approved_by=approved_by,
                exit_code=exit_code,
                duration_ms=duration_ms,
                summary=self._redactor.redact(summary)[:512] if summary else "",
            )

    def handle_admin_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Handle approval requests arriving exclusively on admin.sock (0600, owned by sshops)."""
        started = time.monotonic()
        token_arg = params.get("plan_token")
        actor = str(params.get("actor", "human")).strip() or "human"
        ok = False
        summary = ""

        try:
            if method == "admin.list_pending":
                data = {"pending": self._planner.list_pending()}
            elif method == "admin.show_plan":
                data = self._planner.get_public(str(params["plan_token"]), include_diff=True)
            elif method == "admin.approve":
                data = self._planner.approve(str(params["plan_token"]), approved_by=actor)
                summary = f"approved by {actor}"
            elif method == "admin.reject":
                data = self._planner.reject(str(params["plan_token"]), rejected_by=actor)
                summary = f"rejected by {actor}"
            else:
                raise ExecutionError(f"Unknown admin method: '{method}'")

            ok = True
            return {"ok": True, "data": data}
        except (KeyError, ValueError, ExecutionError, PlanError) as exc:
            safe_err = self._redactor.redact(str(exc))
            summary = safe_err
            return {"ok": False, "error": safe_err}
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            self._audit.record(
                action=method,
                ok=ok,
                plan_token_id=str(token_arg) if token_arg else None,
                approved_by=actor if method in {"admin.approve", "admin.reject"} else None,
                duration_ms=duration_ms,
                summary=summary[:512],
            )


class _UnixRPCHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _DualSocketServer = self.server  # type: ignore[assignment]
        try:
            req = read_json_line(self.request)
            method = str(req.get("method", ""))
            params = req.get("params") or {}
            if not isinstance(params, dict):
                raise ProtocolError("'params' must be a JSON object.")
            if server.is_admin:
                resp = server.engine.handle_admin_request(method, params)
            else:
                resp = server.engine.handle_client_request(method, params)
        except ProtocolError as exc:
            resp = {"ok": False, "error": str(exc)}
        try:
            write_json_line(self.request, resp)
        except OSError:
            pass


class _DualSocketServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path,
        engine: OpsEngine,
        *,
        is_admin: bool,
        mode: int,
        group_name: str | None = None,
    ) -> None:
        self.engine = engine
        self.is_admin = is_admin
        self.socket_path = socket_path

        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists() or socket_path.is_symlink():
            socket_path.unlink()

        super().__init__(str(socket_path), _UnixRPCHandler)
        os.chmod(socket_path, mode)
        if group_name:
            gid = grp.getgrnam(group_name).gr_gid
            os.chown(socket_path, -1, gid)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            try:
                self.socket_path.unlink(missing_ok=True)
            except OSError:
                pass


class OpsDaemon:
    """Manages both ops.sock (client) and admin.sock (human approval) servers."""

    def __init__(
        self,
        *,
        engine: OpsEngine,
        client_socket: Path,
        admin_socket: Path,
        client_mode: int = 0o660,
        socket_group: str | None = None,
    ) -> None:
        self._client_srv = _DualSocketServer(
            client_socket,
            engine,
            is_admin=False,
            mode=client_mode,
            group_name=socket_group,
        )
        self._admin_srv = _DualSocketServer(
            admin_socket,
            engine,
            is_admin=True,
            mode=0o600,
            group_name=None,
        )
        self._threads: list[threading.Thread] = []

    def start_background(self) -> None:
        for name, srv in (("opsd-client", self._client_srv), ("opsd-admin", self._admin_srv)):
            t = threading.Thread(target=srv.serve_forever, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        for srv in (self._client_srv, self._admin_srv):
            srv.shutdown()
            srv.server_close()
        for t in self._threads:
            t.join(timeout=2.0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="opsd",
        description="Credential-isolated production operations daemon.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to opsd.conf (defaults to ~/.local/config/opsd/opsd.conf if present)",
    )
    parser.add_argument("--servers-env", default=None, help="Path to .ssh-servers.env (overrides opsd.conf)")
    parser.add_argument("--policy", default=None, help="Path to policy.yaml (overrides opsd.conf)")
    parser.add_argument("--socket", default=None, help="Client Unix socket path")
    parser.add_argument(
        "--admin-socket", default=None, help="Admin approval Unix socket path (0600)"
    )
    parser.add_argument(
        "--audit-log", default=None, help="Append-only JSONL audit log path"
    )
    parser.add_argument(
        "--socket-group", default=None, help="Optional OS group for client socket (chmod 660)"
    )
    parser.add_argument(
        "--check-ownership",
        action="store_true",
        default=None,
        help="Require config files to be owned by the current daemon user.",
    )
    parser.add_argument(
        "--allow-missing-keys",
        action="store_true",
        help="Skip key existence checks at startup (useful for dry-run / testing).",
    )
    args = parser.parse_args(argv)

    os.umask(0o077)

    conf_path: Path | None = None
    if args.config:
        conf_path = Path(args.config).expanduser()
    elif args.servers_env is None and args.policy is None:
        default_conf = DEFAULT_DAEMON_CONFIG_PATH.expanduser()
        if default_conf.exists():
            conf_path = default_conf

    daemon_cfg = (
        load_daemon_config(conf_path, check_ownership=bool(args.check_ownership))
        if conf_path is not None
        else None
    )

    servers_env = Path(args.servers_env).expanduser() if args.servers_env else (daemon_cfg.servers_env if daemon_cfg else None)
    policy_path = Path(args.policy).expanduser() if args.policy else (daemon_cfg.policy if daemon_cfg else None)
    if servers_env is None or policy_path is None:
        parser.error(
            "Either --config (or ~/.local/config/opsd/opsd.conf) OR both --servers-env and --policy must be provided."
        )

    client_socket = Path(args.socket).expanduser() if args.socket else (
        daemon_cfg.socket if daemon_cfg else Path(DEFAULT_SOCKET_PATH)
    )
    admin_socket = Path(args.admin_socket).expanduser() if args.admin_socket else (
        daemon_cfg.admin_socket if daemon_cfg else Path(DEFAULT_ADMIN_SOCKET_PATH)
    )
    audit_log = Path(args.audit_log).expanduser() if args.audit_log else (
        daemon_cfg.audit_log if daemon_cfg else Path("~/.local/state/opsd/audit.jsonl").expanduser()
    )
    socket_group = args.socket_group if args.socket_group is not None else (
        daemon_cfg.socket_group if daemon_cfg else None
    )
    check_ownership = args.check_ownership if args.check_ownership is not None else (
        daemon_cfg.check_ownership if daemon_cfg else False
    )

    profiles = load_server_profiles(
        servers_env,
        check_ownership=check_ownership,
        require_keys_exist=not args.allow_missing_keys,
    )
    policy = load_policy(
        policy_path,
        known_servers=set(profiles.keys()),
        check_ownership=check_ownership,
    )
    audit = AuditLogger(audit_log)
    engine = OpsEngine(profiles=profiles, policy=policy, audit=audit)

    client_mode = 0o660 if socket_group else 0o600
    daemon = OpsDaemon(
        engine=engine,
        client_socket=client_socket,
        admin_socket=admin_socket,
        client_mode=client_mode,
        socket_group=socket_group,
    )

    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    daemon.start_background()
    print(
        f"opsd listening on client={client_socket} admin={admin_socket}",
        file=sys.stderr,
        flush=True,
    )
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=0.5)
    finally:
        daemon.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
