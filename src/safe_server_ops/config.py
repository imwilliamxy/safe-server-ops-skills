"""Strict literal parser for .ssh-servers.env and YAML parser for policy.yaml."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9:][A-Za-z0-9_.:%-]*$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*\$?$")
SECTION_RE = re.compile(r"^\[([a-z][a-z0-9_-]{0,31})\]\s*$")


class ConfigError(ValueError):
    """Raised when server profiles or policy validation fails."""


@dataclass(frozen=True)
class ServerProfile:
    alias: str
    host: str
    user: str
    port: int
    key_file: Path
    sync_key_file: Path | None = None

    def effective_sync_key(self) -> Path:
        return self.sync_key_file or self.key_file


@dataclass(frozen=True)
class LogSourcePolicy:
    log_id: str
    source_type: str  # "file" | "docker"
    path: str | None = None
    container: str | None = None
    max_lines: int = 500


@dataclass(frozen=True)
class ComposeStackPolicy:
    stack_id: str
    workdir: str
    services: tuple[str, ...]


@dataclass(frozen=True)
class DockerPolicy:
    allowed_containers: tuple[str, ...] = ()
    allowed_compose: dict[str, ComposeStackPolicy] = field(default_factory=dict)

    def has_target(self, target: str) -> bool:
        if target in self.allowed_containers:
            return True
        if ":" in target:
            stack_id, service = target.split(":", 1)
            stack = self.allowed_compose.get(stack_id)
            return stack is not None and service in stack.services
        return False


@dataclass(frozen=True)
class ConfigFilePolicy:
    config_id: str
    path: str
    backup_dir: str
    validator: str | None = None
    reload_action: str | None = None
    redact_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServerPolicy:
    alias: str
    description: str = ""
    logs: dict[str, LogSourcePolicy] = field(default_factory=dict)
    docker: DockerPolicy = field(default_factory=DockerPolicy)
    configs: dict[str, ConfigFilePolicy] = field(default_factory=dict)


@dataclass(frozen=True)
class SyncTargetPolicy:
    target_id: str
    server: str
    direction: str  # "push" | "pull"
    local_base: Path
    remote_base: str
    description: str = ""
    use_rrsync: bool = False
    allow_delete: bool = False
    max_delete_files: int = 20
    max_files: int = 300
    max_size_mb: int = 50
    exclude_file: Path | None = None


@dataclass(frozen=True)
class GlobalPolicy:
    plan_ttl_seconds: int = 180
    max_output_bytes: int = 65536
    default_timeout_seconds: int = 20
    gate_mode: bool = True
    strict_host_key_checking: str = "yes"
    known_hosts_file: Path | None = None
    global_excludes: tuple[str, ...] = (
        ".git/",
        ".env",
        ".env.*",
        "*.pem",
        "*.key",
        "node_modules/",
        "wp-config.php",
    )


@dataclass(frozen=True)
class OpsPolicy:
    global_cfg: GlobalPolicy
    servers: dict[str, ServerPolicy]
    sync_targets: dict[str, SyncTargetPolicy]


def _ensure_safe_regular_file(path: Path, label: str, check_ownership: bool = False) -> None:
    if path.is_symlink():
        raise ConfigError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise ConfigError(f"{label} does not exist or is not a regular file: {path}")
    if check_ownership:
        st = path.stat()
        if st.st_uid != os.getuid():
            raise ConfigError(f"{label} must be owned by the current user.")


def _resolve_key_path(raw: str, base_dir: Path) -> Path:
    if raw.startswith("~/"):
        return Path.home() / raw[2:]
    p = Path(raw)
    if p.is_absolute():
        return p
    return base_dir / p


def _strip_literal_quotes(value: str) -> str:
    if len(value) >= 2 and (
        (value[0] == '"' and value[-1] == '"')
        or (value[0] == "'" and value[-1] == "'")
    ):
        return value[1:-1]
    return value


def load_server_profiles(
    env_path: Path | str,
    *,
    check_ownership: bool = False,
    require_keys_exist: bool = True,
) -> dict[str, ServerProfile]:
    """Parse .ssh-servers.env strictly as literal data (never shell-evaluated)."""
    path = Path(env_path)
    _ensure_safe_regular_file(path, "Server profiles file", check_ownership=check_ownership)

    raw_profiles: dict[str, dict[str, str]] = {}
    current_alias: str | None = None

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.rstrip("\r").lstrip()
        if not line or line.startswith("#"):
            continue
        sec_match = SECTION_RE.match(line)
        if sec_match:
            alias = sec_match.group(1)
            if alias in raw_profiles:
                raise ConfigError(f"Duplicate server alias '{alias}' at line {lineno}.")
            raw_profiles[alias] = {}
            current_alias = alias
            continue
        if current_alias is None or "=" not in line:
            raise ConfigError(f"Malformed line {lineno} in server profiles file.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_literal_quotes(value.strip())
        if key not in {"HOST", "USER", "PORT", "KEY_FILE", "SYNC_KEY_FILE"}:
            raise ConfigError(f"Unsupported field '{key}' at line {lineno}.")
        if key in raw_profiles[current_alias]:
            raise ConfigError(f"Duplicate field '{key}' in [{current_alias}] at line {lineno}.")
        raw_profiles[current_alias][key] = value

    profiles: dict[str, ServerProfile] = {}
    base_dir = path.parent
    for alias, fields in raw_profiles.items():
        for req in ("HOST", "USER", "PORT", "KEY_FILE"):
            if req not in fields or not fields[req]:
                raise ConfigError(f"Server [{alias}] is missing required field '{req}'.")
        host = fields["HOST"]
        user = fields["USER"]
        port_raw = fields["PORT"]
        if not HOST_RE.match(host):
            raise ConfigError(f"Invalid HOST format in [{alias}].")
        if not USER_RE.match(user):
            raise ConfigError(f"Invalid USER format in [{alias}].")
        if not port_raw.isdigit():
            raise ConfigError(f"Invalid PORT in [{alias}].")
        port = int(port_raw, 10)
        if not (1 <= port <= 65535):
            raise ConfigError(f"PORT out of range (1-65535) in [{alias}].")

        key_path = _resolve_key_path(fields["KEY_FILE"], base_dir)
        sync_key_path = (
            _resolve_key_path(fields["SYNC_KEY_FILE"], base_dir)
            if fields.get("SYNC_KEY_FILE")
            else None
        )
        if require_keys_exist:
            if not (key_path.is_file() and key_path.stat().st_size > 0):
                raise ConfigError(f"KEY_FILE for [{alias}] does not exist or is empty.")
            if sync_key_path is not None and not (
                sync_key_path.is_file() and sync_key_path.stat().st_size > 0
            ):
                raise ConfigError(f"SYNC_KEY_FILE for [{alias}] does not exist or is empty.")

        profiles[alias] = ServerProfile(
            alias=alias,
            host=host,
            user=user,
            port=port,
            key_file=key_path,
            sync_key_file=sync_key_path,
        )
    return profiles


def _validate_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.match(value):
        raise ConfigError(f"Invalid {label}: {value!r}")
    return value


def _validate_abs_posix(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or ".." in Path(value).parts:
        raise ConfigError(f"{label} must be a normalized absolute path without '..': {value!r}")
    return value


def load_policy(
    policy_path: Path | str,
    *,
    known_servers: set[str] | None = None,
    check_ownership: bool = False,
) -> OpsPolicy:
    """Load and validate policy.yaml using yaml.safe_load."""
    path = Path(policy_path)
    _ensure_safe_regular_file(path, "Policy file", check_ownership=check_ownership)

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("Policy root must be a YAML mapping.")

    raw_global = data.get("global") or {}
    if not isinstance(raw_global, dict):
        raise ConfigError("'global' must be a mapping.")

    shkc = str(raw_global.get("strict_host_key_checking", "yes"))
    if shkc not in {"yes", "accept-new"}:
        raise ConfigError(
            "global.strict_host_key_checking must be 'yes' or 'accept-new' (never 'no')."
        )

    known_hosts_raw = raw_global.get("known_hosts_file")
    known_hosts = Path(str(known_hosts_raw)).expanduser() if known_hosts_raw else None

    default_excludes = GlobalPolicy.global_excludes
    raw_excludes = raw_global.get("global_excludes")
    if raw_excludes is not None:
        if not isinstance(raw_excludes, list) or not all(isinstance(x, str) for x in raw_excludes):
            raise ConfigError("global.global_excludes must be a list of strings.")
        global_excludes = tuple(raw_excludes)
    else:
        global_excludes = default_excludes

    global_cfg = GlobalPolicy(
        plan_ttl_seconds=int(raw_global.get("plan_ttl_seconds", 180)),
        max_output_bytes=int(raw_global.get("max_output_bytes", 65536)),
        default_timeout_seconds=int(raw_global.get("default_timeout_seconds", 20)),
        gate_mode=bool(raw_global.get("gate_mode", True)),
        strict_host_key_checking=shkc,
        known_hosts_file=known_hosts,
        global_excludes=global_excludes,
    )
    if global_cfg.plan_ttl_seconds < 10 or global_cfg.plan_ttl_seconds > 3600:
        raise ConfigError("global.plan_ttl_seconds must be between 10 and 3600.")
    if global_cfg.max_output_bytes < 1024:
        raise ConfigError("global.max_output_bytes must be >= 1024.")

    raw_servers = data.get("servers") or {}
    if not isinstance(raw_servers, dict):
        raise ConfigError("'servers' must be a mapping.")

    servers: dict[str, ServerPolicy] = {}
    for alias, sdata in raw_servers.items():
        if not isinstance(alias, str) or not ALIAS_RE.match(alias):
            raise ConfigError(f"Invalid server alias in policy: {alias!r}")
        if known_servers is not None and alias not in known_servers:
            raise ConfigError(f"Policy references unknown server alias '{alias}'.")
        if not isinstance(sdata, dict):
            raise ConfigError(f"Server policy for '{alias}' must be a mapping.")

        logs: dict[str, LogSourcePolicy] = {}
        for log_id, ldata in (sdata.get("logs") or {}).items():
            _validate_id(log_id, "log_id")
            if not isinstance(ldata, dict):
                raise ConfigError(f"Log policy '{log_id}' must be a mapping.")
            ltype = str(ldata.get("type", ""))
            max_lines = int(ldata.get("max_lines", 500))
            if max_lines < 1 or max_lines > 5000:
                raise ConfigError(f"max_lines out of range for log '{log_id}'.")
            if ltype == "file":
                lpath = _validate_abs_posix(str(ldata.get("path", "")), f"logs.{log_id}.path")
                logs[log_id] = LogSourcePolicy(
                    log_id=log_id, source_type="file", path=lpath, max_lines=max_lines
                )
            elif ltype == "docker":
                cname = _validate_id(str(ldata.get("container", "")), f"logs.{log_id}.container")
                logs[log_id] = LogSourcePolicy(
                    log_id=log_id, source_type="docker", container=cname, max_lines=max_lines
                )
            else:
                raise ConfigError(f"Unsupported log type '{ltype}' for '{log_id}'.")

        raw_docker = sdata.get("docker") or {}
        if not isinstance(raw_docker, dict):
            raise ConfigError(f"docker policy for '{alias}' must be a mapping.")
        allowed_containers = tuple(
            _validate_id(c, "docker container")
            for c in (raw_docker.get("allowed_containers") or [])
        )
        allowed_compose: dict[str, ComposeStackPolicy] = {}
        for stack_id, cdata in (raw_docker.get("allowed_compose") or {}).items():
            _validate_id(stack_id, "compose stack_id")
            if not isinstance(cdata, dict):
                raise ConfigError(f"compose stack '{stack_id}' must be a mapping.")
            workdir = _validate_abs_posix(str(cdata.get("workdir", "")), f"compose.{stack_id}.workdir")
            services = tuple(
                _validate_id(svc, "compose service") for svc in (cdata.get("services") or [])
            )
            if not services:
                raise ConfigError(f"compose stack '{stack_id}' must declare at least one service.")
            allowed_compose[stack_id] = ComposeStackPolicy(
                stack_id=stack_id, workdir=workdir, services=services
            )
        docker_policy = DockerPolicy(
            allowed_containers=allowed_containers,
            allowed_compose=allowed_compose,
        )

        configs: dict[str, ConfigFilePolicy] = {}
        for cfg_id, cfgdata in (sdata.get("configs") or {}).items():
            _validate_id(cfg_id, "config_id")
            if not isinstance(cfgdata, dict):
                raise ConfigError(f"config policy '{cfg_id}' must be a mapping.")
            cpath = _validate_abs_posix(str(cfgdata.get("path", "")), f"configs.{cfg_id}.path")
            bdir = _validate_abs_posix(
                str(cfgdata.get("backup_dir", "")), f"configs.{cfg_id}.backup_dir"
            )
            validator = cfgdata.get("validator")
            if validator is not None:
                validator = _validate_id(str(validator), f"configs.{cfg_id}.validator")
            reload_action = cfgdata.get("reload_action")
            if reload_action is not None:
                reload_action = _validate_id(str(reload_action), f"configs.{cfg_id}.reload_action")
            raw_patterns = cfgdata.get("redact_patterns") or []
            if not isinstance(raw_patterns, list):
                raise ConfigError(f"configs.{cfg_id}.redact_patterns must be a list.")
            compiled_check = tuple(str(p) for p in raw_patterns)
            for pat in compiled_check:
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise ConfigError(
                        f"Invalid regex in configs.{cfg_id}.redact_patterns: {exc}"
                    ) from exc
            configs[cfg_id] = ConfigFilePolicy(
                config_id=cfg_id,
                path=cpath,
                backup_dir=bdir,
                validator=validator,
                reload_action=reload_action,
                redact_patterns=compiled_check,
            )

        servers[alias] = ServerPolicy(
            alias=alias,
            description=str(sdata.get("description", "")),
            logs=logs,
            docker=docker_policy,
            configs=configs,
        )

    raw_sync = data.get("sync_targets") or {}
    if not isinstance(raw_sync, dict):
        raise ConfigError("'sync_targets' must be a mapping.")

    sync_targets: dict[str, SyncTargetPolicy] = {}
    for target_id, tdata in raw_sync.items():
        _validate_id(target_id, "sync_target")
        if not isinstance(tdata, dict):
            raise ConfigError(f"sync_target '{target_id}' must be a mapping.")
        srv = str(tdata.get("server", ""))
        if not ALIAS_RE.match(srv):
            raise ConfigError(f"Invalid server alias '{srv}' in sync_target '{target_id}'.")
        if known_servers is not None and srv not in known_servers:
            raise ConfigError(f"sync_target '{target_id}' references unknown server '{srv}'.")
        direction = str(tdata.get("direction", "push"))
        if direction not in {"push", "pull"}:
            raise ConfigError(f"sync_target '{target_id}' direction must be 'push' or 'pull'.")
        local_base_raw = str(tdata.get("local_base", ""))
        if not local_base_raw:
            raise ConfigError(f"sync_target '{target_id}' missing local_base.")
        local_base = Path(local_base_raw).expanduser().resolve()
        remote_base = _validate_abs_posix(
            str(tdata.get("remote_base", "")), f"sync_targets.{target_id}.remote_base"
        )
        exclude_raw = tdata.get("exclude_file")
        exclude_file = Path(str(exclude_raw)).expanduser() if exclude_raw else None
        sync_targets[target_id] = SyncTargetPolicy(
            target_id=target_id,
            server=srv,
            direction=direction,
            local_base=local_base,
            remote_base=remote_base,
            description=str(tdata.get("description", "")),
            use_rrsync=bool(tdata.get("use_rrsync", False)),
            allow_delete=bool(tdata.get("allow_delete", False)),
            max_delete_files=int(tdata.get("max_delete_files", 20)),
            max_files=int(tdata.get("max_files", 300)),
            max_size_mb=int(tdata.get("max_size_mb", 50)),
            exclude_file=exclude_file,
        )

    return OpsPolicy(global_cfg=global_cfg, servers=servers, sync_targets=sync_targets)
