"""L0 read-only log inspection and Docker container status executors."""

from __future__ import annotations

from typing import Any

from ..config import OpsPolicy, ServerPolicy, ServerProfile
from ..redactor import Redactor, truncate_output
from .ssh_exec import ExecutionError, SSHExecutor


def _get_server(
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    server_alias: str,
) -> tuple[ServerPolicy, ServerProfile]:
    spolicy = policy.servers.get(server_alias)
    sprofile = profiles.get(server_alias)
    if spolicy is None or sprofile is None:
        raise ExecutionError(f"Unknown or unpermitted server alias: '{server_alias}'")
    return spolicy, sprofile


def read_logs(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    server: str,
    log_id: str,
    lines: int = 100,
    keyword: str | None = None,
) -> dict[str, Any]:
    """Read tail lines of a whitelisted file or Docker log source, filtered & redacted locally."""
    spolicy, sprofile = _get_server(policy, profiles, server)
    lpolicy = spolicy.logs.get(log_id)
    if lpolicy is None:
        raise ExecutionError(
            f"Log source '{log_id}' is not whitelisted on server '{server}'."
        )

    clamped_lines = max(1, min(int(lines), lpolicy.max_lines))

    if policy.global_cfg.gate_mode:
        if lpolicy.source_type == "file":
            remote_tokens = ["logs-file", log_id, str(clamped_lines)]
        else:
            remote_tokens = ["logs-docker", lpolicy.container or "", str(clamped_lines)]
    else:
        if lpolicy.source_type == "file":
            remote_tokens = ["tail", "-n", str(clamped_lines), "--", lpolicy.path or ""]
        else:
            remote_tokens = [
                "docker",
                "logs",
                "--tail",
                str(clamped_lines),
                "--",
                lpolicy.container or "",
            ]

    res = ssh.run_remote(sprofile, remote_tokens)

    # Combine stdout & stderr for docker logs (many containers log to stderr)
    raw_content = res.stdout
    if lpolicy.source_type == "docker" and res.stderr:
        raw_content = f"{raw_content}\n{res.stderr}".strip() if raw_content else res.stderr

    if keyword:
        # Fixed literal substring filtering performed locally inside opsd (no remote injection/ReDoS)
        filtered = [ln for ln in raw_content.splitlines() if keyword in ln]
        raw_content = "\n".join(filtered)

    extra_literals: list[tuple[str, str]] = []
    if lpolicy.path:
        extra_literals.append((lpolicy.path, "[LOG_PATH]"))

    safe_content = truncate_output(
        redactor.redact(raw_content, active_profile=sprofile, extra_literals=extra_literals),
        policy.global_cfg.max_output_bytes,
    )
    safe_stderr = truncate_output(
        redactor.redact(res.stderr, active_profile=sprofile, extra_literals=extra_literals),
        min(8192, policy.global_cfg.max_output_bytes),
    )

    return {
        "server": server,
        "log_id": log_id,
        "lines_requested": clamped_lines,
        "keyword": keyword,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "content": safe_content,
        "stderr": safe_stderr if lpolicy.source_type == "file" else "",
    }


def docker_status(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    server: str,
    target: str | None = None,
) -> dict[str, Any]:
    """Query status/health of whitelisted Docker containers or compose services (never Env)."""
    spolicy, sprofile = _get_server(policy, profiles, server)
    dpolicy = spolicy.docker

    targets: list[str] = []
    if target is not None:
        if not dpolicy.has_target(target):
            raise ExecutionError(
                f"Docker target '{target}' is not whitelisted on server '{server}'."
            )
        targets = [target]
    else:
        targets.extend(dpolicy.allowed_containers)
        for stack_id, stack in dpolicy.allowed_compose.items():
            for svc in stack.services:
                targets.append(f"{stack_id}:{svc}")

    if not targets:
        return {"server": server, "targets": []}

    results: list[dict[str, Any]] = []
    for item in targets:
        if ":" in item:
            stack_id, svc = item.split(":", 1)
            stack = dpolicy.allowed_compose[stack_id]
            if policy.global_cfg.gate_mode:
                tokens = ["compose-status", stack_id, svc]
            else:
                tokens = [
                    "docker",
                    "compose",
                    "--project-directory",
                    stack.workdir,
                    "ps",
                    "--format",
                    "{{.Name}}\t{{.State}}\t{{.Health}}\t{{.Status}}",
                    svc,
                ]
            extra_literals = [(stack.workdir, "[COMPOSE_DIR]")]
        else:
            if policy.global_cfg.gate_mode:
                tokens = ["docker-status", item]
            else:
                tokens = [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t{{.RestartCount}}\t{{.State.StartedAt}}",
                    "--",
                    item,
                ]
            extra_literals = []

        res = ssh.run_remote(sprofile, tokens)
        results.append(
            {
                "target": item,
                "exit_code": res.exit_code,
                "status": truncate_output(
                    redactor.redact(res.stdout.strip(), active_profile=sprofile, extra_literals=extra_literals),
                    4096,
                ),
                "stderr": truncate_output(
                    redactor.redact(res.stderr.strip(), active_profile=sprofile, extra_literals=extra_literals),
                    2048,
                ),
            }
        )

    return {"server": server, "targets": results}
