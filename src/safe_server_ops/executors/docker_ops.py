"""L1 two-phase Docker container / Compose service restart executor."""

from __future__ import annotations

import time
from typing import Any

from ..config import OpsPolicy, ServerProfile
from ..planner import PlanStore
from ..redactor import Redactor, truncate_output
from .logs import docker_status
from .ssh_exec import ExecutionError, SSHExecutor


def docker_restart_plan(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    server: str,
    target: str,
    reason: str,
) -> dict[str, Any]:
    """Validate Docker target whitelist, capture pre-restart status, and issue a Plan Token."""
    spolicy = policy.servers.get(server)
    if spolicy is None or server not in profiles:
        raise ExecutionError(f"Unknown or unpermitted server alias: '{server}'")
    if not spolicy.docker.has_target(target):
        raise ExecutionError(
            f"Docker target '{target}' is not whitelisted on server '{server}'."
        )
    clean_reason = reason.strip()
    if not clean_reason:
        raise ExecutionError("A non-empty --reason is required for Docker restarts.")

    current = docker_status(
        policy=policy,
        profiles=profiles,
        ssh=ssh,
        redactor=redactor,
        server=server,
        target=target,
    )
    current_line = current["targets"][0]["status"] if current["targets"] else "unknown"
    summary = f"Restart Docker target '{target}' on '{server}' (current: {current_line or 'unknown'})"

    plan = planner.create(
        kind="docker_restart",
        server=server,
        target=target,
        reason=clean_reason,
        summary=summary,
        payload={"server": server, "target": target},
    )
    result = plan.to_public_dict(include_diff=False)
    result["current_status"] = current["targets"]
    return result


def docker_restart_apply(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    plan_token: str,
    post_wait_seconds: float = 2.0,
) -> dict[str, Any]:
    """Consume an APPROVED Docker restart plan, execute restart, and return post-health + logs."""
    plan = planner.consume_approved(plan_token, expected_kind="docker_restart")
    server = str(plan.payload["server"])
    target = str(plan.payload["target"])
    spolicy = policy.servers[server]
    sprofile = profiles[server]

    extra_literals: list[tuple[str, str]] = []
    if ":" in target:
        stack_id, svc = target.split(":", 1)
        stack = spolicy.docker.allowed_compose[stack_id]
        extra_literals.append((stack.workdir, "[COMPOSE_DIR]"))
        if policy.global_cfg.gate_mode:
            restart_tokens = ["compose-restart", stack_id, svc]
            logs_tokens = ["compose-logs", stack_id, svc, "30"]
        else:
            restart_tokens = [
                "docker",
                "compose",
                "--project-directory",
                stack.workdir,
                "restart",
                svc,
            ]
            logs_tokens = [
                "docker",
                "compose",
                "--project-directory",
                stack.workdir,
                "logs",
                "--tail",
                "30",
                svc,
            ]
    else:
        if policy.global_cfg.gate_mode:
            restart_tokens = ["docker-restart", target]
            logs_tokens = ["logs-docker", target, "30"]
        else:
            restart_tokens = ["docker", "restart", "--", target]
            logs_tokens = ["docker", "logs", "--tail", "30", "--", target]

    restart_res = ssh.run_remote(sprofile, restart_tokens, timeout=max(30, policy.global_cfg.default_timeout_seconds))

    if restart_res.exit_code == 0 and post_wait_seconds > 0:
        time.sleep(post_wait_seconds)

    post_status = docker_status(
        policy=policy,
        profiles=profiles,
        ssh=ssh,
        redactor=redactor,
        server=server,
        target=target,
    )
    startup_res = ssh.run_remote(sprofile, logs_tokens)
    startup_raw = "\n".join(part for part in (startup_res.stdout.strip(), startup_res.stderr.strip()) if part)

    return {
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "target": target,
        "exit_code": restart_res.exit_code,
        "stdout": truncate_output(
            redactor.redact(restart_res.stdout.strip(), active_profile=sprofile, extra_literals=extra_literals),
            4096,
        ),
        "stderr": truncate_output(
            redactor.redact(restart_res.stderr.strip(), active_profile=sprofile, extra_literals=extra_literals),
            4096,
        ),
        "post_status": post_status["targets"],
        "startup_logs": truncate_output(
            redactor.redact(startup_raw, active_profile=sprofile, extra_literals=extra_literals),
            min(16384, policy.global_cfg.max_output_bytes),
        ),
    }
