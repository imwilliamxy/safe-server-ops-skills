"""L2 two-phase production config read, validate, plan/diff, atomic apply, and rollback."""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from ..config import ConfigFilePolicy, OpsPolicy, ServerProfile
from ..planner import PlanStore
from ..redactor import (
    Redactor,
    mask_config_secrets,
    truncate_output,
    unmask_config_secrets,
)
from .ssh_exec import ExecutionError, SSHExecutor


def _get_config_policy(
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    server: str,
    config_id: str,
) -> tuple[ConfigFilePolicy, ServerProfile]:
    spolicy = policy.servers.get(server)
    profile = profiles.get(server)
    if spolicy is None or profile is None:
        raise ExecutionError(f"Unknown or unpermitted server alias: '{server}'")
    cfg = spolicy.configs.get(config_id)
    if cfg is None:
        raise ExecutionError(
            f"Config '{config_id}' is not whitelisted on server '{server}'."
        )
    return cfg, profile


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fetch_remote_raw_config(
    *,
    policy: OpsPolicy,
    ssh: SSHExecutor,
    profile: ServerProfile,
    cfg: ConfigFilePolicy,
    redactor: Redactor,
) -> str:
    if policy.global_cfg.gate_mode:
        tokens = ["config-read", cfg.config_id]
    else:
        tokens = ["cat", "--", cfg.path]
    res = ssh.run_remote(profile, tokens)
    if res.exit_code != 0:
        err = redactor.redact(
            res.stderr.strip(),
            active_profile=profile,
            extra_literals=[(cfg.path, "[CONFIG_PATH]")],
        )
        raise ExecutionError(f"Failed to read remote config '{cfg.config_id}': {err}")
    return res.stdout


def _local_syntax_check(path_str: str, candidate_raw: str) -> None:
    suffix = Path(path_str).suffix.lower()
    if suffix == ".json":
        try:
            json.loads(candidate_raw)
        except json.JSONDecodeError as exc:
            raise ExecutionError(f"Local JSON syntax check failed: {exc}") from exc
    elif suffix in {".yaml", ".yml"}:
        try:
            yaml.safe_load(candidate_raw)
        except yaml.YAMLError as exc:
            raise ExecutionError(f"Local YAML syntax check failed: {exc}") from exc


def config_read(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    server: str,
    config_id: str,
) -> dict[str, Any]:
    """Read a whitelisted config file, masking secret patterns into placeholders."""
    cfg, profile = _get_config_policy(policy, profiles, server, config_id)
    raw = _fetch_remote_raw_config(
        policy=policy, ssh=ssh, profile=profile, cfg=cfg, redactor=redactor
    )
    base_sha = _sha256_text(raw)
    masked, secret_map = mask_config_secrets(raw, cfg.redact_patterns)
    safe_content = truncate_output(
        redactor.redact(
            masked,
            active_profile=profile,
            extra_literals=[(cfg.path, "[CONFIG_PATH]")],
        ),
        policy.global_cfg.max_output_bytes,
    )
    return {
        "server": server,
        "config_id": config_id,
        "base_sha256": base_sha,
        "redacted_secret_count": len(secret_map),
        "content": safe_content,
    }


def config_plan(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    server: str,
    config_id: str,
    draft_content: str,
    base_sha256: str,
    reason: str,
) -> dict[str, Any]:
    """Validate draft config (optimistic lock + secret restoration + syntax check) & issue Plan Token."""
    cfg, profile = _get_config_policy(policy, profiles, server, config_id)
    clean_reason = reason.strip()
    if not clean_reason:
        raise ExecutionError("A non-empty --reason is required for config changes.")

    remote_raw = _fetch_remote_raw_config(
        policy=policy, ssh=ssh, profile=profile, cfg=cfg, redactor=redactor
    )
    current_sha = _sha256_text(remote_raw)
    if current_sha != base_sha256:
        raise ExecutionError(
            f"Optimistic lock failed: remote config changed (expected base_sha256={base_sha256}, current={current_sha}). Re-read the config first."
        )

    remote_masked, secret_map = mask_config_secrets(remote_raw, cfg.redact_patterns)
    candidate_raw = unmask_config_secrets(draft_content, secret_map)
    new_sha = _sha256_text(candidate_raw)
    if new_sha == current_sha:
        raise ExecutionError("Draft config is identical to the current remote config; no change to plan.")

    # 1. Local structural syntax check (JSON/YAML)
    _local_syntax_check(cfg.path, candidate_raw)

    # 2. Remote validator check (e.g. nginx -t)
    validation_output = ""
    if cfg.validator:
        if not policy.global_cfg.gate_mode:
            raise ExecutionError(
                "Config validation and writing require gate_mode=true with remote ai-ops-gate."
            )
        vres = ssh.run_remote(
            profile,
            ["config-validate", cfg.config_id, cfg.validator],
            stdin_data=candidate_raw,
        )
        validation_output = redactor.redact(
            "\n".join(p for p in (vres.stdout.strip(), vres.stderr.strip()) if p),
            active_profile=profile,
            extra_literals=[(cfg.path, "[CONFIG_PATH]")],
        )
        if vres.exit_code != 0:
            raise ExecutionError(
                f"Remote validator '{cfg.validator}' failed (exit_code={vres.exit_code}): {validation_output}"
            )

    # 3. Generate redacted unified diff (comparing masked versions so secrets never appear in diff)
    diff_lines = list(
        difflib.unified_diff(
            remote_masked.splitlines(keepends=True),
            draft_content.splitlines(keepends=True),
            fromfile=f"{config_id} (current)",
            tofile=f"{config_id} (proposed)",
        )
    )
    safe_diff = truncate_output(
        redactor.redact(
            "".join(diff_lines),
            active_profile=profile,
            extra_literals=[(cfg.path, "[CONFIG_PATH]")],
        ),
        min(32768, policy.global_cfg.max_output_bytes),
    )

    summary = f"Update config '{config_id}' on '{server}' (validator={cfg.validator or 'none'}, reload={cfg.reload_action or 'none'})"
    plan = planner.create(
        kind="config_apply",
        server=server,
        target=config_id,
        reason=clean_reason,
        summary=summary,
        diff=safe_diff,
        payload={
            "server": server,
            "config_id": config_id,
            "base_sha256": current_sha,
            "new_sha256": new_sha,
            "candidate_raw": candidate_raw,
        },
    )
    out = plan.to_public_dict(include_diff=True)
    out["base_sha256"] = current_sha
    out["new_sha256"] = new_sha
    out["validation_output"] = validation_output
    return out


def config_apply(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    plan_token: str,
) -> dict[str, Any]:
    """Consume an APPROVED config plan, re-verify base_sha256, backup + atomic replace + reload."""
    plan = planner.consume_approved(plan_token, expected_kind="config_apply")
    server = str(plan.payload["server"])
    config_id = str(plan.payload["config_id"])
    expected_base_sha = str(plan.payload["base_sha256"])
    candidate_raw = str(plan.payload["candidate_raw"])

    cfg, profile = _get_config_policy(policy, profiles, server, config_id)
    if not policy.global_cfg.gate_mode:
        raise ExecutionError(
            "Config apply requires gate_mode=true with remote ai-ops-gate."
        )

    # Re-verify remote hash immediately prior to writing
    current_raw = _fetch_remote_raw_config(
        policy=policy, ssh=ssh, profile=profile, cfg=cfg, redactor=redactor
    )
    if _sha256_text(current_raw) != expected_base_sha:
        raise ExecutionError(
            "Concurrent modification detected right before apply. Aborted; please re-read and re-plan."
        )

    apply_tokens = ["config-apply", cfg.config_id]
    if cfg.validator:
        apply_tokens.append(f"--validator={cfg.validator}")
    if cfg.reload_action:
        apply_tokens.append(f"--reload={cfg.reload_action}")

    res = ssh.run_remote(
        profile,
        apply_tokens,
        stdin_data=candidate_raw,
        timeout=max(30, policy.global_cfg.default_timeout_seconds),
    )

    extra_literals = [
        (cfg.path, "[CONFIG_PATH]"),
        (cfg.backup_dir, "[BACKUP_DIR]"),
    ]
    safe_stdout = truncate_output(
        redactor.redact(res.stdout.strip(), active_profile=profile, extra_literals=extra_literals),
        8192,
    )
    safe_stderr = truncate_output(
        redactor.redact(res.stderr.strip(), active_profile=profile, extra_literals=extra_literals),
        8192,
    )

    parsed: dict[str, Any] = {}
    if res.stdout.strip().startswith("{"):
        try:
            parsed = json.loads(res.stdout.strip())
        except json.JSONDecodeError:
            parsed = {}

    return {
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "config_id": config_id,
        "exit_code": res.exit_code,
        "backup_id": parsed.get("backup_id"),
        "reloaded": parsed.get("reloaded"),
        "rolled_back": parsed.get("rolled_back", False),
        "stdout": safe_stdout,
        "stderr": safe_stderr,
    }


def config_backups(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    server: str,
    config_id: str,
) -> dict[str, Any]:
    """List available remote backup IDs for a whitelisted config."""
    cfg, profile = _get_config_policy(policy, profiles, server, config_id)
    if not policy.global_cfg.gate_mode:
        raise ExecutionError("Listing config backups requires gate_mode=true.")
    res = ssh.run_remote(profile, ["config-backups", cfg.config_id])
    extra_literals = [(cfg.backup_dir, "[BACKUP_DIR]"), (cfg.path, "[CONFIG_PATH]")]
    if res.exit_code != 0:
        raise ExecutionError(
            redactor.redact(res.stderr.strip(), active_profile=profile, extra_literals=extra_literals)
        )
    backups = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    return {"server": server, "config_id": config_id, "backups": backups}


def config_rollback_plan(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    planner: PlanStore,
    server: str,
    config_id: str,
    backup_id: str,
    reason: str,
) -> dict[str, Any]:
    """Create a two-phase rollback plan for a whitelisted config backup."""
    cfg, _ = _get_config_policy(policy, profiles, server, config_id)
    clean_reason = reason.strip()
    if not clean_reason:
        raise ExecutionError("A non-empty --reason is required for config rollback.")
    if not backup_id or "/" in backup_id or ".." in backup_id:
        raise ExecutionError(f"Invalid backup_id: {backup_id!r}")

    plan = planner.create(
        kind="config_rollback",
        server=server,
        target=config_id,
        reason=clean_reason,
        summary=f"Rollback config '{config_id}' on '{server}' to backup '{backup_id}' (reload={cfg.reload_action or 'none'})",
        payload={"server": server, "config_id": config_id, "backup_id": backup_id},
    )
    return plan.to_public_dict(include_diff=False)


def config_rollback_apply(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    plan_token: str,
) -> dict[str, Any]:
    """Consume an APPROVED rollback plan and restore the specified backup."""
    plan = planner.consume_approved(plan_token, expected_kind="config_rollback")
    server = str(plan.payload["server"])
    config_id = str(plan.payload["config_id"])
    backup_id = str(plan.payload["backup_id"])
    cfg, profile = _get_config_policy(policy, profiles, server, config_id)
    if not policy.global_cfg.gate_mode:
        raise ExecutionError("Config rollback requires gate_mode=true.")

    tokens = ["config-rollback", cfg.config_id, backup_id]
    if cfg.validator:
        tokens.append(f"--validator={cfg.validator}")
    if cfg.reload_action:
        tokens.append(f"--reload={cfg.reload_action}")

    res = ssh.run_remote(profile, tokens)
    extra_literals = [(cfg.path, "[CONFIG_PATH]"), (cfg.backup_dir, "[BACKUP_DIR]")]
    return {
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "config_id": config_id,
        "backup_id": backup_id,
        "exit_code": res.exit_code,
        "stdout": truncate_output(
            redactor.redact(res.stdout.strip(), active_profile=profile, extra_literals=extra_literals),
            8192,
        ),
        "stderr": truncate_output(
            redactor.redact(res.stderr.strip(), active_profile=profile, extra_literals=extra_literals),
            8192,
        ),
    }
