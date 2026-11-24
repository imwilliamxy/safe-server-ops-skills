//! L2 two-phase production config read, validate, diff plan, atomic apply, and rollback.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use zeroize::Zeroizing;

use crate::config::{ConfigFilePolicy, OpsPolicy, ServerProfile};
use crate::executors::logs::get_server;
use crate::executors::ssh_exec::SSHExecutor;
use crate::planner::{PlanPayload, PlanStore};
use crate::redactor::{mask_config_secrets, truncate_output, unmask_config_secrets, Redactor};

fn get_config_policy<'a>(
    policy: &'a OpsPolicy,
    profiles: &'a BTreeMap<String, ServerProfile>,
    server: &str,
    config_id: &str,
) -> Result<(&'a ConfigFilePolicy, &'a ServerProfile), String> {
    let (spol, sprof) = get_server(policy, profiles, server)?;
    let cfg = spol.configs.get(config_id).ok_or_else(|| {
        format!("Config '{config_id}' is not whitelisted on server '{server}'.")
    })?;
    Ok((cfg, sprof))
}

fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn fetch_remote_raw_config(
    policy: &OpsPolicy,
    ssh: &SSHExecutor,
    profile: &ServerProfile,
    cfg: &ConfigFilePolicy,
    redactor: &Redactor,
) -> Result<String, String> {
    let tokens = if policy.global_cfg.gate_mode {
        vec!["config-read".to_string(), cfg.config_id.clone()]
    } else {
        vec!["cat".to_string(), "--".to_string(), cfg.path.clone()]
    };
    let res = ssh.run_remote(profile, &tokens, None, None)?;
    if res.exit_code != 0 {
        let err = redactor.redact(
            res.stderr.trim(),
            Some(profile),
            &[(cfg.path.as_str(), "[CONFIG_PATH]")],
        );
        return Err(format!(
            "Failed to read remote config '{}': {err}",
            cfg.config_id
        ));
    }
    Ok(res.stdout)
}

fn local_syntax_check(path_str: &str, candidate_raw: &str) -> Result<(), String> {
    let ext = Path::new(path_str)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("json") => {
            serde_json::from_str::<Value>(candidate_raw)
                .map_err(|e| format!("Local JSON syntax check failed: {e}"))?;
        }
        Some("yaml") | Some("yml") => {
            serde_yaml::from_str::<serde_yaml::Value>(candidate_raw)
                .map_err(|e| format!("Local YAML syntax check failed: {e}"))?;
        }
        _ => {}
    }
    Ok(())
}

pub fn config_read(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    server: &str,
    config_id: &str,
) -> Result<Value, String> {
    let (cfg, profile) = get_config_policy(policy, profiles, server, config_id)?;
    let raw = fetch_remote_raw_config(policy, ssh, profile, cfg, redactor)?;
    let base_sha = sha256_text(&raw);
    let (masked, secret_map) = mask_config_secrets(&raw, &cfg.redact_patterns)?;
    let safe_content = truncate_output(
        &redactor.redact(&masked, Some(profile), &[(cfg.path.as_str(), "[CONFIG_PATH]")]),
        policy.global_cfg.max_output_bytes,
    );
    Ok(json!({
        "server": server,
        "config_id": config_id,
        "base_sha256": base_sha,
        "redacted_secret_count": secret_map.len(),
        "content": safe_content,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn config_plan(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    server: &str,
    config_id: &str,
    draft_content: &str,
    base_sha256: &str,
    reason: &str,
) -> Result<Value, String> {
    let (cfg, profile) = get_config_policy(policy, profiles, server, config_id)?;
    let clean_reason = reason.trim();
    if clean_reason.is_empty() {
        return Err("A non-empty --reason is required for config changes.".to_string());
    }

    let remote_raw = fetch_remote_raw_config(policy, ssh, profile, cfg, redactor)?;
    let current_sha = sha256_text(&remote_raw);
    if current_sha != base_sha256 {
        return Err(format!(
            "Optimistic lock failed: remote config changed (expected base_sha256={base_sha256}, current={current_sha}). Re-read the config first."
        ));
    }

    let (remote_masked, secret_map) = mask_config_secrets(&remote_raw, &cfg.redact_patterns)?;
    let candidate_raw = Zeroizing::new(unmask_config_secrets(draft_content, &secret_map)?);
    let new_sha = sha256_text(&candidate_raw);
    if new_sha == current_sha {
        return Err(
            "Draft config is identical to the current remote config; no change to plan.".to_string(),
        );
    }

    local_syntax_check(&cfg.path, &candidate_raw)?;

    let mut validation_output = String::new();
    if let Some(ref validator) = cfg.validator {
        if !policy.global_cfg.gate_mode {
            return Err(
                "Config validation and writing require gate_mode=true with remote ai-ops-gate."
                    .to_string(),
            );
        }
        let vres = ssh.run_remote(
            profile,
            &[
                "config-validate".to_string(),
                cfg.config_id.clone(),
                validator.clone(),
            ],
            Some(&candidate_raw),
            None,
        )?;
        let combined = [vres.stdout.trim(), vres.stderr.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        validation_output = redactor.redact(
            &combined,
            Some(profile),
            &[(cfg.path.as_str(), "[CONFIG_PATH]")],
        );
        if vres.exit_code != 0 {
            return Err(format!(
                "Remote validator '{validator}' failed (exit_code={}): {validation_output}",
                vres.exit_code
            ));
        }
    }

    let diff = TextDiff::from_lines(remote_masked.as_str(), draft_content)
        .unified_diff()
        .header(
            &format!("{config_id} (current)"),
            &format!("{config_id} (proposed)"),
        )
        .to_string();

    let safe_diff = truncate_output(
        &redactor.redact(&diff, Some(profile), &[(cfg.path.as_str(), "[CONFIG_PATH]")]),
        policy.global_cfg.max_output_bytes.min(32768),
    );

    let summary = format!(
        "Update config '{config_id}' on '{server}' (validator={}, reload={})",
        cfg.validator.as_deref().unwrap_or("none"),
        cfg.reload_action.as_deref().unwrap_or("none"),
    );

    let plan = planner.create(
        server.to_string(),
        config_id.to_string(),
        clean_reason.to_string(),
        summary,
        safe_diff,
        PlanPayload::ConfigApply {
            server: server.to_string(),
            config_id: config_id.to_string(),
            base_sha256: current_sha.clone(),
            new_sha256: new_sha.clone(),
            candidate_raw,
        },
    )?;

    let mut out = plan.to_public_json(true);
    out["base_sha256"] = Value::String(current_sha);
    out["new_sha256"] = Value::String(new_sha);
    out["validation_output"] = Value::String(validation_output);
    Ok(out)
}

pub fn config_apply(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    plan_token: &str,
) -> Result<Value, String> {
    let plan = planner.consume_approved(plan_token, "config_apply")?;
    let (server, config_id, expected_base_sha, candidate_raw) = match plan.payload {
        PlanPayload::ConfigApply {
            server,
            config_id,
            base_sha256,
            candidate_raw,
            ..
        } => (server, config_id, base_sha256, candidate_raw),
        _ => return Err("Unexpected plan payload for config_apply.".to_string()),
    };

    let (cfg, profile) = get_config_policy(policy, profiles, &server, &config_id)?;
    if !policy.global_cfg.gate_mode {
        return Err("Config apply requires gate_mode=true with remote ai-ops-gate.".to_string());
    }

    let current_raw = fetch_remote_raw_config(policy, ssh, profile, cfg, redactor)?;
    if sha256_text(&current_raw) != expected_base_sha {
        return Err(
            "Concurrent modification detected right before apply. Aborted; please re-read and re-plan."
                .to_string(),
        );
    }

    let mut apply_tokens = vec!["config-apply".to_string(), cfg.config_id.clone()];
    if let Some(ref v) = cfg.validator {
        apply_tokens.push(format!("--validator={v}"));
    }
    if let Some(ref r) = cfg.reload_action {
        apply_tokens.push(format!("--reload={r}"));
    }

    let timeout = policy.global_cfg.default_timeout_seconds.max(30);
    let res = ssh.run_remote(profile, &apply_tokens, Some(&candidate_raw), Some(timeout))?;

    let extra = [
        (cfg.path.as_str(), "[CONFIG_PATH]"),
        (cfg.backup_dir.as_str(), "[BACKUP_DIR]"),
    ];
    let safe_stdout = truncate_output(&redactor.redact(res.stdout.trim(), Some(profile), &extra), 8192);
    let safe_stderr = truncate_output(&redactor.redact(res.stderr.trim(), Some(profile), &extra), 8192);

    let parsed: Value = serde_json::from_str(res.stdout.trim()).unwrap_or(Value::Null);

    Ok(json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "config_id": config_id,
        "exit_code": res.exit_code,
        "backup_id": parsed.get("backup_id").cloned().unwrap_or(Value::Null),
        "reloaded": parsed.get("reloaded").cloned().unwrap_or(Value::Null),
        "rolled_back": parsed.get("rolled_back").and_then(Value::as_bool).unwrap_or(false),
        "stdout": safe_stdout,
        "stderr": safe_stderr,
    }))
}

pub fn config_backups(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    server: &str,
    config_id: &str,
) -> Result<Value, String> {
    let (cfg, profile) = get_config_policy(policy, profiles, server, config_id)?;
    if !policy.global_cfg.gate_mode {
        return Err("Listing config backups requires gate_mode=true.".to_string());
    }
    let res = ssh.run_remote(
        profile,
        &["config-backups".to_string(), cfg.config_id.clone()],
        None,
        None,
    )?;
    let extra = [
        (cfg.backup_dir.as_str(), "[BACKUP_DIR]"),
        (cfg.path.as_str(), "[CONFIG_PATH]"),
    ];
    if res.exit_code != 0 {
        return Err(redactor.redact(res.stderr.trim(), Some(profile), &extra));
    }
    let backups: Vec<String> = res
        .stdout
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    Ok(json!({
        "server": server,
        "config_id": config_id,
        "backups": backups,
    }))
}

pub fn config_rollback_plan(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    planner: &PlanStore,
    server: &str,
    config_id: &str,
    backup_id: &str,
    reason: &str,
) -> Result<Value, String> {
    let (cfg, _) = get_config_policy(policy, profiles, server, config_id)?;
    let clean_reason = reason.trim();
    if clean_reason.is_empty() {
        return Err("A non-empty --reason is required for config rollback.".to_string());
    }
    if backup_id.is_empty() || backup_id.contains('/') || backup_id.contains("..") {
        return Err(format!("Invalid backup_id: {backup_id:?}"));
    }

    let summary = format!(
        "Rollback config '{config_id}' on '{server}' to backup '{backup_id}' (reload={})",
        cfg.reload_action.as_deref().unwrap_or("none")
    );
    let plan = planner.create(
        server.to_string(),
        config_id.to_string(),
        clean_reason.to_string(),
        summary,
        String::new(),
        PlanPayload::ConfigRollback {
            server: server.to_string(),
            config_id: config_id.to_string(),
            backup_id: backup_id.to_string(),
        },
    )?;
    Ok(plan.to_public_json(false))
}

pub fn config_rollback_apply(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    plan_token: &str,
) -> Result<Value, String> {
    let plan = planner.consume_approved(plan_token, "config_rollback")?;
    let (server, config_id, backup_id) = match plan.payload {
        PlanPayload::ConfigRollback {
            server,
            config_id,
            backup_id,
        } => (server, config_id, backup_id),
        _ => return Err("Unexpected plan payload for config_rollback.".to_string()),
    };

    let (cfg, profile) = get_config_policy(policy, profiles, &server, &config_id)?;
    if !policy.global_cfg.gate_mode {
        return Err("Config rollback requires gate_mode=true.".to_string());
    }

    let mut tokens = vec![
        "config-rollback".to_string(),
        cfg.config_id.clone(),
        backup_id.clone(),
    ];
    if let Some(ref v) = cfg.validator {
        tokens.push(format!("--validator={v}"));
    }
    if let Some(ref r) = cfg.reload_action {
        tokens.push(format!("--reload={r}"));
    }

    let res = ssh.run_remote(profile, &tokens, None, None)?;
    let extra = [
        (cfg.path.as_str(), "[CONFIG_PATH]"),
        (cfg.backup_dir.as_str(), "[BACKUP_DIR]"),
    ];
    Ok(json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "config_id": config_id,
        "backup_id": backup_id,
        "exit_code": res.exit_code,
        "stdout": truncate_output(&redactor.redact(res.stdout.trim(), Some(profile), &extra), 8192),
        "stderr": truncate_output(&redactor.redact(res.stderr.trim(), Some(profile), &extra), 8192),
    }))
}
