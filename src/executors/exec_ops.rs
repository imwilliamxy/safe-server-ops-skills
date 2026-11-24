//! L2 two-phase human-approved custom remote command executor.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{OpsPolicy, ServerProfile};
use crate::executors::logs::{resolve_server_access, ServerAccess};
use crate::executors::ssh_exec::SSHExecutor;
use crate::planner::{PlanPayload, PlanStore};
use crate::redactor::{truncate_output, Redactor};
use crate::risk::assess_command_risk;

pub fn exec_plan(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    redactor: &Redactor,
    planner: &PlanStore,
    server: &str,
    command: &str,
    reason: &str,
) -> Result<Value, String> {
    let access = resolve_server_access(policy, profiles, server)?;
    match access {
        ServerAccess::Restricted(spol, _) => {
            if !spol.allow_exec {
                return Err(format!(
                    "Custom exec is disabled for restricted server '{server}'. Set 'allow_exec: true' in policy.yaml if intended."
                ));
            }
        }
        ServerAccess::DefaultOpen(_) => {}
    }

    if policy.global_cfg.gate_mode {
        return Err(
            "Custom exec requires global.gate_mode: false (in gate_mode=true remote ForceCommand only permits structured gate actions)."
                .to_string(),
        );
    }

    let clean_cmd = command.trim();
    if clean_cmd.is_empty() {
        return Err("A non-empty --cmd is required.".to_string());
    }
    if clean_cmd.len() > 8192 {
        return Err("Command length exceeds maximum of 8192 bytes.".to_string());
    }
    let clean_reason = reason.trim();
    if clean_reason.is_empty() {
        return Err("A non-empty --reason is required for custom command execution.".to_string());
    }

    let sprof = profiles.get(server);
    let safe_cmd_preview = redactor.redact(clean_cmd, sprof, &[]);
    let risk_warnings = assess_command_risk(clean_cmd);
    let short_cmd: String = safe_cmd_preview.chars().take(120).collect();
    let summary = format!("Execute custom command on '{server}': {short_cmd}");
    let diff = format!("$ {safe_cmd_preview}");

    let plan = planner.create_with_details(
        server.to_string(),
        "custom_exec".to_string(),
        clean_reason.to_string(),
        summary,
        diff,
        PlanPayload::CustomExec {
            server: server.to_string(),
            command: clean_cmd.to_string(),
        },
        risk_warnings,
        Some(safe_cmd_preview.clone()),
    )?;

    let mut out = plan.to_public_json(true);
    out["command"] = Value::String(safe_cmd_preview);
    Ok(out)
}

pub fn exec_apply(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    plan_token: &str,
) -> Result<Value, String> {
    let plan = planner.consume_approved(plan_token, "custom_exec")?;
    let (server, command) = match plan.payload {
        PlanPayload::CustomExec { server, command } => (server, command),
        _ => return Err("Unexpected plan payload for custom_exec.".to_string()),
    };

    let sprof = profiles
        .get(&server)
        .ok_or_else(|| format!("Unknown server alias: '{server}'"))?;

    let timeout = policy.global_cfg.default_timeout_seconds.max(30);
    let res = ssh.run_remote_command_string(sprof, &command, None, Some(timeout))?;
    let safe_cmd = redactor.redact(&command, Some(sprof), &[]);
    let short_cmd: String = safe_cmd.chars().take(120).collect();

    let mut out = json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "target": "custom_exec",
        "command": safe_cmd,
        "remote_command": safe_cmd,
        "summary": format!("Executed custom command on '{server}': {short_cmd}"),
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "stdout": truncate_output(
            &redactor.redact(&res.stdout, Some(sprof), &[]),
            policy.global_cfg.max_output_bytes,
        ),
        "stderr": truncate_output(
            &redactor.redact(&res.stderr, Some(sprof), &[]),
            policy.global_cfg.max_output_bytes.min(16384),
        ),
    });
    if !plan.risk_warnings.is_empty() {
        out["risk_warnings"] = json!(plan.risk_warnings);
    }
    Ok(out)
}
