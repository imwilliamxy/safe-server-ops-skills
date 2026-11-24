//! L2 two-phase human-approved custom remote command executor.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{OpsPolicy, ServerProfile};
use crate::executors::logs::{resolve_server_access, ServerAccess};
use crate::executors::ssh_exec::SSHExecutor;
use crate::planner::{PlanPayload, PlanStore};
use crate::redactor::{truncate_output, Redactor};

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

    let safe_cmd_preview = redactor.redact(clean_cmd, None, &[]);
    let summary = format!("Execute custom command on '{server}' (requires human approval)");
    let diff = format!("$ {safe_cmd_preview}");

    let plan = planner.create(
        server.to_string(),
        "custom_exec".to_string(),
        clean_reason.to_string(),
        summary,
        diff,
        PlanPayload::CustomExec {
            server: server.to_string(),
            command: clean_cmd.to_string(),
        },
    )?;

    Ok(plan.to_public_json(true))
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

    Ok(json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
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
    }))
}
