//! L1 two-phase Docker container / Compose service restart executor.

use std::collections::BTreeMap;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{validate_id, OpsPolicy, ServerProfile};
use crate::executors::logs::{docker_status, resolve_server_access, ServerAccess};
use crate::executors::ssh_exec::SSHExecutor;
use crate::planner::{PlanPayload, PlanStore};
use crate::redactor::{truncate_output, Redactor};

pub fn docker_restart_plan(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    server: &str,
    target: &str,
    reason: &str,
) -> Result<Value, String> {
    match resolve_server_access(policy, profiles, server)? {
        ServerAccess::Restricted(spol, _) => {
            if !spol.docker.has_target(target) {
                return Err(format!(
                    "Docker target '{target}' is not whitelisted on server '{server}'."
                ));
            }
        }
        ServerAccess::DefaultOpen(_) => {
            validate_id(target, "docker container")?;
        }
    }

    let clean_reason = reason.trim();
    if clean_reason.is_empty() {
        return Err("A non-empty --reason is required for Docker restarts.".to_string());
    }

    let current = docker_status(policy, profiles, ssh, redactor, server, Some(target))?;
    let current_line = current["targets"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item["status"].as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown");

    let summary = format!(
        "Restart Docker target '{target}' on '{server}' (current: {current_line})"
    );
    let plan = planner.create(
        server.to_string(),
        target.to_string(),
        clean_reason.to_string(),
        summary,
        String::new(),
        PlanPayload::DockerRestart {
            server: server.to_string(),
            target: target.to_string(),
        },
    )?;

    let mut out = plan.to_public_json(false);
    out["current_status"] = current["targets"].clone();
    Ok(out)
}

pub fn docker_restart_apply(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    plan_token: &str,
    post_wait_ms: u64,
) -> Result<Value, String> {
    let plan = planner.consume_approved(plan_token, "docker_restart")?;
    let (server, target) = match plan.payload {
        PlanPayload::DockerRestart { server, target } => (server, target),
        _ => return Err("Unexpected plan payload for docker_restart.".to_string()),
    };

    let access = resolve_server_access(policy, profiles, &server)?;
    let mut extra: Vec<(&str, &str)> = Vec::new();

    let (sprof, restart_tokens, logs_tokens) = match access {
        ServerAccess::DefaultOpen(sprof) => (
            sprof,
            vec![
                "docker".to_string(),
                "restart".to_string(),
                "--".to_string(),
                target.clone(),
            ],
            vec![
                "docker".to_string(),
                "logs".to_string(),
                "--tail".to_string(),
                "30".to_string(),
                "--".to_string(),
                target.clone(),
            ],
        ),
        ServerAccess::Restricted(spol, sprof) => {
            let (rt, lt) = if let Some((stack_id, svc)) = target.split_once(':') {
                let stack = &spol.docker.allowed_compose[stack_id];
                extra.push((stack.workdir.as_str(), "[COMPOSE_DIR]"));
                if policy.global_cfg.gate_mode {
                    (
                        vec![
                            "compose-restart".to_string(),
                            stack_id.to_string(),
                            svc.to_string(),
                        ],
                        vec![
                            "compose-logs".to_string(),
                            stack_id.to_string(),
                            svc.to_string(),
                            "30".to_string(),
                        ],
                    )
                } else {
                    (
                        vec![
                            "docker".to_string(),
                            "compose".to_string(),
                            "--project-directory".to_string(),
                            stack.workdir.clone(),
                            "restart".to_string(),
                            svc.to_string(),
                        ],
                        vec![
                            "docker".to_string(),
                            "compose".to_string(),
                            "--project-directory".to_string(),
                            stack.workdir.clone(),
                            "logs".to_string(),
                            "--tail".to_string(),
                            "30".to_string(),
                            svc.to_string(),
                        ],
                    )
                }
            } else if policy.global_cfg.gate_mode {
                (
                    vec!["docker-restart".to_string(), target.clone()],
                    vec!["logs-docker".to_string(), target.clone(), "30".to_string()],
                )
            } else {
                (
                    vec![
                        "docker".to_string(),
                        "restart".to_string(),
                        "--".to_string(),
                        target.clone(),
                    ],
                    vec![
                        "docker".to_string(),
                        "logs".to_string(),
                        "--tail".to_string(),
                        "30".to_string(),
                        "--".to_string(),
                        target.clone(),
                    ],
                )
            };
            (sprof, rt, lt)
        }
    };

    let timeout = policy.global_cfg.default_timeout_seconds.max(30);
    let restart_res = ssh.run_remote(sprof, &restart_tokens, None, Some(timeout))?;

    if restart_res.exit_code == 0 && post_wait_ms > 0 {
        thread::sleep(Duration::from_millis(post_wait_ms));
    }

    let post_status = docker_status(policy, profiles, ssh, redactor, &server, Some(&target))?;
    let startup_res = ssh.run_remote(sprof, &logs_tokens, None, None)?;
    let startup_raw = [startup_res.stdout.trim(), startup_res.stderr.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "target": target,
        "exit_code": restart_res.exit_code,
        "stdout": truncate_output(&redactor.redact(restart_res.stdout.trim(), Some(sprof), &extra), 4096),
        "stderr": truncate_output(&redactor.redact(restart_res.stderr.trim(), Some(sprof), &extra), 4096),
        "post_status": post_status["targets"],
        "startup_logs": truncate_output(
            &redactor.redact(&startup_raw, Some(sprof), &extra),
            policy.global_cfg.max_output_bytes.min(16384),
        ),
    }))
}
