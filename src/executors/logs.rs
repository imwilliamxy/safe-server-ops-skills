//! L0 read-only log inspection and Docker container status executors.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::config::{OpsPolicy, ServerPolicy, ServerProfile};
use crate::executors::ssh_exec::SSHExecutor;
use crate::redactor::{truncate_output, Redactor};

pub fn get_server<'a>(
    policy: &'a OpsPolicy,
    profiles: &'a BTreeMap<String, ServerProfile>,
    server_alias: &str,
) -> Result<(&'a ServerPolicy, &'a ServerProfile), String> {
    let spol = policy
        .servers
        .get(server_alias)
        .ok_or_else(|| format!("Unknown or unpermitted server alias: '{server_alias}'"))?;
    let sprof = profiles
        .get(server_alias)
        .ok_or_else(|| format!("Unknown or unpermitted server alias: '{server_alias}'"))?;
    Ok((spol, sprof))
}

pub fn read_logs(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    server: &str,
    log_id: &str,
    lines: usize,
    keyword: Option<&str>,
) -> Result<Value, String> {
    let (spol, sprof) = get_server(policy, profiles, server)?;
    let lpol = spol
        .logs
        .get(log_id)
        .ok_or_else(|| format!("Log source '{log_id}' is not whitelisted on server '{server}'."))?;

    let clamped = lines.clamp(1, lpol.max_lines);
    let remote_tokens: Vec<String> = if policy.global_cfg.gate_mode {
        if lpol.source_type == "file" {
            vec![
                "logs-file".to_string(),
                log_id.to_string(),
                clamped.to_string(),
            ]
        } else {
            vec![
                "logs-docker".to_string(),
                lpol.container.clone().unwrap_or_default(),
                clamped.to_string(),
            ]
        }
    } else if lpol.source_type == "file" {
        vec![
            "tail".to_string(),
            "-n".to_string(),
            clamped.to_string(),
            "--".to_string(),
            lpol.path.clone().unwrap_or_default(),
        ]
    } else {
        vec![
            "docker".to_string(),
            "logs".to_string(),
            "--tail".to_string(),
            clamped.to_string(),
            "--".to_string(),
            lpol.container.clone().unwrap_or_default(),
        ]
    };

    let res = ssh.run_remote(sprof, &remote_tokens, None, None)?;

    let mut raw_content = res.stdout.clone();
    if lpol.source_type == "docker" && !res.stderr.is_empty() {
        if raw_content.is_empty() {
            raw_content = res.stderr.clone();
        } else {
            raw_content = format!("{raw_content}\n{}", res.stderr);
        }
    }

    if let Some(kw) = keyword.filter(|s| !s.is_empty()) {
        raw_content = raw_content
            .lines()
            .filter(|ln| ln.contains(kw))
            .collect::<Vec<_>>()
            .join("\n");
    }

    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(ref p) = lpol.path {
        extra.push((p.as_str(), "[LOG_PATH]"));
    }

    let safe_content = truncate_output(
        &redactor.redact(&raw_content, Some(sprof), &extra),
        policy.global_cfg.max_output_bytes,
    );
    let safe_stderr = if lpol.source_type == "file" {
        truncate_output(
            &redactor.redact(&res.stderr, Some(sprof), &extra),
            policy.global_cfg.max_output_bytes.min(8192),
        )
    } else {
        String::new()
    };

    Ok(json!({
        "server": server,
        "log_id": log_id,
        "lines_requested": clamped,
        "keyword": keyword,
        "exit_code": res.exit_code,
        "timed_out": res.timed_out,
        "content": safe_content,
        "stderr": safe_stderr,
    }))
}

pub fn docker_status(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    server: &str,
    target: Option<&str>,
) -> Result<Value, String> {
    let (spol, sprof) = get_server(policy, profiles, server)?;
    let dpol = &spol.docker;

    let mut targets: Vec<String> = Vec::new();
    if let Some(t) = target {
        if !dpol.has_target(t) {
            return Err(format!(
                "Docker target '{t}' is not whitelisted on server '{server}'."
            ));
        }
        targets.push(t.to_string());
    } else {
        targets.extend(dpol.allowed_containers.iter().cloned());
        for (stack_id, stack) in &dpol.allowed_compose {
            for svc in &stack.services {
                targets.push(format!("{stack_id}:{svc}"));
            }
        }
    }

    let mut results = Vec::new();
    for item in targets {
        let (tokens, workdir_opt) = if let Some((stack_id, svc)) = item.split_once(':') {
            let stack = &dpol.allowed_compose[stack_id];
            let toks = if policy.global_cfg.gate_mode {
                vec![
                    "compose-status".to_string(),
                    stack_id.to_string(),
                    svc.to_string(),
                ]
            } else {
                vec![
                    "docker".to_string(),
                    "compose".to_string(),
                    "--project-directory".to_string(),
                    stack.workdir.clone(),
                    "ps".to_string(),
                    "--format".to_string(),
                    "{{.Name}}\t{{.State}}\t{{.Health}}\t{{.Status}}".to_string(),
                    svc.to_string(),
                ]
            };
            (toks, Some(stack.workdir.as_str()))
        } else {
            let toks = if policy.global_cfg.gate_mode {
                vec!["docker-status".to_string(), item.clone()]
            } else {
                vec![
                    "docker".to_string(),
                    "inspect".to_string(),
                    "--format".to_string(),
                    "{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t{{.RestartCount}}\t{{.State.StartedAt}}".to_string(),
                    "--".to_string(),
                    item.clone(),
                ]
            };
            (toks, None)
        };

        let mut extra: Vec<(&str, &str)> = Vec::new();
        if let Some(wd) = workdir_opt {
            extra.push((wd, "[COMPOSE_DIR]"));
        }

        let res = ssh.run_remote(sprof, &tokens, None, None)?;
        results.push(json!({
            "target": item,
            "exit_code": res.exit_code,
            "status": truncate_output(&redactor.redact(res.stdout.trim(), Some(sprof), &extra), 4096),
            "stderr": truncate_output(&redactor.redact(res.stderr.trim(), Some(sprof), &extra), 2048),
        }));
    }

    Ok(json!({
        "server": server,
        "targets": results,
    }))
}
