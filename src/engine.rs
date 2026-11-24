//! Policy-enforced request router separating client (ops.sock) and admin (admin.sock) handlers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::audit::{AuditLogger, AuditRecord};
use crate::config::{OpsPolicy, ServerProfile};
use crate::executors::config_ops::{
    config_apply, config_backups, config_plan, config_read, config_rollback_apply,
    config_rollback_plan,
};
use crate::executors::docker_ops::{docker_restart_apply, docker_restart_plan};
use crate::executors::logs::{docker_status, read_logs};
use crate::executors::rsync_ops::{rsync_apply, rsync_preview};
use crate::executors::ssh_exec::{CommandRunner, SSHExecutor};
use crate::planner::PlanStore;
use crate::redactor::Redactor;

pub struct OpsEngine {
    profiles: BTreeMap<String, ServerProfile>,
    policy: OpsPolicy,
    audit: AuditLogger,
    redactor: Redactor,
    ssh: SSHExecutor,
    planner: PlanStore,
    post_restart_wait_ms: u64,
}

fn req_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing required string parameter '{key}'."))
}

fn opt_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

impl OpsEngine {
    pub fn new(
        profiles: BTreeMap<String, ServerProfile>,
        policy: OpsPolicy,
        audit: AuditLogger,
        runner: Option<Arc<dyn CommandRunner>>,
        post_restart_wait_ms: u64,
    ) -> Self {
        let redactor = Redactor::new(&profiles);
        let ssh = SSHExecutor::new(policy.global_cfg.clone(), runner);
        let planner = PlanStore::new(policy.global_cfg.plan_ttl_seconds);
        Self {
            profiles,
            policy,
            audit,
            redactor,
            ssh,
            planner,
            post_restart_wait_ms,
        }
    }

    pub fn planner(&self) -> &PlanStore {
        &self.planner
    }

    pub fn capabilities(&self) -> Value {
        let mut servers_map = Map::new();
        for (alias, spol) in &self.policy.servers {
            let mut docker_targets = spol.docker.allowed_containers.clone();
            for (stack_id, stack) in &spol.docker.allowed_compose {
                for svc in &stack.services {
                    docker_targets.push(format!("{stack_id}:{svc}"));
                }
            }
            let mut logs_map = Map::new();
            for (lid, lp) in &spol.logs {
                logs_map.insert(
                    lid.clone(),
                    json!({
                        "type": lp.source_type,
                        "max_lines": lp.max_lines,
                    }),
                );
            }
            let mut cfg_map = Map::new();
            for (cid, cp) in &spol.configs {
                cfg_map.insert(
                    cid.clone(),
                    json!({
                        "has_validator": cp.validator.is_some(),
                        "has_reload": cp.reload_action.is_some(),
                    }),
                );
            }
            servers_map.insert(
                alias.clone(),
                json!({
                    "description": spol.description,
                    "logs": logs_map,
                    "docker_targets": docker_targets,
                    "configs": cfg_map,
                }),
            );
        }

        let mut sync_map = Map::new();
        for (tid, tpol) in &self.policy.sync_targets {
            sync_map.insert(
                tid.clone(),
                json!({
                    "server": tpol.server,
                    "direction": tpol.direction,
                    "description": tpol.description,
                    "allow_delete": tpol.allow_delete,
                    "max_files": tpol.max_files,
                    "max_size_mb": tpol.max_size_mb,
                }),
            );
        }

        json!({
            "servers": servers_map,
            "sync_targets": sync_map,
            "plan_ttl_seconds": self.policy.global_cfg.plan_ttl_seconds,
        })
    }

    /// Handle requests from the non-privileged client socket (ops.sock).
    /// Admin/approval methods are strictly rejected here to prevent AI self-approval.
    pub fn handle_client_request(&self, method: &str, params: &Value) -> Value {
        let started = Instant::now();
        let mut server_arg = opt_str(params, "server").map(ToString::to_string);
        let mut target_arg = opt_str(params, "target")
            .or_else(|| opt_str(params, "log_id"))
            .or_else(|| opt_str(params, "config_id"))
            .map(ToString::to_string);
        let mut token_arg = opt_str(params, "plan_token").map(ToString::to_string);

        let result: Result<Value, String> = if method.starts_with("admin.") {
            Err(
                "Approval methods are forbidden on the client socket. Use ops-approve via admin socket."
                    .to_string(),
            )
        } else {
            match method {
                "capabilities" => Ok(self.capabilities()),
                "logs" => (|| {
                    let server = req_str(params, "server")?;
                    let log_id = req_str(params, "log_id")?;
                    let lines = params
                        .get("lines")
                        .and_then(Value::as_u64)
                        .unwrap_or(100) as usize;
                    let keyword = opt_str(params, "keyword");
                    read_logs(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        server,
                        log_id,
                        lines,
                        keyword,
                    )
                })(),
                "docker.status" => (|| {
                    let server = req_str(params, "server")?;
                    let target = opt_str(params, "target");
                    docker_status(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        server,
                        target,
                    )
                })(),
                "docker.restart_plan" => (|| {
                    let server = req_str(params, "server")?;
                    let target = req_str(params, "target")?;
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
                    docker_restart_plan(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        server,
                        target,
                        reason,
                    )
                })(),
                "docker.restart_apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    docker_restart_apply(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        token,
                        self.post_restart_wait_ms,
                    )
                })(),
                "rsync.preview" => (|| {
                    let target = req_str(params, "target")?;
                    rsync_preview(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        target,
                    )
                })(),
                "rsync.apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    rsync_apply(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                "config.read" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    config_read(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        server,
                        config_id,
                    )
                })(),
                "config.plan" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    let draft_content = req_str(params, "draft_content")?;
                    let base_sha256 = req_str(params, "base_sha256")?;
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
                    config_plan(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        server,
                        config_id,
                        draft_content,
                        base_sha256,
                        reason,
                    )
                })(),
                "config.apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    config_apply(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                "config.backups" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    config_backups(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        server,
                        config_id,
                    )
                })(),
                "config.rollback_plan" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    let backup_id = req_str(params, "backup_id")?;
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
                    config_rollback_plan(
                        &self.policy,
                        &self.profiles,
                        &self.planner,
                        server,
                        config_id,
                        backup_id,
                        reason,
                    )
                })(),
                "config.rollback_apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    config_rollback_apply(
                        &self.policy,
                        &self.profiles,
                        &self.ssh,
                        &self.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                other => Err(format!("Unknown method: '{other}'")),
            }
        };

        let duration_ms = started.elapsed().as_millis();
        match result {
            Ok(data) => {
                if let Some(s) = data.get("server").and_then(Value::as_str) {
                    server_arg = Some(s.to_string());
                }
                if let Some(t) = data
                    .get("target")
                    .or_else(|| data.get("config_id"))
                    .and_then(Value::as_str)
                {
                    target_arg = Some(t.to_string());
                }
                if let Some(tok) = data.get("plan_token").and_then(Value::as_str) {
                    token_arg = Some(tok.to_string());
                }
                let exit_code = data
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|c| c as i32);
                let approved_by = data.get("approved_by").and_then(Value::as_str);
                let summary_raw = data.get("summary").and_then(Value::as_str).unwrap_or("");
                let safe_summary = self.redactor.redact(summary_raw, None, &[]);
                let safe_summary_cut: String = safe_summary.chars().take(512).collect();

                self.audit.record(AuditRecord {
                    action: method,
                    ok: true,
                    server: server_arg.as_deref(),
                    target: target_arg.as_deref(),
                    plan_token_id: token_arg.as_deref(),
                    approved_by,
                    exit_code,
                    duration_ms: Some(duration_ms),
                    summary: &safe_summary_cut,
                });
                json!({ "ok": true, "data": data })
            }
            Err(err) => {
                let safe_err = self.redactor.redact(&err, None, &[]);
                let safe_cut: String = safe_err.chars().take(512).collect();
                self.audit.record(AuditRecord {
                    action: method,
                    ok: false,
                    server: server_arg.as_deref(),
                    target: target_arg.as_deref(),
                    plan_token_id: token_arg.as_deref(),
                    approved_by: None,
                    exit_code: None,
                    duration_ms: Some(duration_ms),
                    summary: &safe_cut,
                });
                json!({ "ok": false, "error": safe_err })
            }
        }
    }

    /// Handle approval requests arriving exclusively on admin.sock (0600, owned by sshops).
    pub fn handle_admin_request(&self, method: &str, params: &Value) -> Value {
        let started = Instant::now();
        let token_arg = opt_str(params, "plan_token");
        let actor = opt_str(params, "actor").unwrap_or("human");

        let result: Result<Value, String> = match method {
            "admin.list_pending" => Ok(json!({ "pending": self.planner.list_pending() })),
            "admin.show_plan" => (|| {
                let tok = req_str(params, "plan_token")?;
                self.planner.get_public(tok, true)
            })(),
            "admin.approve" => (|| {
                let tok = req_str(params, "plan_token")?;
                self.planner.approve(tok, actor)
            })(),
            "admin.reject" => (|| {
                let tok = req_str(params, "plan_token")?;
                self.planner.reject(tok, actor)
            })(),
            other => Err(format!("Unknown admin method: '{other}'")),
        };

        let duration_ms = started.elapsed().as_millis();
        match result {
            Ok(data) => {
                let summary = match method {
                    "admin.approve" => format!("approved by {actor}"),
                    "admin.reject" => format!("rejected by {actor}"),
                    _ => String::new(),
                };
                self.audit.record(AuditRecord {
                    action: method,
                    ok: true,
                    server: None,
                    target: None,
                    plan_token_id: token_arg,
                    approved_by: if matches!(method, "admin.approve" | "admin.reject") {
                        Some(actor)
                    } else {
                        None
                    },
                    exit_code: None,
                    duration_ms: Some(duration_ms),
                    summary: &summary,
                });
                json!({ "ok": true, "data": data })
            }
            Err(err) => {
                let safe_err = self.redactor.redact(&err, None, &[]);
                let safe_cut: String = safe_err.chars().take(512).collect();
                self.audit.record(AuditRecord {
                    action: method,
                    ok: false,
                    server: None,
                    target: None,
                    plan_token_id: token_arg,
                    approved_by: None,
                    exit_code: None,
                    duration_ms: Some(duration_ms),
                    summary: &safe_cut,
                });
                json!({ "ok": false, "error": safe_err })
            }
        }
    }
}
