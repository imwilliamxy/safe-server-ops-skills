//! Policy-enforced request router separating client (ops.sock) and admin (admin.sock) handlers,
//! with session-aware audit logging, output capture, risk warnings, and hot config reload.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::audit::{AuditLogger, AuditRecord, DEFAULT_AUDIT_OUTPUT_MAX_BYTES};
use crate::config::{load_policy, load_server_profiles, OpsPolicy, ServerProfile};
use crate::executors::config_ops::{
    config_apply, config_backups, config_plan, config_read, config_rollback_apply,
    config_rollback_plan,
};
use crate::executors::docker_ops::{docker_restart_apply, docker_restart_plan};
use crate::executors::exec_ops::{exec_apply, exec_plan};
use crate::executors::logs::{docker_status, read_logs};
use crate::executors::rsync_ops::{rsync_apply, rsync_preview, rsync_preview_dynamic};
use crate::executors::ssh_exec::{shell_quote, CommandRunner, SSHExecutor};
use crate::planner::PlanStore;
use crate::redactor::{truncate_output, Redactor};
use crate::session::{sanitize_field, ClientMeta, PeerCred};

#[derive(Debug, Clone)]
pub struct ReloadSource {
    pub servers_env: PathBuf,
    pub policy_path: PathBuf,
    pub check_ownership: bool,
    pub require_keys_exist: bool,
}

struct EngineRuntime {
    profiles: BTreeMap<String, ServerProfile>,
    policy: OpsPolicy,
    redactor: Redactor,
    ssh: SSHExecutor,
}

pub struct OpsEngine {
    runtime: RwLock<EngineRuntime>,
    custom_runner: Option<Arc<dyn CommandRunner>>,
    reload_source: Option<ReloadSource>,
    audit: AuditLogger,
    audit_output_max_bytes: usize,
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

fn sanitize_client_meta(meta: Option<&ClientMeta>, redactor: &Redactor) -> ClientMeta {
    let Some(m) = meta else {
        return ClientMeta::default();
    };
    ClientMeta {
        session_id: m
            .session_id
            .as_deref()
            .and_then(|s| sanitize_field(s, 128)),
        session_title: m
            .session_title
            .as_deref()
            .and_then(|s| sanitize_field(s, 160))
            .map(|s| redactor.redact(&s, None, &[])),
        agent: m.agent.as_deref().and_then(|s| sanitize_field(s, 48)),
        host_app: m.host_app.as_deref().and_then(|s| sanitize_field(s, 48)),
        cwd: m
            .cwd
            .as_deref()
            .and_then(|s| sanitize_field(s, 512))
            .map(|s| redactor.redact(&s, None, &[])),
        client_pid: m.client_pid,
    }
}

/// Build a canonical, redacted `opsctl ...` representation from the server-validated method & params.
fn build_cli_command(method: &str, params: &Value, redactor: &Redactor) -> String {
    let s = |k: &str| opt_str(params, k).unwrap_or("");
    let q = |v: &str| shell_quote(&redactor.redact(v, None, &[]));

    let raw = match method {
        "capabilities" => "opsctl capabilities".to_string(),
        "logs" => {
            let mut parts = vec![
                "opsctl".to_string(),
                "logs".to_string(),
                q(s("server")),
                q(s("log_id")),
            ];
            if let Some(lines) = params.get("lines").and_then(Value::as_u64) {
                parts.push("--lines".to_string());
                parts.push(lines.to_string());
            }
            if let Some(kw) = opt_str(params, "keyword") {
                parts.push("--keyword".to_string());
                parts.push(q(kw));
            }
            parts.join(" ")
        }
        "docker.status" => {
            if let Some(t) = opt_str(params, "target") {
                format!("opsctl docker status {} {}", q(s("server")), q(t))
            } else {
                format!("opsctl docker status {}", q(s("server")))
            }
        }
        "docker.restart_plan" => format!(
            "opsctl docker restart-plan {} {} --reason {}",
            q(s("server")),
            q(s("target")),
            q(s("reason"))
        ),
        "docker.restart_apply" => {
            format!("opsctl docker restart-apply {}", q(s("plan_token")))
        }
        "rsync.preview" => {
            if let Some(t) = opt_str(params, "target") {
                format!("opsctl rsync preview {} {}", q(s("server")), q(t))
            } else {
                let mut parts = vec![
                    "opsctl".to_string(),
                    "rsync".to_string(),
                    "preview".to_string(),
                    q(s("server")),
                ];
                if let Some(local) = opt_str(params, "local") {
                    parts.push("--local".to_string());
                    parts.push(q(local));
                }
                if let Some(remote) = opt_str(params, "remote") {
                    parts.push("--remote".to_string());
                    parts.push(q(remote));
                }
                if let Some(dir) = opt_str(params, "direction") {
                    parts.push("--direction".to_string());
                    parts.push(q(dir));
                }
                if params
                    .get("allow_delete")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    parts.push("--allow-delete".to_string());
                }
                parts.join(" ")
            }
        }
        "rsync.apply" => format!("opsctl rsync apply {}", q(s("plan_token"))),
        "exec.plan" => format!(
            "opsctl exec plan {} --cmd {} --reason {}",
            q(s("server")),
            q(s("command")),
            q(s("reason"))
        ),
        "exec.apply" => format!("opsctl exec apply {}", q(s("plan_token"))),
        "config.read" => format!(
            "opsctl config read {} {}",
            q(s("server")),
            q(s("config_id"))
        ),
        "config.plan" => format!(
            "opsctl config plan {} {} --base-sha {} --reason {}",
            q(s("server")),
            q(s("config_id")),
            q(s("base_sha256")),
            q(s("reason"))
        ),
        "config.apply" => format!("opsctl config apply {}", q(s("plan_token"))),
        "config.backups" => format!(
            "opsctl config backups {} {}",
            q(s("server")),
            q(s("config_id"))
        ),
        "config.rollback_plan" => format!(
            "opsctl config rollback-plan {} {} {} --reason {}",
            q(s("server")),
            q(s("config_id")),
            q(s("backup_id")),
            q(s("reason"))
        ),
        "config.rollback_apply" => {
            format!("opsctl config rollback-apply {}", q(s("plan_token")))
        }
        other => format!("opsctl {other}"),
    };
    truncate_output(&redactor.redact(&raw, None, &[]), 2048)
}

fn extract_remote_command(
    method: &str,
    params: &Value,
    data: Option<&Value>,
    redactor: &Redactor,
) -> Option<String> {
    if let Some(d) = data {
        if let Some(rc) = d
            .get("remote_command")
            .or_else(|| d.get("command"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(truncate_output(&redactor.redact(rc, None, &[]), 2048));
        }
    }
    if method == "exec.plan" {
        if let Some(cmd) = opt_str(params, "command") {
            return Some(truncate_output(&redactor.redact(cmd, None, &[]), 2048));
        }
    }
    None
}

fn extract_output_preview(
    method: &str,
    data: &Value,
    redactor: &Redactor,
    max_bytes: usize,
) -> Option<String> {
    if max_bytes == 0 {
        return None;
    }

    let mut sections: Vec<String> = Vec::new();
    match method {
        "logs" | "config.read" => {
            if let Some(c) = data.get("content").and_then(Value::as_str) {
                if !c.trim().is_empty() {
                    sections.push(c.to_string());
                }
            }
            if let Some(err) = data.get("stderr").and_then(Value::as_str) {
                if !err.trim().is_empty() {
                    sections.push(format!("[stderr]\n{err}"));
                }
            }
        }
        "docker.status" => {
            if let Some(arr) = data.get("targets").and_then(Value::as_array) {
                for item in arr {
                    let target = item.get("target").and_then(Value::as_str).unwrap_or("");
                    let status = item.get("status").and_then(Value::as_str).unwrap_or("");
                    let stderr = item.get("stderr").and_then(Value::as_str).unwrap_or("");
                    if !status.is_empty() {
                        sections.push(format!("[{target}]\n{status}"));
                    }
                    if !stderr.is_empty() {
                        sections.push(format!("[{target} stderr]\n{stderr}"));
                    }
                }
            }
        }
        "docker.restart_apply" => {
            if let Some(out) = data.get("stdout").and_then(Value::as_str) {
                if !out.trim().is_empty() {
                    sections.push(out.to_string());
                }
            }
            if let Some(err) = data.get("stderr").and_then(Value::as_str) {
                if !err.trim().is_empty() {
                    sections.push(format!("[stderr]\n{err}"));
                }
            }
            if let Some(logs) = data.get("startup_logs").and_then(Value::as_str) {
                if !logs.trim().is_empty() {
                    sections.push(format!("[startup_logs]\n{logs}"));
                }
            }
        }
        "rsync.preview" => {
            if let Some(prev) = data.get("preview_output").and_then(Value::as_str) {
                if !prev.trim().is_empty() {
                    sections.push(prev.to_string());
                }
            }
        }
        "config.plan" => {
            if let Some(val) = data.get("validation_output").and_then(Value::as_str) {
                if !val.trim().is_empty() {
                    sections.push(format!("[validation]\n{val}"));
                }
            }
        }
        "config.backups" => {
            if let Some(arr) = data.get("backups").and_then(Value::as_array) {
                let list: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
                if !list.is_empty() {
                    sections.push(list.join("\n"));
                }
            }
        }
        "capabilities" => {
            if let Some(srvs) = data.get("servers").and_then(Value::as_object) {
                let keys: Vec<&str> = srvs.keys().map(String::as_str).collect();
                sections.push(format!("servers ({}): {}", keys.len(), keys.join(", ")));
            }
        }
        _ => {
            if let Some(out) = data.get("stdout").and_then(Value::as_str) {
                if !out.trim().is_empty() {
                    sections.push(out.to_string());
                }
            }
            if let Some(err) = data.get("stderr").and_then(Value::as_str) {
                if !err.trim().is_empty() {
                    sections.push(format!("[stderr]\n{err}"));
                }
            }
        }
    }

    let combined = sections.join("\n").trim().to_string();
    if combined.is_empty() {
        None
    } else {
        Some(truncate_output(
            &redactor.redact(&combined, None, &[]),
            max_bytes,
        ))
    }
}

fn extract_risk_warnings(data: &Value) -> Vec<String> {
    data.get("risk_warnings")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
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
        let ssh = SSHExecutor::new(policy.global_cfg.clone(), runner.clone());
        let planner = PlanStore::new(policy.global_cfg.plan_ttl_seconds);
        Self {
            runtime: RwLock::new(EngineRuntime {
                profiles,
                policy,
                redactor,
                ssh,
            }),
            custom_runner: runner,
            reload_source: None,
            audit,
            audit_output_max_bytes: DEFAULT_AUDIT_OUTPUT_MAX_BYTES,
            planner,
            post_restart_wait_ms,
        }
    }

    pub fn with_reload_source(mut self, source: ReloadSource) -> Self {
        self.reload_source = Some(source);
        self
    }

    pub fn with_audit_output_max_bytes(mut self, max_bytes: usize) -> Self {
        self.audit_output_max_bytes = max_bytes;
        self
    }

    pub fn planner(&self) -> &PlanStore {
        &self.planner
    }

    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit
    }

    /// Hot-reload `.ssh-servers.env` and `policy.yaml` without dropping pending plans or stopping sockets/web.
    pub fn reload_config(&self) -> Result<Value, String> {
        let Some(ref src) = self.reload_source else {
            return Err("Hot reload is unavailable: no config file paths bound to this engine.".to_string());
        };

        let new_profiles = load_server_profiles(
            &src.servers_env,
            src.check_ownership,
            src.require_keys_exist,
        )?;
        let known: HashSet<String> = new_profiles.keys().cloned().collect();
        let new_policy = load_policy(&src.policy_path, Some(&known), src.check_ownership)?;

        let new_redactor = Redactor::new(&new_profiles);
        let new_ssh = SSHExecutor::new(new_policy.global_cfg.clone(), self.custom_runner.clone());
        let new_ttl = new_policy.global_cfg.plan_ttl_seconds;
        let server_count = new_profiles.len();
        let restricted_count = new_policy.servers.len();
        let allow_unlisted = new_policy.global_cfg.allow_unlisted_servers;
        let gate_mode = new_policy.global_cfg.gate_mode;

        {
            let mut guard = self.runtime.write().unwrap_or_else(|e| e.into_inner());
            *guard = EngineRuntime {
                profiles: new_profiles,
                policy: new_policy,
                redactor: new_redactor,
                ssh: new_ssh,
            };
        }
        self.planner.set_ttl_seconds(new_ttl);

        let info = json!({
            "reloaded": true,
            "server_count": server_count,
            "restricted_servers": restricted_count,
            "allow_unlisted_servers": allow_unlisted,
            "gate_mode": gate_mode,
            "plan_ttl_seconds": new_ttl,
        });
        self.audit.broadcast_event("reload", &info);
        Ok(info)
    }

    /// Trigger a SIGHUP-initiated hot reload and write an audit entry.
    pub fn reload_config_via_signal(&self) -> Result<Value, String> {
        let started = Instant::now();
        let res = self.reload_config();
        let duration_ms = started.elapsed().as_millis();
        match &res {
            Ok(data) => {
                let summary = format!(
                    "reloaded config via SIGHUP (servers={})",
                    data["server_count"].as_u64().unwrap_or(0)
                );
                self.audit.record(AuditRecord {
                    action: "admin.reload",
                    ok: true,
                    server: None,
                    target: None,
                    plan_token_id: None,
                    approved_by: Some("signal:SIGHUP"),
                    exit_code: Some(0),
                    duration_ms: Some(duration_ms),
                    summary: &summary,
                    session_id: None,
                    session_title: None,
                    agent: Some("opsd"),
                    host_app: None,
                    cwd: None,
                    peer_uid: None,
                    peer_pid: None,
                    cli_command: Some("kill -HUP <opsd>"),
                    remote_command: None,
                    reason: Some("SIGHUP reload"),
                    risk_warnings: Vec::new(),
                    diff_preview: None,
                    output_preview: Some(&summary),
                });
            }
            Err(err) => {
                let guard = self.runtime.read().unwrap_or_else(|e| e.into_inner());
                let safe_err = guard.redactor.redact(err, None, &[]);
                let safe_cut: String = safe_err.chars().take(512).collect();
                self.audit.record(AuditRecord {
                    action: "admin.reload",
                    ok: false,
                    server: None,
                    target: None,
                    plan_token_id: None,
                    approved_by: Some("signal:SIGHUP"),
                    exit_code: Some(1),
                    duration_ms: Some(duration_ms),
                    summary: &safe_cut,
                    session_id: None,
                    session_title: None,
                    agent: Some("opsd"),
                    host_app: None,
                    cwd: None,
                    peer_uid: None,
                    peer_pid: None,
                    cli_command: Some("kill -HUP <opsd>"),
                    remote_command: None,
                    reason: Some("SIGHUP reload"),
                    risk_warnings: Vec::new(),
                    diff_preview: None,
                    output_preview: Some(&safe_cut),
                });
            }
        }
        res
    }

    pub fn capabilities(&self) -> Value {
        let rt = self.runtime.read().unwrap_or_else(|e| e.into_inner());
        Self::capabilities_from_runtime(&rt)
    }

    fn capabilities_from_runtime(rt: &EngineRuntime) -> Value {
        let mut servers_map = Map::new();
        for (alias, spol) in &rt.policy.servers {
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
            let mut sync_map = Map::new();
            for (tid, tpol) in &spol.sync_targets {
                sync_map.insert(
                    tid.clone(),
                    json!({
                        "direction": tpol.direction,
                        "description": tpol.description,
                        "allow_delete": tpol.allow_delete,
                        "max_files": tpol.max_files,
                        "max_size_mb": tpol.max_size_mb,
                    }),
                );
            }
            servers_map.insert(
                alias.clone(),
                json!({
                    "policy_mode": "restricted",
                    "description": spol.description,
                    "allow_exec": spol.allow_exec,
                    "logs": logs_map,
                    "docker_targets": docker_targets,
                    "configs": cfg_map,
                    "sync_targets": sync_map,
                }),
            );
        }

        if rt.policy.global_cfg.allow_unlisted_servers {
            for alias in rt.profiles.keys() {
                if servers_map.contains_key(alias) {
                    continue;
                }
                servers_map.insert(
                    alias.clone(),
                    json!({
                        "policy_mode": "default_open",
                        "description": "Unlisted server inheriting default_open read/write (all mutating actions still require human ops-approve)",
                        "allow_exec": !rt.policy.global_cfg.gate_mode,
                        "logs": "any safe absolute path or docker:<container>",
                        "docker_targets": "*",
                        "configs": "any safe absolute path",
                        "sync_targets": "dynamic (--local inside unlisted_staging_root, --remote any safe absolute path)",
                    }),
                );
            }
        }

        json!({
            "servers": servers_map,
            "allow_unlisted_servers": rt.policy.global_cfg.allow_unlisted_servers,
            "gate_mode": rt.policy.global_cfg.gate_mode,
            "unlisted_staging_root": rt.policy.global_cfg.unlisted_staging_root.display().to_string(),
            "plan_ttl_seconds": rt.policy.global_cfg.plan_ttl_seconds,
        })
    }

    /// Safe snapshot of logical server aliases for the read-only Web overview.
    pub fn web_servers_snapshot(&self) -> Vec<Value> {
        let caps = self.capabilities();
        caps.get("servers")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .map(|(alias, info)| {
                        json!({
                            "alias": alias,
                            "policy_mode": info.get("policy_mode").and_then(Value::as_str).unwrap_or("restricted"),
                            "allow_exec": info.get("allow_exec").and_then(Value::as_bool).unwrap_or(false),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn handle_client_request(&self, method: &str, params: &Value) -> Value {
        self.handle_client_request_with_context(method, params, None, PeerCred::default())
    }

    /// Handle requests from the non-privileged client socket (ops.sock).
    /// Admin/approval methods are strictly rejected here to prevent AI self-approval.
    pub fn handle_client_request_with_context(
        &self,
        method: &str,
        params: &Value,
        raw_meta: Option<&ClientMeta>,
        peer: PeerCred,
    ) -> Value {
        let started = Instant::now();
        let mut server_arg = opt_str(params, "server").map(ToString::to_string);
        let mut target_arg = opt_str(params, "target")
            .or_else(|| opt_str(params, "log_id"))
            .or_else(|| opt_str(params, "config_id"))
            .map(ToString::to_string);
        let mut token_arg = opt_str(params, "plan_token").map(ToString::to_string);

        let rt = self.runtime.read().unwrap_or_else(|e| e.into_inner());
        let meta = sanitize_client_meta(raw_meta, &rt.redactor);
        let cli_cmd = build_cli_command(method, params, &rt.redactor);
        let reason_clean = opt_str(params, "reason")
            .map(|r| truncate_output(&rt.redactor.redact(r, None, &[]), 512));

        let result: Result<Value, String> = if method.starts_with("admin.") {
            Err(
                "Approval methods are forbidden on the client socket. Use ops-approve via admin socket."
                    .to_string(),
            )
        } else {
            match method {
                "capabilities" => Ok(Self::capabilities_from_runtime(&rt)),
                "logs" => (|| {
                    let server = req_str(params, "server")?;
                    let log_id = req_str(params, "log_id")?;
                    let lines = params
                        .get("lines")
                        .and_then(Value::as_u64)
                        .unwrap_or(100) as usize;
                    let keyword = opt_str(params, "keyword");
                    read_logs(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
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
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        server,
                        target,
                    )
                })(),
                "docker.restart_plan" => (|| {
                    let server = req_str(params, "server")?;
                    let target = req_str(params, "target")?;
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
                    docker_restart_plan(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        server,
                        target,
                        reason,
                    )
                })(),
                "docker.restart_apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    docker_restart_apply(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        token,
                        self.post_restart_wait_ms,
                    )
                })(),
                "rsync.preview" => (|| {
                    let server = req_str(params, "server")?;
                    if let Some(target) = opt_str(params, "target") {
                        rsync_preview(
                            &rt.policy,
                            &rt.profiles,
                            &rt.ssh,
                            &rt.redactor,
                            &self.planner,
                            server,
                            target,
                        )
                    } else {
                        let local = req_str(params, "local")?;
                        let remote = req_str(params, "remote")?;
                        let direction = opt_str(params, "direction").unwrap_or("push");
                        let allow_delete = params
                            .get("allow_delete")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        rsync_preview_dynamic(
                            &rt.policy,
                            &rt.profiles,
                            &rt.ssh,
                            &rt.redactor,
                            &self.planner,
                            server,
                            local,
                            remote,
                            direction,
                            allow_delete,
                        )
                    }
                })(),
                "rsync.apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    rsync_apply(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                "exec.plan" => (|| {
                    let server = req_str(params, "server")?;
                    let command = req_str(params, "command")?;
                    let reason = params.get("reason").and_then(Value::as_str).unwrap_or("");
                    exec_plan(
                        &rt.policy,
                        &rt.profiles,
                        &rt.redactor,
                        &self.planner,
                        server,
                        command,
                        reason,
                    )
                })(),
                "exec.apply" => (|| {
                    let token = req_str(params, "plan_token")?;
                    exec_apply(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                "config.read" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    config_read(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
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
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
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
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                "config.backups" => (|| {
                    let server = req_str(params, "server")?;
                    let config_id = req_str(params, "config_id")?;
                    config_backups(
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
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
                        &rt.policy,
                        &rt.profiles,
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
                        &rt.policy,
                        &rt.profiles,
                        &rt.ssh,
                        &rt.redactor,
                        &self.planner,
                        token,
                    )
                })(),
                other => Err(format!("Unknown method: '{other}'")),
            }
        };

        let duration_ms = started.elapsed().as_millis();
        match result {
            Ok(mut data) => {
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
                    if data.get("status").and_then(Value::as_str) == Some("PENDING_APPROVAL") {
                        self.planner.attach_session_meta(
                            tok,
                            meta.session_id.clone(),
                            meta.session_title.clone(),
                            meta.agent.clone(),
                            meta.host_app.clone(),
                        );
                        if let Some(ref sid) = meta.session_id {
                            data["session_id"] = Value::String(sid.clone());
                        }
                        if let Some(ref title) = meta.session_title {
                            data["session_title"] = Value::String(title.clone());
                        }
                        if let Some(ref agent) = meta.agent {
                            data["agent"] = Value::String(agent.clone());
                        }
                        self.audit
                            .notify_pending_changed(self.planner.pending_count());
                    }
                }
                if method.ends_with("_apply") || method.ends_with(".apply") {
                    self.audit
                        .notify_pending_changed(self.planner.pending_count());
                }

                let exit_code = data
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|c| c as i32);
                let approved_by = data.get("approved_by").and_then(Value::as_str);
                let summary_raw = data.get("summary").and_then(Value::as_str).unwrap_or("");
                let safe_summary = rt.redactor.redact(summary_raw, None, &[]);
                let safe_summary_cut: String = safe_summary.chars().take(512).collect();
                let remote_command =
                    extract_remote_command(method, params, Some(&data), &rt.redactor);
                let risk_warnings = extract_risk_warnings(&data);
                let diff_preview = data
                    .get("diff")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|d| truncate_output(&rt.redactor.redact(d, None, &[]), 4096));
                let output_preview = extract_output_preview(
                    method,
                    &data,
                    &rt.redactor,
                    self.audit_output_max_bytes,
                );

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
                    session_id: meta.session_id.as_deref(),
                    session_title: meta.session_title.as_deref(),
                    agent: meta.agent.as_deref(),
                    host_app: meta.host_app.as_deref(),
                    cwd: meta.cwd.as_deref(),
                    peer_uid: peer.uid,
                    peer_pid: peer.pid.or(meta.client_pid),
                    cli_command: Some(&cli_cmd),
                    remote_command: remote_command.as_deref(),
                    reason: reason_clean.as_deref(),
                    risk_warnings,
                    diff_preview: diff_preview.as_deref(),
                    output_preview: output_preview.as_deref(),
                });
                json!({ "ok": true, "data": data })
            }
            Err(err) => {
                let safe_err = rt.redactor.redact(&err, None, &[]);
                let safe_cut: String = safe_err.chars().take(512).collect();
                let err_output = truncate_output(&safe_err, self.audit_output_max_bytes);
                let remote_command = extract_remote_command(method, params, None, &rt.redactor);
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
                    session_id: meta.session_id.as_deref(),
                    session_title: meta.session_title.as_deref(),
                    agent: meta.agent.as_deref(),
                    host_app: meta.host_app.as_deref(),
                    cwd: meta.cwd.as_deref(),
                    peer_uid: peer.uid,
                    peer_pid: peer.pid.or(meta.client_pid),
                    cli_command: Some(&cli_cmd),
                    remote_command: remote_command.as_deref(),
                    reason: reason_clean.as_deref(),
                    risk_warnings: Vec::new(),
                    diff_preview: None,
                    output_preview: Some(&err_output),
                });
                json!({ "ok": false, "error": safe_err })
            }
        }
    }

    pub fn handle_admin_request(&self, method: &str, params: &Value) -> Value {
        self.handle_admin_request_with_peer(method, params, PeerCred::default())
    }

    /// Handle approval and reload requests arriving exclusively on admin.sock (0600, owned by sshops).
    pub fn handle_admin_request_with_peer(
        &self,
        method: &str,
        params: &Value,
        peer: PeerCred,
    ) -> Value {
        let started = Instant::now();
        let token_arg = opt_str(params, "plan_token");
        let actor = opt_str(params, "actor").unwrap_or("human");

        let mut plan_ctx_server: Option<String> = None;
        let mut plan_ctx_target: Option<String> = None;
        let mut plan_ctx_session_id: Option<String> = None;
        let mut plan_ctx_session_title: Option<String> = None;
        let mut plan_ctx_agent: Option<String> = None;
        let mut plan_ctx_host_app: Option<String> = None;
        let mut plan_ctx_remote_cmd: Option<String> = None;
        let mut plan_ctx_reason: Option<String> = None;
        let mut plan_ctx_warnings: Vec<String> = Vec::new();

        let result: Result<Value, String> = match method {
            "admin.list_pending" => Ok(json!({ "pending": self.planner.list_pending() })),
            "admin.show_plan" => (|| {
                let tok = req_str(params, "plan_token")?;
                self.planner.get_public(tok, true)
            })(),
            "admin.approve" => (|| {
                let tok = req_str(params, "plan_token")?;
                let plan = self.planner.approve_plan(tok, actor)?;
                plan_ctx_server = Some(plan.server.clone());
                plan_ctx_target = Some(plan.target.clone());
                plan_ctx_session_id = plan.session_id.clone();
                plan_ctx_session_title = plan.session_title.clone();
                plan_ctx_agent = plan.agent.clone();
                plan_ctx_host_app = plan.host_app.clone();
                plan_ctx_remote_cmd = plan.remote_command.clone();
                plan_ctx_reason = if plan.reason.is_empty() {
                    None
                } else {
                    Some(plan.reason.clone())
                };
                plan_ctx_warnings = plan.risk_warnings.clone();
                self.audit
                    .notify_pending_changed(self.planner.pending_count());
                Ok(plan.to_public_json(false))
            })(),
            "admin.reject" => (|| {
                let tok = req_str(params, "plan_token")?;
                let plan = self.planner.reject_plan(tok, actor)?;
                plan_ctx_server = Some(plan.server.clone());
                plan_ctx_target = Some(plan.target.clone());
                plan_ctx_session_id = plan.session_id.clone();
                plan_ctx_session_title = plan.session_title.clone();
                plan_ctx_agent = plan.agent.clone();
                plan_ctx_host_app = plan.host_app.clone();
                plan_ctx_remote_cmd = plan.remote_command.clone();
                plan_ctx_reason = if plan.reason.is_empty() {
                    None
                } else {
                    Some(plan.reason.clone())
                };
                plan_ctx_warnings = plan.risk_warnings.clone();
                self.audit
                    .notify_pending_changed(self.planner.pending_count());
                Ok(plan.to_public_json(false))
            })(),
            "admin.reload" => self.reload_config(),
            other => Err(format!("Unknown admin method: '{other}'")),
        };

        let cli_cmd = match method {
            "admin.list_pending" => "ops-approve --list".to_string(),
            "admin.show_plan" => format!("ops-approve --show {}", token_arg.unwrap_or("")),
            "admin.approve" => format!("ops-approve approve {}", token_arg.unwrap_or("")),
            "admin.reject" => format!("ops-approve reject {}", token_arg.unwrap_or("")),
            "admin.reload" => "ops-approve reload".to_string(),
            other => format!("ops-approve {other}"),
        };

        let duration_ms = started.elapsed().as_millis();
        match result {
            Ok(data) => {
                let summary = match method {
                    "admin.approve" => format!("approved by {actor}"),
                    "admin.reject" => format!("rejected by {actor}"),
                    "admin.reload" => format!(
                        "reloaded config by {actor} (servers={})",
                        data["server_count"].as_u64().unwrap_or(0)
                    ),
                    _ => String::new(),
                };
                self.audit.record(AuditRecord {
                    action: method,
                    ok: true,
                    server: plan_ctx_server.as_deref(),
                    target: plan_ctx_target.as_deref(),
                    plan_token_id: token_arg,
                    approved_by: if matches!(
                        method,
                        "admin.approve" | "admin.reject" | "admin.reload"
                    ) {
                        Some(actor)
                    } else {
                        None
                    },
                    exit_code: None,
                    duration_ms: Some(duration_ms),
                    summary: &summary,
                    session_id: plan_ctx_session_id.as_deref(),
                    session_title: plan_ctx_session_title.as_deref(),
                    agent: plan_ctx_agent.as_deref().or(Some("admin")),
                    host_app: plan_ctx_host_app.as_deref(),
                    cwd: None,
                    peer_uid: peer.uid,
                    peer_pid: peer.pid,
                    cli_command: Some(&cli_cmd),
                    remote_command: plan_ctx_remote_cmd.as_deref(),
                    reason: plan_ctx_reason.as_deref(),
                    risk_warnings: plan_ctx_warnings,
                    diff_preview: None,
                    output_preview: if summary.is_empty() {
                        None
                    } else {
                        Some(&summary)
                    },
                });
                json!({ "ok": true, "data": data })
            }
            Err(err) => {
                let rt = self.runtime.read().unwrap_or_else(|e| e.into_inner());
                let safe_err = rt.redactor.redact(&err, None, &[]);
                let safe_cut: String = safe_err.chars().take(512).collect();
                self.audit.record(AuditRecord {
                    action: method,
                    ok: false,
                    server: plan_ctx_server.as_deref(),
                    target: plan_ctx_target.as_deref(),
                    plan_token_id: token_arg,
                    approved_by: None,
                    exit_code: None,
                    duration_ms: Some(duration_ms),
                    summary: &safe_cut,
                    session_id: plan_ctx_session_id.as_deref(),
                    session_title: plan_ctx_session_title.as_deref(),
                    agent: Some("admin"),
                    host_app: None,
                    cwd: None,
                    peer_uid: peer.uid,
                    peer_pid: peer.pid,
                    cli_command: Some(&cli_cmd),
                    remote_command: None,
                    reason: None,
                    risk_warnings: Vec::new(),
                    diff_preview: None,
                    output_preview: Some(&safe_cut),
                });
                json!({ "ok": false, "error": safe_err })
            }
        }
    }
}
