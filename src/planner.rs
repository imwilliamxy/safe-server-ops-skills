//! Two-phase approval state machine with zeroized secret config storage,
//! session attribution, and risk warning tracking.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStatus {
    PendingApproval,
    Approved,
    Rejected,
    Consumed,
    Expired,
}

impl PlanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanStatus::PendingApproval => "PENDING_APPROVAL",
            PlanStatus::Approved => "APPROVED",
            PlanStatus::Rejected => "REJECTED",
            PlanStatus::Consumed => "CONSUMED",
            PlanStatus::Expired => "EXPIRED",
        }
    }
}

#[derive(Debug, Clone)]
pub enum PlanPayload {
    DockerRestart {
        server: String,
        target: String,
    },
    RsyncSync {
        target_id: Option<String>,
        server: String,
        direction: String,
        local_base: PathBuf,
        remote_base: String,
        use_rrsync: bool,
        allow_delete: bool,
        max_files: usize,
        max_size_mb: u64,
        manifest_sha256: String,
        local_file_count: usize,
        local_total_bytes: u64,
        exclude_patterns: Vec<String>,
    },
    ConfigApply {
        server: String,
        config_id: String,
        base_sha256: String,
        new_sha256: String,
        /// Zeroized automatically on drop so restored secrets do not linger in heap memory.
        candidate_raw: Zeroizing<String>,
    },
    ConfigRollback {
        server: String,
        config_id: String,
        backup_id: String,
    },
    CustomExec {
        server: String,
        command: String,
    },
}

impl PlanPayload {
    pub fn kind(&self) -> &'static str {
        match self {
            PlanPayload::DockerRestart { .. } => "docker_restart",
            PlanPayload::RsyncSync { .. } => "rsync_sync",
            PlanPayload::ConfigApply { .. } => "config_apply",
            PlanPayload::ConfigRollback { .. } => "config_rollback",
            PlanPayload::CustomExec { .. } => "custom_exec",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub token: String,
    pub kind: String,
    pub server: String,
    pub target: String,
    pub reason: String,
    pub summary: String,
    pub diff: String,
    pub payload: PlanPayload,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: PlanStatus,
    pub approved_by: Option<String>,
    pub approved_at: Option<u64>,
    pub risk_warnings: Vec<String>,
    pub session_id: Option<String>,
    pub session_title: Option<String>,
    pub agent: Option<String>,
    pub host_app: Option<String>,
    pub remote_command: Option<String>,
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

impl Plan {
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    pub fn to_public_json(&self, include_diff: bool) -> Value {
        let now = now_epoch_secs();
        let eff_status = if matches!(
            self.status,
            PlanStatus::PendingApproval | PlanStatus::Approved
        ) && self.is_expired(now)
        {
            PlanStatus::Expired
        } else {
            self.status.clone()
        };

        let mut obj = json!({
            "plan_token": self.token,
            "kind": self.kind,
            "server": self.server,
            "target": self.target,
            "reason": self.reason,
            "summary": self.summary,
            "status": eff_status.as_str(),
            "created_at": self.created_at,
            "expires_in_seconds": self.expires_at.saturating_sub(now),
        });
        if let Some(ref by) = self.approved_by {
            obj["approved_by"] = Value::String(by.clone());
        }
        if include_diff && !self.diff.is_empty() {
            obj["diff"] = Value::String(self.diff.clone());
        }
        if !self.risk_warnings.is_empty() {
            obj["risk_warnings"] = json!(self.risk_warnings);
        }
        if let Some(ref sid) = self.session_id {
            obj["session_id"] = Value::String(sid.clone());
        }
        if let Some(ref title) = self.session_title {
            obj["session_title"] = Value::String(title.clone());
        }
        if let Some(ref a) = self.agent {
            obj["agent"] = Value::String(a.clone());
        }
        if let Some(ref h) = self.host_app {
            obj["host_app"] = Value::String(h.clone());
        }
        if let Some(ref cmd) = self.remote_command {
            obj["remote_command"] = Value::String(cmd.clone());
        }
        obj
    }
}

struct PlanStoreInner {
    ttl_seconds: u64,
    plans: HashMap<String, Plan>,
}

pub struct PlanStore {
    inner: Mutex<PlanStoreInner>,
}

impl PlanStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            inner: Mutex::new(PlanStoreInner {
                ttl_seconds,
                plans: HashMap::new(),
            }),
        }
    }

    pub fn set_ttl_seconds(&self, ttl_seconds: u64) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.ttl_seconds = ttl_seconds;
    }

    fn generate_token() -> Result<String, String> {
        let mut buf = [0u8; 12];
        getrandom::getrandom(&mut buf)
            .map_err(|e| format!("Failed to generate secure plan token: {e}"))?;
        Ok(format!("pln_{}", hex::encode(buf)))
    }

    fn prune_locked(map: &mut HashMap<String, Plan>, now: u64) {
        map.retain(|_, plan| {
            let finished_old = matches!(plan.status, PlanStatus::Consumed | PlanStatus::Rejected)
                && now.saturating_sub(plan.created_at) > 3600;
            let long_expired = now > plan.expires_at.saturating_add(600);
            !(finished_old || long_expired)
        });
    }

    pub fn create(
        &self,
        server: String,
        target: String,
        reason: String,
        summary: String,
        diff: String,
        payload: PlanPayload,
    ) -> Result<Plan, String> {
        self.create_with_details(
            server,
            target,
            reason,
            summary,
            diff,
            payload,
            Vec::new(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_with_details(
        &self,
        server: String,
        target: String,
        reason: String,
        summary: String,
        diff: String,
        payload: PlanPayload,
        risk_warnings: Vec<String>,
        remote_command: Option<String>,
    ) -> Result<Plan, String> {
        let now = now_epoch_secs();
        let token = Self::generate_token()?;
        let kind = payload.kind().to_string();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let ttl = guard.ttl_seconds;
        let plan = Plan {
            token: token.clone(),
            kind,
            server,
            target,
            reason,
            summary,
            diff,
            payload,
            created_at: now,
            expires_at: now.saturating_add(ttl),
            status: PlanStatus::PendingApproval,
            approved_by: None,
            approved_at: None,
            risk_warnings,
            session_id: None,
            session_title: None,
            agent: None,
            host_app: None,
            remote_command,
        };
        Self::prune_locked(&mut guard.plans, now);
        guard.plans.insert(token, plan.clone());
        Ok(plan)
    }

    pub fn attach_session_meta(
        &self,
        token: &str,
        session_id: Option<String>,
        session_title: Option<String>,
        agent: Option<String>,
        host_app: Option<String>,
    ) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(plan) = guard.plans.get_mut(token) {
            plan.session_id = session_id;
            plan.session_title = session_title;
            plan.agent = agent;
            plan.host_app = host_app;
        }
    }

    pub fn list_pending(&self) -> Vec<Value> {
        self.list_pending_with_diff(false)
    }

    pub fn list_pending_with_diff(&self, include_diff: bool) -> Vec<Value> {
        let now = now_epoch_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_locked(&mut guard.plans, now);
        let mut items: Vec<(u64, Value)> = guard
            .plans
            .values()
            .filter(|p| p.status == PlanStatus::PendingApproval && !p.is_expired(now))
            .map(|p| (p.created_at, p.to_public_json(include_diff)))
            .collect();
        items.sort_by(|a, b| b.0.cmp(&a.0));
        items.into_iter().map(|(_, v)| v).collect()
    }

    pub fn pending_counts_by_session(&self) -> BTreeMap<String, usize> {
        let now = now_epoch_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_locked(&mut guard.plans, now);
        let mut counts = BTreeMap::new();
        for p in guard.plans.values() {
            if p.status == PlanStatus::PendingApproval && !p.is_expired(now) {
                if let Some(sid) = p.session_id.as_deref().filter(|s| !s.is_empty()) {
                    *counts.entry(sid.to_string()).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    pub fn pending_count(&self) -> usize {
        let now = now_epoch_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune_locked(&mut guard.plans, now);
        guard
            .plans
            .values()
            .filter(|p| p.status == PlanStatus::PendingApproval && !p.is_expired(now))
            .count()
    }

    pub fn get_public(&self, token: &str, include_diff: bool) -> Result<Value, String> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let plan = guard
            .plans
            .get(token)
            .ok_or_else(|| format!("Unknown plan token: {token}"))?;
        Ok(plan.to_public_json(include_diff))
    }

    pub fn approve(&self, token: &str, approved_by: &str) -> Result<Value, String> {
        self.approve_plan(token, approved_by)
            .map(|p| p.to_public_json(false))
    }

    pub fn approve_plan(&self, token: &str, approved_by: &str) -> Result<Plan, String> {
        let now = now_epoch_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let plan = guard
            .plans
            .get_mut(token)
            .ok_or_else(|| format!("Unknown plan token: {token}"))?;
        if plan.is_expired(now) {
            plan.status = PlanStatus::Expired;
            return Err("Plan token has expired. Please re-run plan/preview.".to_string());
        }
        if plan.status != PlanStatus::PendingApproval {
            return Err(format!(
                "Plan token cannot be approved from status '{}'.",
                plan.status.as_str()
            ));
        }
        plan.status = PlanStatus::Approved;
        plan.approved_by = Some(approved_by.to_string());
        plan.approved_at = Some(now);
        Ok(plan.clone())
    }

    pub fn reject(&self, token: &str, rejected_by: &str) -> Result<Value, String> {
        self.reject_plan(token, rejected_by)
            .map(|p| p.to_public_json(false))
    }

    pub fn reject_plan(&self, token: &str, rejected_by: &str) -> Result<Plan, String> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let plan = guard
            .plans
            .get_mut(token)
            .ok_or_else(|| format!("Unknown plan token: {token}"))?;
        if !matches!(
            plan.status,
            PlanStatus::PendingApproval | PlanStatus::Approved
        ) {
            return Err(format!(
                "Plan token cannot be rejected from status '{}'.",
                plan.status.as_str()
            ));
        }
        plan.status = PlanStatus::Rejected;
        plan.approved_by = Some(format!("rejected:{rejected_by}"));
        Ok(plan.clone())
    }

    pub fn consume_approved(&self, token: &str, expected_kind: &str) -> Result<Plan, String> {
        let now = now_epoch_secs();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let plan = guard
            .plans
            .get_mut(token)
            .ok_or_else(|| format!("Unknown plan token: {token}"))?;
        if plan.kind != expected_kind {
            return Err(format!(
                "Plan token kind mismatch: expected '{expected_kind}', got '{}'.",
                plan.kind
            ));
        }
        if plan.is_expired(now) {
            plan.status = PlanStatus::Expired;
            return Err("Plan token has expired. Please re-run plan/preview.".to_string());
        }
        if plan.status == PlanStatus::PendingApproval {
            return Err(
                "Plan token has NOT been approved yet. A human must approve it via ops-approve."
                    .to_string(),
            );
        }
        if plan.status != PlanStatus::Approved {
            return Err(format!(
                "Plan token cannot be applied (status: '{}').",
                plan.status.as_str()
            ));
        }
        plan.status = PlanStatus::Consumed;
        let cloned = plan.clone();
        // Drop sensitive payload from store immediately after consumption
        if let PlanPayload::ConfigApply { candidate_raw, .. } = &mut plan.payload {
            *candidate_raw = Zeroizing::new(String::new());
        }
        Ok(cloned)
    }

    /// Test helper: force a plan's expiration timestamp into the past.
    pub fn expire_for_test(&self, token: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = guard.plans.get_mut(token) {
            p.expires_at = 0;
        }
    }
}
