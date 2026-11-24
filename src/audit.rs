//! Thread-safe append-only JSONL audit logger (0600) with automatic log rotation,
//! in-memory session/command index, and SSE event broadcasting.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Mutex;

use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::risk::{action_risk_level, is_write_action};

pub const DEFAULT_AUDIT_MAX_BYTES: u64 = 20 * 1024 * 1024; // 20 MiB
pub const DEFAULT_AUDIT_MAX_FILES: usize = 5;
pub const DEFAULT_AUDIT_MEMORY_CAPACITY: usize = 5000;
pub const DEFAULT_AUDIT_OUTPUT_MAX_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub max_file_bytes: u64,
    pub max_rotated_files: usize,
    pub memory_capacity: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_AUDIT_MAX_BYTES,
            max_rotated_files: DEFAULT_AUDIT_MAX_FILES,
            memory_capacity: DEFAULT_AUDIT_MEMORY_CAPACITY,
        }
    }
}

/// Complete audit entry stored in JSONL and served via the read-only Web API.
/// Backward-compatible with legacy JSONL entries that only contain core fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    #[serde(default)]
    pub id: u64,
    pub ts: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub risk_level: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_preview: Option<String>,
}

pub struct AuditRecord<'a> {
    pub action: &'a str,
    pub ok: bool,
    pub server: Option<&'a str>,
    pub target: Option<&'a str>,
    pub plan_token_id: Option<&'a str>,
    pub approved_by: Option<&'a str>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u128>,
    pub summary: &'a str,
    pub session_id: Option<&'a str>,
    pub session_title: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub host_app: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
    pub cli_command: Option<&'a str>,
    pub remote_command: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub risk_warnings: Vec<String>,
    pub diff_preview: Option<&'a str>,
    pub output_preview: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub title: String,
    pub agent: String,
    pub host_app: Option<String>,
    pub cwd: Option<String>,
    pub project_name: Option<String>,
    pub first_ts: String,
    pub last_ts: String,
    pub total_calls: usize,
    pub write_calls: usize,
    pub error_calls: usize,
    pub high_risk_calls: usize,
    pub pending_count: usize,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    pub session_id: Option<String>,
    pub server: Option<String>,
    pub risk_level: Option<String>,
    pub only_errors: bool,
    pub only_high_risk: bool,
    pub query: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordPage {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub records: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditStats {
    pub total_in_memory: usize,
    pub total_sessions: usize,
    pub error_calls: usize,
    pub high_risk_calls: usize,
    pub log_file_bytes: u64,
    pub rotated_files: usize,
    pub max_file_bytes: u64,
    pub max_rotated_files: usize,
}

struct AuditState {
    next_id: u64,
    entries: VecDeque<AuditEntry>,
}

pub struct AuditLogger {
    path: PathBuf,
    options: AuditOptions,
    write_lock: Mutex<()>,
    state: Mutex<AuditState>,
    subscribers: Mutex<Vec<SyncSender<String>>>,
}

fn short_id(session_id: &str) -> String {
    let tail = session_id.rsplit(':').next().unwrap_or(session_id);
    let chars: Vec<char> = tail.chars().collect();
    if chars.len() <= 8 {
        tail.to_string()
    } else {
        chars[..8].iter().collect()
    }
}

fn project_name_from_cwd(cwd: &str) -> Option<String> {
    Path::new(cwd)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn list_rotated_files(base_path: &Path) -> Vec<PathBuf> {
    let Some(parent) = base_path.parent() else {
        return Vec::new();
    };
    let Some(base_name) = base_path.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{base_name}.");
    let Ok(rd) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| n.starts_with(&prefix))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

fn load_entries_from_file(path: &Path, out: &mut Vec<AuditEntry>) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(mut entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            if entry.risk_level.is_empty() {
                entry.risk_level = action_risk_level(&entry.action).to_string();
            }
            out.push(entry);
        }
    }
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> Result<Self, String> {
        Self::with_options(path, AuditOptions::default())
    }

    pub fn with_options(path: PathBuf, options: AuditOptions) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create audit log directory: {e}"))?;
        }

        let mut loaded = Vec::new();
        // Load rotated files oldest -> newest, then current file, keeping the newest `memory_capacity`.
        let rotated = list_rotated_files(&path);
        for rpath in rotated {
            load_entries_from_file(&rpath, &mut loaded);
        }
        load_entries_from_file(&path, &mut loaded);

        let cap = options.memory_capacity.max(100);
        if loaded.len() > cap {
            let drain_count = loaded.len() - cap;
            loaded.drain(..drain_count);
        }

        let mut next_id: u64 = 1;
        let mut entries = VecDeque::with_capacity(loaded.len().min(cap));
        for mut e in loaded {
            if e.id == 0 {
                e.id = next_id;
            }
            next_id = next_id.max(e.id.saturating_add(1));
            entries.push_back(e);
        }

        Ok(Self {
            path,
            options,
            write_lock: Mutex::new(()),
            state: Mutex::new(AuditState { next_id, entries }),
            subscribers: Mutex::new(Vec::new()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn subscribe(&self) -> Receiver<String> {
        let (tx, rx) = mpsc::sync_channel(64);
        let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        subs.push(tx);
        rx
    }

    pub fn broadcast_event(&self, event_name: &str, payload: &Value) {
        let msg = format!("event: {event_name}\ndata: {payload}\n\n");
        let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        subs.retain(|tx| match tx.try_send(msg.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => true, // slow reader: drop this frame, keep connected
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    fn rotate_if_needed_locked(&self, incoming_len: u64) {
        let max_bytes = self.options.max_file_bytes;
        if max_bytes == 0 {
            return;
        }
        let Ok(meta) = fs::metadata(&self.path) else {
            return;
        };
        if meta.len().saturating_add(incoming_len) <= max_bytes {
            return;
        }

        let ts_stamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let Some(base_name) = self.path.file_name().and_then(|s| s.to_str()) else {
            return;
        };
        let Some(parent) = self.path.parent() else {
            return;
        };

        let mut rotated_path = parent.join(format!("{base_name}.{ts_stamp}"));
        let mut suffix = 1usize;
        while rotated_path.exists() {
            rotated_path = parent.join(format!("{base_name}.{ts_stamp}.{suffix}"));
            suffix += 1;
        }

        if fs::rename(&self.path, &rotated_path).is_ok() {
            let max_keep = self.options.max_rotated_files;
            let mut rotated = list_rotated_files(&self.path);
            if rotated.len() > max_keep {
                let to_remove = rotated.len() - max_keep;
                for old in rotated.drain(..to_remove) {
                    let _ = fs::remove_file(old);
                }
            }
        }
    }

    pub fn record(&self, rec: AuditRecord<'_>) -> AuditEntry {
        let ts = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
        let risk_level = action_risk_level(rec.action).to_string();

        let id = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let id = st.next_id;
            st.next_id = st.next_id.saturating_add(1);
            id
        };

        let entry = AuditEntry {
            id,
            ts,
            action: rec.action.to_string(),
            risk_level,
            ok: rec.ok,
            server: rec.server.map(ToString::to_string),
            target: rec.target.map(ToString::to_string),
            plan_token_id: rec.plan_token_id.map(ToString::to_string),
            approved_by: rec.approved_by.map(ToString::to_string),
            exit_code: rec.exit_code,
            duration_ms: rec.duration_ms.map(|ms| ms as u64),
            summary: rec.summary.to_string(),
            session_id: rec.session_id.map(ToString::to_string),
            session_title: rec.session_title.map(ToString::to_string),
            agent: rec.agent.map(ToString::to_string),
            host_app: rec.host_app.map(ToString::to_string),
            cwd: rec.cwd.map(ToString::to_string),
            peer_uid: rec.peer_uid,
            peer_pid: rec.peer_pid,
            cli_command: rec.cli_command.map(ToString::to_string),
            remote_command: rec.remote_command.map(ToString::to_string),
            reason: rec.reason.map(ToString::to_string),
            risk_warnings: rec.risk_warnings,
            diff_preview: rec.diff_preview.map(ToString::to_string),
            output_preview: rec.output_preview.map(ToString::to_string),
        };

        if let Ok(mut bytes) = serde_json::to_vec(&entry) {
            bytes.push(b'\n');
            let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
            self.rotate_if_needed_locked(bytes.len() as u64);
            if let Ok(mut fh) = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)
            {
                let _ = fh.write_all(&bytes);
            }
        }

        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let cap = self.options.memory_capacity.max(100);
            if st.entries.len() >= cap {
                st.entries.pop_front();
            }
            st.entries.push_back(entry.clone());
        }

        if let Ok(val) = serde_json::to_value(&entry) {
            self.broadcast_event("audit", &val);
        }

        entry
    }

    pub fn list_sessions(
        &self,
        pending_by_session: &BTreeMap<String, usize>,
    ) -> Vec<SessionSummary> {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());

        struct Acc {
            title: Option<String>,
            fallback_reason: Option<String>,
            agent: Option<String>,
            host_app: Option<String>,
            cwd: Option<String>,
            first_ts: String,
            last_ts: String,
            last_id: u64,
            total_calls: usize,
            write_calls: usize,
            error_calls: usize,
            high_risk_calls: usize,
            servers: BTreeSet<String>,
        }

        let mut map: BTreeMap<String, Acc> = BTreeMap::new();

        for e in &st.entries {
            let Some(sid_ref) = e.session_id.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let sid = sid_ref.to_string();

            let acc = map.entry(sid).or_insert_with(|| Acc {
                title: None,
                fallback_reason: None,
                agent: None,
                host_app: None,
                cwd: None,
                first_ts: e.ts.clone(),
                last_ts: e.ts.clone(),
                last_id: e.id,
                total_calls: 0,
                write_calls: 0,
                error_calls: 0,
                high_risk_calls: 0,
                servers: BTreeSet::new(),
            });

            acc.total_calls += 1;
            if is_write_action(&e.action) {
                acc.write_calls += 1;
            }
            if !e.ok || e.exit_code.map(|c| c != 0).unwrap_or(false) {
                acc.error_calls += 1;
            }
            if !e.risk_warnings.is_empty() {
                acc.high_risk_calls += 1;
            }
            if let Some(ref srv) = e.server {
                acc.servers.insert(srv.clone());
            }
            if let Some(ref t) = e.session_title {
                if !t.trim().is_empty() {
                    acc.title = Some(t.clone());
                }
            }
            if let Some(ref r) = e.reason {
                if !r.trim().is_empty() {
                    acc.fallback_reason = Some(r.clone());
                }
            }
            if let Some(ref a) = e.agent {
                if !a.trim().is_empty() {
                    acc.agent = Some(a.clone());
                }
            }
            if let Some(ref h) = e.host_app {
                if !h.trim().is_empty() {
                    acc.host_app = Some(h.clone());
                }
            }
            if let Some(ref c) = e.cwd {
                if !c.trim().is_empty() {
                    acc.cwd = Some(c.clone());
                }
            }
            acc.last_ts = e.ts.clone();
            acc.last_id = e.id;
        }

        let mut sessions: Vec<(u64, SessionSummary)> = map
            .into_iter()
            .map(|(sid, acc)| {
                let project_name = acc.cwd.as_deref().and_then(project_name_from_cwd);
                let title = if let Some(t) = acc.title {
                    t
                } else if let Some(r) = acc.fallback_reason {
                    r.chars().take(64).collect()
                } else if let Some(ref proj) = project_name {
                    format!("{proj} · {}", short_id(&sid))
                } else {
                    format!("Session {}", short_id(&sid))
                };

                let agent = acc.agent.unwrap_or_else(|| "unknown".to_string());

                let pending_count = pending_by_session.get(&sid).copied().unwrap_or(0);
                (
                    acc.last_id,
                    SessionSummary {
                        session_id: sid,
                        title,
                        agent,
                        host_app: acc.host_app,
                        cwd: acc.cwd,
                        project_name,
                        first_ts: acc.first_ts,
                        last_ts: acc.last_ts,
                        total_calls: acc.total_calls,
                        write_calls: acc.write_calls,
                        error_calls: acc.error_calls,
                        high_risk_calls: acc.high_risk_calls,
                        pending_count,
                        servers: acc.servers.into_iter().collect(),
                    },
                )
            })
            .collect();

        // Sort by most recently active (descending last_ts, tie-break by last_id)
        sessions.sort_by(|a, b| {
            b.1.last_ts
                .cmp(&a.1.last_ts)
                .then_with(|| b.0.cmp(&a.0))
        });

        sessions.into_iter().map(|(_, s)| s).collect()
    }

    pub fn query_records(&self, filter: &RecordFilter) -> RecordPage {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let q_low = filter
            .query
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());

        let matched: Vec<AuditEntry> = st
            .entries
            .iter()
            .rev()
            .filter(|e| {
                let Some(entry_sid) = e.session_id.as_deref().filter(|s| !s.is_empty()) else {
                    return false;
                };
                if let Some(ref sid) = filter.session_id {
                    if sid != "__all__" && entry_sid != sid {
                        return false;
                    }
                }
                if let Some(ref srv) = filter.server {
                    if e.server.as_deref() != Some(srv.as_str()) {
                        return false;
                    }
                }
                if let Some(ref rl) = filter.risk_level {
                    if !e.risk_level.eq_ignore_ascii_case(rl) {
                        return false;
                    }
                }
                if filter.only_errors && e.ok && e.exit_code.map(|c| c == 0).unwrap_or(true) {
                    return false;
                }
                if filter.only_high_risk && e.risk_warnings.is_empty() {
                    return false;
                }
                if let Some(ref q) = q_low {
                    let hay = [
                        e.action.as_str(),
                        e.server.as_deref().unwrap_or(""),
                        e.target.as_deref().unwrap_or(""),
                        e.cli_command.as_deref().unwrap_or(""),
                        e.remote_command.as_deref().unwrap_or(""),
                        e.reason.as_deref().unwrap_or(""),
                        e.summary.as_str(),
                        e.plan_token_id.as_deref().unwrap_or(""),
                        e.session_title.as_deref().unwrap_or(""),
                        e.output_preview.as_deref().unwrap_or(""),
                    ]
                    .join("\n")
                    .to_ascii_lowercase();
                    if !hay.contains(q) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        let total = matched.len();
        let limit = if filter.limit == 0 {
            100
        } else {
            filter.limit.min(500)
        };
        let offset = filter.offset.min(total);
        let end = offset.saturating_add(limit).min(total);
        let records = matched[offset..end].to_vec();
        let has_more = end < total;

        RecordPage {
            total,
            limit,
            offset,
            has_more,
            records,
        }
    }

    pub fn stats(&self) -> AuditStats {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut sessions = BTreeSet::new();
        let mut error_calls = 0usize;
        let mut high_risk_calls = 0usize;

        let mut total_in_memory = 0usize;
        for e in &st.entries {
            let Some(sid) = e.session_id.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            total_in_memory += 1;
            sessions.insert(sid);
            if !e.ok || e.exit_code.map(|c| c != 0).unwrap_or(false) {
                error_calls += 1;
            }
            if !e.risk_warnings.is_empty() {
                high_risk_calls += 1;
            }
        }

        let log_file_bytes = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let rotated_files = list_rotated_files(&self.path).len();

        AuditStats {
            total_in_memory,
            total_sessions: sessions.len(),
            error_calls,
            high_risk_calls,
            log_file_bytes,
            rotated_files,
            max_file_bytes: self.options.max_file_bytes,
            max_rotated_files: self.options.max_rotated_files,
        }
    }

    pub fn notify_pending_changed(&self, pending_count: usize) {
        self.broadcast_event(
            "pending",
            &json!({ "pending_count": pending_count }),
        );
    }
}
