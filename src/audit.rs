//! Thread-safe append-only JSONL audit logger (0600 permissions).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Local;
use serde_json::{Map, Value};

pub struct AuditLogger {
    path: PathBuf,
    lock: Mutex<()>,
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
}

impl AuditLogger {
    pub fn new(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create audit log directory: {e}"))?;
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, rec: AuditRecord<'_>) {
        let mut obj = Map::new();
        obj.insert(
            "ts".to_string(),
            Value::String(Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)),
        );
        obj.insert("action".to_string(), Value::String(rec.action.to_string()));
        obj.insert("ok".to_string(), Value::Bool(rec.ok));
        if let Some(s) = rec.server {
            obj.insert("server".to_string(), Value::String(s.to_string()));
        }
        if let Some(t) = rec.target {
            obj.insert("target".to_string(), Value::String(t.to_string()));
        }
        if let Some(tok) = rec.plan_token_id {
            obj.insert("plan_token_id".to_string(), Value::String(tok.to_string()));
        }
        if let Some(by) = rec.approved_by {
            obj.insert("approved_by".to_string(), Value::String(by.to_string()));
        }
        if let Some(code) = rec.exit_code {
            obj.insert("exit_code".to_string(), Value::from(code));
        }
        if let Some(ms) = rec.duration_ms {
            obj.insert("duration_ms".to_string(), Value::from(ms as u64));
        }
        if !rec.summary.is_empty() {
            obj.insert("summary".to_string(), Value::String(rec.summary.to_string()));
        }

        let Ok(mut bytes) = serde_json::to_vec(&Value::Object(obj)) else {
            return;
        };
        bytes.push(b'\n');

        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut fh) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            let _ = fh.write_all(&bytes);
        }
    }
}
