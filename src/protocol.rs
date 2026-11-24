//! Unix Domain Socket NDJSON framing for opsctl / ops-approve / opsd.

use std::env;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

pub const DEFAULT_SOCKET_PATH: &str = "/var/run/sshops/ops.sock";
pub const DEFAULT_ADMIN_SOCKET_PATH: &str = "/var/run/sshops/admin.sock";
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

pub fn resolve_socket_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(env_p) = env::var("OPS_SOCKET") {
        if !env_p.trim().is_empty() {
            return PathBuf::from(env_p);
        }
    }
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

pub fn resolve_admin_socket_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(env_p) = env::var("OPS_ADMIN_SOCKET") {
        if !env_p.trim().is_empty() {
            return PathBuf::from(env_p);
        }
    }
    PathBuf::from(DEFAULT_ADMIN_SOCKET_PATH)
}

pub fn read_json_line(stream: &UnixStream, max_bytes: usize) -> Result<Value, String> {
    let limited = stream.take((max_bytes + 1) as u64);
    let mut reader = BufReader::new(limited);
    let mut buf = Vec::new();
    let n = reader
        .read_until(b'\n', &mut buf)
        .map_err(|e| format!("Failed to read from socket: {e}"))?;
    if n == 0 {
        return Err("Empty message received.".to_string());
    }
    if buf.len() > max_bytes {
        return Err(format!("Message exceeds limit of {max_bytes} bytes."));
    }
    let text = std::str::from_utf8(&buf)
        .map_err(|e| format!("Invalid UTF-8 payload: {e}"))?
        .trim();
    if text.is_empty() {
        return Err("Empty message received.".to_string());
    }
    let val: Value =
        serde_json::from_str(text).map_err(|e| format!("Invalid JSON payload: {e}"))?;
    if !val.is_object() {
        return Err("JSON payload must be an object.".to_string());
    }
    Ok(val)
}

pub fn write_json_line(stream: &mut UnixStream, payload: &Value) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(payload)
        .map_err(|e| format!("Failed to serialize JSON response: {e}"))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_MESSAGE_BYTES {
        return Err("Response exceeds maximum message size.".to_string());
    }
    stream
        .write_all(&encoded)
        .map_err(|e| format!("Failed to write to socket: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("Failed to flush socket: {e}"))
}

pub fn send_request(
    socket_path: &Path,
    method: &str,
    params: Value,
    timeout_secs: u64,
) -> Result<Value, String> {
    if !socket_path.exists() {
        return Err(format!(
            "Socket not found at '{}'. Is opsd running?",
            socket_path.display()
        ));
    }
    let mut stream = UnixStream::connect(socket_path).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => format!(
            "Permission denied connecting to '{}'.",
            socket_path.display()
        ),
        _ => format!("Failed to connect to '{}': {e}", socket_path.display()),
    })?;
    let timeout = Some(Duration::from_secs(timeout_secs));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let req = json!({
        "method": method,
        "params": params,
    });
    write_json_line(&mut stream, &req)?;
    read_json_line(&stream, MAX_MESSAGE_BYTES)
}
