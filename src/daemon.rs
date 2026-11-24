//! Dual Unix Domain Socket daemon managing ops.sock (client) and admin.sock (0600 approval).

use std::ffi::CString;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{json, Value};

use crate::engine::OpsEngine;
use crate::protocol::{read_json_line, write_json_line, MAX_MESSAGE_BYTES};
use crate::session::{extract_peer_cred, ClientMeta};

fn chown_socket_group(path: &Path, group_name: &str) -> Result<(), String> {
    let c_group = CString::new(group_name)
        .map_err(|_| format!("Invalid socket group name: '{group_name}'"))?;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("Invalid socket path: {}", path.display()))?;

    let gid = unsafe {
        let grp = libc::getgrnam(c_group.as_ptr());
        if grp.is_null() {
            return Err(format!("OS group '{group_name}' does not exist."));
        }
        (*grp).gr_gid
    };

    let rc = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "Failed to chgrp '{}' to '{group_name}': {err}",
            path.display()
        ));
    }
    Ok(())
}

fn bind_unix_socket(
    path: &Path,
    mode: u32,
    socket_group: Option<&str>,
) -> Result<UnixListener, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create socket dir {}: {e}", parent.display()))?;
    }
    if path.exists() || fs::symlink_metadata(path).is_ok() {
        fs::remove_file(path)
            .map_err(|e| format!("Failed to remove stale socket {}: {e}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("Failed to bind Unix socket {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("Failed to chmod socket {}: {e}", path.display()))?;
    if let Some(grp) = socket_group {
        chown_socket_group(path, grp)?;
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set socket nonblocking: {e}"))?;
    Ok(listener)
}

fn handle_connection(mut stream: UnixStream, engine: Arc<OpsEngine>, is_admin: bool) {
    let timeout = Some(Duration::from_secs(60));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    let peer = extract_peer_cred(&stream);

    let resp = match read_json_line(&stream, MAX_MESSAGE_BYTES) {
        Ok(req) => {
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let meta: Option<ClientMeta> = req
                .get("meta")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if !params.is_object() {
                json!({ "ok": false, "error": "'params' must be a JSON object." })
            } else if is_admin {
                engine.handle_admin_request_with_peer(method, &params, peer)
            } else {
                engine.handle_client_request_with_context(method, &params, meta.as_ref(), peer)
            }
        }
        Err(err) => json!({ "ok": false, "error": err }),
    };

    let _ = write_json_line(&mut stream, &resp);
}

fn spawn_listener_loop(
    name: &'static str,
    listener: UnixListener,
    engine: Arc<OpsEngine>,
    is_admin: bool,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let eng = Arc::clone(&engine);
                        thread::spawn(move || handle_connection(stream, eng, is_admin));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        })
        .expect("failed to spawn socket listener thread")
}

pub struct OpsDaemon {
    client_path: PathBuf,
    admin_path: PathBuf,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl OpsDaemon {
    pub fn start(
        engine: Arc<OpsEngine>,
        client_socket: PathBuf,
        admin_socket: PathBuf,
        client_mode: u32,
        socket_group: Option<&str>,
    ) -> Result<Self, String> {
        let client_listener = bind_unix_socket(&client_socket, client_mode, socket_group)?;
        let admin_listener = match bind_unix_socket(&admin_socket, 0o600, None) {
            Ok(l) => l,
            Err(e) => {
                let _ = fs::remove_file(&client_socket);
                return Err(e);
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let t_client = spawn_listener_loop(
            "opsd-client",
            client_listener,
            Arc::clone(&engine),
            false,
            Arc::clone(&stop),
        );
        let t_admin = spawn_listener_loop(
            "opsd-admin",
            admin_listener,
            engine,
            true,
            Arc::clone(&stop),
        );

        Ok(Self {
            client_path: client_socket,
            admin_path: admin_socket,
            stop,
            threads: vec![t_client, t_admin],
        })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let _ = fs::remove_file(&self.client_path);
        let _ = fs::remove_file(&self.admin_path);
    }
}

impl Drop for OpsDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let _ = fs::remove_file(&self.client_path);
        let _ = fs::remove_file(&self.admin_path);
    }
}
