//! opsd binary: Credential-isolated production operations daemon with embedded read-only Web UI.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;

use safe_server_ops::audit::{
    AuditLogger, AuditOptions, DEFAULT_AUDIT_MAX_BYTES, DEFAULT_AUDIT_MAX_FILES,
    DEFAULT_AUDIT_MEMORY_CAPACITY, DEFAULT_AUDIT_OUTPUT_MAX_BYTES,
};
use safe_server_ops::config::{
    expand_path, home_dir, load_daemon_config, load_policy, load_server_profiles,
    validate_loopback_listen_addr, DEFAULT_DAEMON_CONFIG_REL, DEFAULT_WEB_LISTEN_ADDR,
};
use safe_server_ops::daemon::OpsDaemon;
use safe_server_ops::engine::{OpsEngine, ReloadSource};
use safe_server_ops::protocol::{DEFAULT_ADMIN_SOCKET_PATH, DEFAULT_SOCKET_PATH};
use safe_server_ops::web::WebServer;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

extern "C" fn handle_sighup(_sig: libc::c_int) {
    RELOAD_REQUESTED.store(true, Ordering::SeqCst);
}

#[derive(Parser, Debug)]
#[command(
    name = "opsd",
    about = "Credential-isolated production operations daemon."
)]
struct Args {
    /// Path to opsd.conf (defaults to ~/.local/config/opsd/opsd.conf if present)
    #[arg(long)]
    config: Option<String>,

    /// Path to .ssh-servers.env (overrides opsd.conf)
    #[arg(long)]
    servers_env: Option<String>,

    /// Path to policy.yaml (overrides opsd.conf)
    #[arg(long)]
    policy: Option<String>,

    /// Client Unix socket path
    #[arg(long)]
    socket: Option<String>,

    /// Admin approval Unix socket path (0600)
    #[arg(long)]
    admin_socket: Option<String>,

    /// Append-only JSONL audit log path
    #[arg(long)]
    audit_log: Option<String>,

    /// Rotate audit.jsonl when it exceeds this size in bytes (default: 20 MiB)
    #[arg(long)]
    audit_max_bytes: Option<u64>,

    /// Number of rotated audit log archives to retain (default: 5)
    #[arg(long)]
    audit_max_files: Option<usize>,

    /// Max bytes of redacted command output stored per audit record (default: 4096)
    #[arg(long)]
    audit_output_max_bytes: Option<usize>,

    /// Optional OS group for client socket (chmod 660)
    #[arg(long)]
    socket_group: Option<String>,

    /// Require config files to be owned by the current daemon user
    #[arg(long)]
    check_ownership: bool,

    /// Skip SSH key existence checks at startup (useful for dry-run / testing)
    #[arg(long)]
    allow_missing_keys: bool,

    /// Loopback listen address for embedded read-only Web UI (default: 127.0.0.1:10100)
    #[arg(long)]
    web_listen: Option<String>,

    /// Disable the embedded read-only Web UI
    #[arg(long)]
    no_web: bool,
}

fn run(args: Args) -> Result<(), String> {
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handle_sighup as *const () as libc::sighandler_t);
    }

    let conf_path: Option<PathBuf> = if let Some(ref explicit) = args.config {
        Some(expand_path(explicit, None)?)
    } else if args.servers_env.is_none() && args.policy.is_none() {
        let candidate = home_dir()?.join(DEFAULT_DAEMON_CONFIG_REL);
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    } else {
        None
    };

    let daemon_cfg = match conf_path {
        Some(ref p) => Some(load_daemon_config(p, args.check_ownership)?),
        None => None,
    };

    let servers_env = match args.servers_env {
        Some(ref p) => expand_path(p, None)?,
        None => daemon_cfg
            .as_ref()
            .map(|c| c.servers_env.clone())
            .ok_or_else(|| {
                "Either --config (or ~/.local/config/opsd/opsd.conf) OR both --servers-env and --policy must be provided."
                    .to_string()
            })?,
    };
    let policy_path = match args.policy {
        Some(ref p) => expand_path(p, None)?,
        None => daemon_cfg
            .as_ref()
            .map(|c| c.policy.clone())
            .ok_or_else(|| {
                "Either --config (or ~/.local/config/opsd/opsd.conf) OR both --servers-env and --policy must be provided."
                    .to_string()
            })?,
    };

    let client_socket = match args.socket {
        Some(ref p) => expand_path(p, None)?,
        None => daemon_cfg
            .as_ref()
            .map(|c| c.socket.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
    };
    let admin_socket = match args.admin_socket {
        Some(ref p) => expand_path(p, None)?,
        None => daemon_cfg
            .as_ref()
            .map(|c| c.admin_socket.clone())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ADMIN_SOCKET_PATH)),
    };
    let audit_log = match args.audit_log {
        Some(ref p) => expand_path(p, None)?,
        None => match daemon_cfg {
            Some(ref c) => c.audit_log.clone(),
            None => expand_path("~/.local/state/opsd/audit.jsonl", None)?,
        },
    };
    let audit_max_bytes = args
        .audit_max_bytes
        .or_else(|| daemon_cfg.as_ref().map(|c| c.audit_max_bytes))
        .unwrap_or(DEFAULT_AUDIT_MAX_BYTES);
    let audit_max_files = args
        .audit_max_files
        .or_else(|| daemon_cfg.as_ref().map(|c| c.audit_max_files))
        .unwrap_or(DEFAULT_AUDIT_MAX_FILES);
    let audit_output_max_bytes = args
        .audit_output_max_bytes
        .or_else(|| daemon_cfg.as_ref().map(|c| c.audit_output_max_bytes))
        .unwrap_or(DEFAULT_AUDIT_OUTPUT_MAX_BYTES);

    let socket_group = args
        .socket_group
        .or_else(|| daemon_cfg.as_ref().and_then(|c| c.socket_group.clone()));
    let check_ownership =
        args.check_ownership || daemon_cfg.as_ref().map(|c| c.check_ownership).unwrap_or(false);

    let web_listen: Option<String> = if args.no_web {
        None
    } else if let Some(ref explicit) = args.web_listen {
        let trimmed = explicit.trim();
        if trimmed.is_empty()
            || matches!(
                trimmed.to_ascii_lowercase().as_str(),
                "off" | "none" | "false" | "disabled"
            )
        {
            None
        } else {
            validate_loopback_listen_addr(trimmed)?;
            Some(trimmed.to_string())
        }
    } else if let Some(ref cfg) = daemon_cfg {
        cfg.web_listen.clone()
    } else {
        Some(DEFAULT_WEB_LISTEN_ADDR.to_string())
    };

    let require_keys_exist = !args.allow_missing_keys;
    let profiles = load_server_profiles(&servers_env, check_ownership, require_keys_exist)?;
    let known: HashSet<String> = profiles.keys().cloned().collect();
    let policy = load_policy(&policy_path, Some(&known), check_ownership)?;
    let audit = AuditLogger::with_options(
        audit_log,
        AuditOptions {
            max_file_bytes: audit_max_bytes,
            max_rotated_files: audit_max_files,
            memory_capacity: DEFAULT_AUDIT_MEMORY_CAPACITY,
        },
    )?;

    let engine = Arc::new(
        OpsEngine::new(profiles, policy, audit, None, 2000)
            .with_audit_output_max_bytes(audit_output_max_bytes)
            .with_reload_source(ReloadSource {
                servers_env,
                policy_path,
                check_ownership,
                require_keys_exist,
            }),
    );
    let client_mode = if socket_group.is_some() { 0o660 } else { 0o600 };

    let daemon = OpsDaemon::start(
        Arc::clone(&engine),
        client_socket.clone(),
        admin_socket.clone(),
        client_mode,
        socket_group.as_deref(),
    )?;

    let web_server = match web_listen {
        Some(ref addr) => match WebServer::start(Arc::clone(&engine), addr) {
            Ok(ws) => Some(ws),
            Err(e) => {
                daemon.stop();
                return Err(e);
            }
        },
        None => None,
    };

    if let Some(ref ws) = web_server {
        eprintln!(
            "opsd listening on client={} admin={} web=http://{}",
            client_socket.display(),
            admin_socket.display(),
            ws.local_addr(),
        );
    } else {
        eprintln!(
            "opsd listening on client={} admin={} web=disabled",
            client_socket.display(),
            admin_socket.display(),
        );
    }

    while !SHUTDOWN.load(Ordering::Relaxed) {
        if RELOAD_REQUESTED.swap(false, Ordering::SeqCst) {
            match engine.reload_config_via_signal() {
                Ok(info) => {
                    eprintln!(
                        "opsd hot-reloaded config via SIGHUP (servers={})",
                        info["server_count"].as_u64().unwrap_or(0)
                    );
                }
                Err(e) => {
                    eprintln!("opsd SIGHUP hot-reload failed (keeping previous config): {e}");
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    if let Some(ws) = web_server {
        ws.stop();
    }
    daemon.stop();
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}
