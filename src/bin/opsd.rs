//! opsd binary: Credential-isolated production operations daemon.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;

use safe_server_ops::audit::AuditLogger;
use safe_server_ops::config::{
    expand_path, home_dir, load_daemon_config, load_policy, load_server_profiles,
    DEFAULT_DAEMON_CONFIG_REL,
};
use safe_server_ops::daemon::OpsDaemon;
use safe_server_ops::engine::OpsEngine;
use safe_server_ops::protocol::{DEFAULT_ADMIN_SOCKET_PATH, DEFAULT_SOCKET_PATH};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
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

    /// Optional OS group for client socket (chmod 660)
    #[arg(long)]
    socket_group: Option<String>,

    /// Require config files to be owned by the current daemon user
    #[arg(long)]
    check_ownership: bool,

    /// Skip SSH key existence checks at startup (useful for dry-run / testing)
    #[arg(long)]
    allow_missing_keys: bool,
}

fn run(args: Args) -> Result<(), String> {
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
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
    let socket_group = args
        .socket_group
        .or_else(|| daemon_cfg.as_ref().and_then(|c| c.socket_group.clone()));
    let check_ownership =
        args.check_ownership || daemon_cfg.as_ref().map(|c| c.check_ownership).unwrap_or(false);

    let profiles = load_server_profiles(&servers_env, check_ownership, !args.allow_missing_keys)?;
    let known: HashSet<String> = profiles.keys().cloned().collect();
    let policy = load_policy(&policy_path, Some(&known), check_ownership)?;
    let audit = AuditLogger::new(audit_log)?;

    let engine = Arc::new(OpsEngine::new(profiles, policy, audit, None, 2000));
    let client_mode = if socket_group.is_some() { 0o660 } else { 0o600 };

    let daemon = OpsDaemon::start(
        engine,
        client_socket.clone(),
        admin_socket.clone(),
        client_mode,
        socket_group.as_deref(),
    )?;

    eprintln!(
        "opsd listening on client={} admin={}",
        client_socket.display(),
        admin_socket.display()
    );

    while !SHUTDOWN.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
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
