//! opsctl binary: Zero-credential thin CLI client for AI agents and operators.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use safe_server_ops::protocol::{resolve_socket_path, send_request};

#[derive(Parser, Debug)]
#[command(
    name = "opsctl",
    about = "Credential-less CLI client for safe-server-ops (opsd)."
)]
struct Cli {
    /// Path to opsd client Unix socket (or OPS_SOCKET)
    #[arg(long, global = true)]
    socket: Option<String>,

    /// Output raw JSON response
    #[arg(long = "json", global = true)]
    as_json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List allowed server aliases, logs, Docker targets, configs, and sync targets
    Capabilities,

    /// Read whitelisted server or Docker logs (L0)
    Logs {
        server: String,
        log_id: String,
        #[arg(long, default_value_t = 100)]
        lines: usize,
        #[arg(long)]
        keyword: Option<String>,
    },

    /// Inspect or restart whitelisted Docker targets
    Docker {
        #[command(subcommand)]
        action: DockerCmd,
    },

    /// Two-phase safe rsync file synchronization
    Rsync {
        #[command(subcommand)]
        action: RsyncCmd,
    },

    /// Read, validate, apply, and rollback whitelisted configs
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },

    /// Two-phase human-approved custom remote command execution (L2)
    Exec {
        #[command(subcommand)]
        action: ExecCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ExecCmd {
    /// Propose a remote command for human review (L0 -> requires human approval)
    Plan {
        server: String,
        #[arg(long)]
        cmd: String,
        #[arg(long)]
        reason: String,
    },
    /// Execute a human-approved remote command plan (L2)
    Apply { plan_token: String },
}

#[derive(Subcommand, Debug)]
enum DockerCmd {
    /// Show whitelisted Docker status (L0)
    Status {
        server: String,
        target: Option<String>,
    },
    /// Create a Docker restart plan (L0 -> requires human approval)
    RestartPlan {
        server: String,
        target: String,
        #[arg(long)]
        reason: String,
    },
    /// Apply an approved Docker restart plan (L1)
    RestartApply { plan_token: String },
}

#[derive(Subcommand, Debug)]
enum RsyncCmd {
    /// Dry-run preview & manifest hash: `<server> <target>` OR `<server> --local <dir> --remote <dir>`
    Preview {
        /// Server logical alias
        server: String,
        /// Pre-declared sync_target ID under this server (omit when using --local/--remote)
        target: Option<String>,
        #[arg(long)]
        local: Option<String>,
        #[arg(long)]
        remote: Option<String>,
        #[arg(long, default_value = "push")]
        direction: String,
        #[arg(long)]
        allow_delete: bool,
    },
    /// Apply an approved rsync plan (L2)
    Apply { plan_token: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Read config with secrets masked (L0)
    Read { server: String, config_id: String },
    /// Validate draft config and generate diff plan (L0 -> requires human approval)
    Plan {
        server: String,
        config_id: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        base_sha: String,
        #[arg(long)]
        reason: String,
    },
    /// Apply an approved config change plan (L2)
    Apply { plan_token: String },
    /// List available backups for a config (L0)
    Backups { server: String, config_id: String },
    /// Create a config rollback plan (L0 -> requires human approval)
    RollbackPlan {
        server: String,
        config_id: String,
        backup_id: String,
        #[arg(long)]
        reason: String,
    },
    /// Apply an approved config rollback plan (L1)
    RollbackApply { plan_token: String },
}

fn print_result(resp: &Value, as_json: bool) -> ExitCode {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(resp).unwrap_or_else(|_| resp.to_string())
        );
        return if resp.get("ok").and_then(Value::as_bool) == Some(true) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        let err = resp
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Unknown error");
        eprintln!("ERROR: {err}");
        return ExitCode::FAILURE;
    }

    let data = &resp["data"];
    if data.get("content").is_some() && data.get("log_id").is_some() {
        println!(
            "# logs {}:{} (lines={}, exit_code={})",
            data["server"].as_str().unwrap_or(""),
            data["log_id"].as_str().unwrap_or(""),
            data["lines_requested"].as_u64().unwrap_or(0),
            data["exit_code"].as_i64().unwrap_or(0),
        );
        if let Some(c) = data["content"].as_str().filter(|s| !s.is_empty()) {
            println!("{c}");
        }
        if let Some(err) = data["stderr"].as_str().filter(|s| !s.is_empty()) {
            eprintln!("--- stderr ---\n{err}");
        }
        return if data["exit_code"].as_i64() == Some(0) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if data.get("plan_token").is_some()
        && data.get("status").and_then(Value::as_str) == Some("PENDING_APPROVAL")
    {
        let token = data["plan_token"].as_str().unwrap_or("");
        println!(
            "PLAN CREATED (status: PENDING_APPROVAL, expires in {}s)",
            data["expires_in_seconds"].as_u64().unwrap_or(0)
        );
        println!("  plan_token : {token}");
        println!("  kind       : {}", data["kind"].as_str().unwrap_or(""));
        println!("  server     : {}", data["server"].as_str().unwrap_or(""));
        println!("  target     : {}", data["target"].as_str().unwrap_or(""));
        println!("  summary    : {}", data["summary"].as_str().unwrap_or(""));
        if let Some(diff) = data.get("diff").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            println!("\n--- diff / changes ---\n{diff}");
        }
        println!(
            "\nNext step (human approval required):\n  sudo -u sshops /Users/sshops/.local/bin/ops-approve --show {token}\n  sudo -u sshops /Users/sshops/.local/bin/ops-approve approve {token}"
        );
        return ExitCode::SUCCESS;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string())
    );
    match data.get("exit_code").and_then(Value::as_i64) {
        None | Some(0) => ExitCode::SUCCESS,
        Some(_) => ExitCode::FAILURE,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let sock = resolve_socket_path(cli.socket.as_deref());

    let (method, params) = match cli.command {
        Commands::Capabilities => ("capabilities", json!({})),
        Commands::Logs {
            server,
            log_id,
            lines,
            keyword,
        } => (
            "logs",
            json!({
                "server": server,
                "log_id": log_id,
                "lines": lines,
                "keyword": keyword,
            }),
        ),
        Commands::Docker { action } => match action {
            DockerCmd::Status { server, target } => (
                "docker.status",
                json!({ "server": server, "target": target }),
            ),
            DockerCmd::RestartPlan {
                server,
                target,
                reason,
            } => (
                "docker.restart_plan",
                json!({ "server": server, "target": target, "reason": reason }),
            ),
            DockerCmd::RestartApply { plan_token } => (
                "docker.restart_apply",
                json!({ "plan_token": plan_token }),
            ),
        },
        Commands::Rsync { action } => match action {
            RsyncCmd::Preview {
                server,
                target,
                local,
                remote,
                direction,
                allow_delete,
            } => {
                if let Some(t) = target {
                    ("rsync.preview", json!({ "server": server, "target": t }))
                } else {
                    (
                        "rsync.preview",
                        json!({
                            "server": server,
                            "local": local,
                            "remote": remote,
                            "direction": direction,
                            "allow_delete": allow_delete,
                        }),
                    )
                }
            }
            RsyncCmd::Apply { plan_token } => ("rsync.apply", json!({ "plan_token": plan_token })),
        },
        Commands::Exec { action } => match action {
            ExecCmd::Plan {
                server,
                cmd,
                reason,
            } => (
                "exec.plan",
                json!({ "server": server, "command": cmd, "reason": reason }),
            ),
            ExecCmd::Apply { plan_token } => ("exec.apply", json!({ "plan_token": plan_token })),
        },
        Commands::Config { action } => match action {
            ConfigCmd::Read { server, config_id } => (
                "config.read",
                json!({ "server": server, "config_id": config_id }),
            ),
            ConfigCmd::Plan {
                server,
                config_id,
                file,
                base_sha,
                reason,
            } => {
                let draft_content = match fs::read_to_string(&file) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("ERROR: Failed to read draft file {}: {e}", file.display());
                        return ExitCode::FAILURE;
                    }
                };
                (
                    "config.plan",
                    json!({
                        "server": server,
                        "config_id": config_id,
                        "draft_content": draft_content,
                        "base_sha256": base_sha,
                        "reason": reason,
                    }),
                )
            }
            ConfigCmd::Apply { plan_token } => ("config.apply", json!({ "plan_token": plan_token })),
            ConfigCmd::Backups { server, config_id } => (
                "config.backups",
                json!({ "server": server, "config_id": config_id }),
            ),
            ConfigCmd::RollbackPlan {
                server,
                config_id,
                backup_id,
                reason,
            } => (
                "config.rollback_plan",
                json!({
                    "server": server,
                    "config_id": config_id,
                    "backup_id": backup_id,
                    "reason": reason,
                }),
            ),
            ConfigCmd::RollbackApply { plan_token } => (
                "config.rollback_apply",
                json!({ "plan_token": plan_token }),
            ),
        },
    };

    match send_request(&sock, method, params, 120) {
        Ok(resp) => print_result(&resp, cli.as_json),
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::from(2)
        }
    }
}
