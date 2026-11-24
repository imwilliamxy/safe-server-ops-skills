//! ops-approve binary: Human-only approval & admin reload CLI communicating over admin.sock (0600).

use std::env;
use std::process::ExitCode;

use clap::Parser;
use serde_json::{json, Value};

use safe_server_ops::protocol::{resolve_admin_socket_path, send_request};

#[derive(Parser, Debug)]
#[command(
    name = "ops-approve",
    about = "Human-only approval and admin reload tool for opsd (connects to 0600 admin.sock)."
)]
struct Args {
    /// Path to opsd admin Unix socket (or OPS_ADMIN_SOCKET)
    #[arg(long)]
    admin_socket: Option<String>,

    /// Output raw JSON
    #[arg(long = "json")]
    as_json: bool,

    /// List pending plans
    #[arg(long, conflicts_with_all = ["show", "approve", "reject", "reload"])]
    list: bool,

    /// Inspect full plan summary and diff
    #[arg(long, value_name = "PLAN_TOKEN", conflicts_with_all = ["list", "approve", "reject", "reload"])]
    show: Option<String>,

    /// Approve a pending plan token
    #[arg(long, value_name = "PLAN_TOKEN", conflicts_with_all = ["list", "show", "reject", "reload"])]
    approve: Option<String>,

    /// Reject a pending plan token
    #[arg(long, value_name = "PLAN_TOKEN", conflicts_with_all = ["list", "show", "approve", "reload"])]
    reject: Option<String>,

    /// Hot-reload .ssh-servers.env and policy.yaml without restarting opsd
    #[arg(long, conflicts_with_all = ["list", "show", "approve", "reject"])]
    reload: bool,
}

fn detect_actor() -> String {
    let current = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        if !sudo_user.trim().is_empty() {
            return format!("human:{sudo_user} (via sudo->{current})");
        }
    }
    format!("human:{current}")
}

fn normalize_shorthand_args() -> Vec<String> {
    let raw: Vec<String> = env::args().collect();
    let mut out = Vec::with_capacity(raw.len());
    let mut skip_next = false;
    for (idx, tok) in raw.into_iter().enumerate() {
        if idx == 0 {
            out.push(tok);
            continue;
        }
        if skip_next {
            out.push(tok);
            skip_next = false;
            continue;
        }
        if tok == "--admin-socket" {
            out.push(tok);
            skip_next = true;
            continue;
        }
        match tok.as_str() {
            "approve" | "reject" | "show" | "list" | "reload" => out.push(format!("--{tok}")),
            _ => out.push(tok),
        }
    }
    out
}

fn print_warnings(obj: &Value) {
    if let Some(warns) = obj.get("risk_warnings").and_then(Value::as_array) {
        if !warns.is_empty() {
            println!("  !! RISK WARNINGS !!");
            for w in warns {
                if let Some(s) = w.as_str() {
                    println!("    - {s}");
                }
            }
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse_from(normalize_shorthand_args());
    let sock = resolve_admin_socket_path(args.admin_socket.as_deref());
    let actor = detect_actor();

    let (method, params) = if args.list {
        ("admin.list_pending", json!({}))
    } else if let Some(ref tok) = args.show {
        ("admin.show_plan", json!({ "plan_token": tok }))
    } else if let Some(ref tok) = args.approve {
        (
            "admin.approve",
            json!({ "plan_token": tok, "actor": actor }),
        )
    } else if let Some(ref tok) = args.reject {
        (
            "admin.reject",
            json!({ "plan_token": tok, "actor": actor }),
        )
    } else if args.reload {
        ("admin.reload", json!({ "actor": actor }))
    } else {
        eprintln!("ERROR: Specify one of --list, --show <TOKEN>, approve <TOKEN>, reject <TOKEN>, or reload.");
        return ExitCode::from(2);
    };

    let resp = match send_request(&sock, method, params, 30) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::from(2);
        }
    };

    if args.as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| resp.to_string())
        );
        return if resp.get("ok").and_then(Value::as_bool) == Some(true) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if resp.get("ok").and_then(Value::as_bool) != Some(true) {
        eprintln!(
            "ERROR: {}",
            resp.get("error")
                .and_then(Value::as_str)
                .unwrap_or("Unknown error")
        );
        return ExitCode::FAILURE;
    }

    let data = &resp["data"];
    if args.list {
        let pending = data
            .get("pending")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if pending.is_empty() {
            println!("No pending approval plans.");
            return ExitCode::SUCCESS;
        }
        for p in pending {
            println!(
                "{}  [{}]  {}/{}  (expires in {}s)\n  reason : {}\n  summary: {}",
                p["plan_token"].as_str().unwrap_or(""),
                p["kind"].as_str().unwrap_or(""),
                p["server"].as_str().unwrap_or(""),
                p["target"].as_str().unwrap_or(""),
                p["expires_in_seconds"].as_u64().unwrap_or(0),
                p["reason"].as_str().unwrap_or(""),
                p["summary"].as_str().unwrap_or(""),
            );
            if let Some(st) = p.get("session_title").and_then(Value::as_str) {
                println!(
                    "  session: {} ({})",
                    st,
                    p.get("agent").and_then(Value::as_str).unwrap_or("unknown")
                );
            }
            print_warnings(&p);
        }
        return ExitCode::SUCCESS;
    }

    if args.show.is_some() {
        println!("plan_token : {}", data["plan_token"].as_str().unwrap_or(""));
        println!(
            "status     : {} (expires in {}s)",
            data["status"].as_str().unwrap_or(""),
            data["expires_in_seconds"].as_u64().unwrap_or(0)
        );
        println!("kind       : {}", data["kind"].as_str().unwrap_or(""));
        println!("server     : {}", data["server"].as_str().unwrap_or(""));
        println!("target     : {}", data["target"].as_str().unwrap_or(""));
        println!("reason     : {}", data["reason"].as_str().unwrap_or(""));
        println!("summary    : {}", data["summary"].as_str().unwrap_or(""));
        if let Some(sid) = data.get("session_id").and_then(Value::as_str) {
            println!(
                "session    : {} (title={}, agent={})",
                sid,
                data.get("session_title").and_then(Value::as_str).unwrap_or("-"),
                data.get("agent").and_then(Value::as_str).unwrap_or("-"),
            );
        }
        print_warnings(data);
        if let Some(diff) = data.get("diff").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            println!("\n--- diff / changes ---\n{diff}");
        }
        return ExitCode::SUCCESS;
    }

    if args.reload {
        println!(
            "Configuration hot-reloaded (servers={}, restricted={}, allow_unlisted={}, gate_mode={}, plan_ttl={}s)",
            data["server_count"].as_u64().unwrap_or(0),
            data["restricted_servers"].as_u64().unwrap_or(0),
            data["allow_unlisted_servers"].as_bool().unwrap_or(false),
            data["gate_mode"].as_bool().unwrap_or(true),
            data["plan_ttl_seconds"].as_u64().unwrap_or(180),
        );
        return ExitCode::SUCCESS;
    }

    println!(
        "{} -> {} ({})",
        data["plan_token"].as_str().unwrap_or(""),
        data["status"].as_str().unwrap_or(""),
        data.get("approved_by")
            .and_then(Value::as_str)
            .unwrap_or(&actor)
    );
    ExitCode::SUCCESS
}
