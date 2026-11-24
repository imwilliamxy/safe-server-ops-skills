//! Agent session auto-detection (client-side env + ancestry) and peer credential lookup (daemon-side).

use std::env;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Untrusted-but-structured session metadata attached by `opsctl`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMeta {
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
    pub client_pid: Option<u32>,
}

/// Kernel-verified Unix Domain Socket peer credentials captured by `opsd`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerCred {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
}

pub fn sanitize_field(raw: &str, max_chars: usize) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect::<String>()
        .trim()
        .chars()
        .take(max_chars)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .and_then(|v| sanitize_field(&v, 256))
}

#[derive(Debug, Clone)]
struct AncestorProc {
    pid: u32,
    comm: String,
}

fn inspect_ancestry(start_pid: u32, max_depth: usize) -> Vec<AncestorProc> {
    let mut chain = Vec::new();
    let mut current = start_pid;
    for _ in 0..max_depth {
        if current <= 1 {
            break;
        }
        let Ok(out) = Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &current.to_string()])
            .output()
        else {
            break;
        };
        if !out.status.success() {
            break;
        }
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if line.is_empty() {
            break;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let ppid = parts
            .next()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let comm = parts.next().map(|s| s.trim().to_string()).unwrap_or_default();
        chain.push(AncestorProc {
            pid: current,
            comm,
        });
        if ppid <= 1 || ppid == current {
            break;
        }
        current = ppid;
    }
    chain
}

fn basename_lower(comm: &str) -> String {
    Path::new(comm)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(comm)
        .trim_start_matches('-')
        .to_ascii_lowercase()
}

fn classify_agent_from_comm(comm: &str) -> Option<&'static str> {
    let low = comm.to_ascii_lowercase();
    let base = basename_lower(comm);
    if base == "agy" || low.contains("antigravity") {
        return Some("antigravity");
    }
    if base == "claude" || low.contains("claude-code") || low.contains("claude code") {
        return Some("claude-code");
    }
    if base == "codex" || low.contains("/codex") {
        return Some("codex");
    }
    if base == "cursor-agent" || low.contains("cursor-agent") {
        return Some("cursor");
    }
    if base == "openclaw" || low.contains("openclaw") {
        return Some("openclaw");
    }
    if base == "opencode" || low.contains("opencode") {
        return Some("opencode");
    }
    if base == "aider" {
        return Some("aider");
    }
    None
}

fn classify_host_app_from_comm(comm: &str) -> Option<&'static str> {
    let low = comm.to_ascii_lowercase();
    let base = basename_lower(comm);
    if low.contains("paseo") {
        return Some("paseo");
    }
    if low.contains("cursor.app") || base == "cursor" {
        return Some("cursor");
    }
    if low.contains("visual studio code") || base == "code" {
        return Some("vscode");
    }
    if low.contains("iterm") {
        return Some("iterm2");
    }
    if low.contains("ghostty") {
        return Some("ghostty");
    }
    if low.contains("wezterm") {
        return Some("wezterm");
    }
    if low.contains("alacritty") {
        return Some("alacritty");
    }
    if low.contains("warp") {
        return Some("warp");
    }
    if base == "tmux" {
        return Some("tmux");
    }
    if low.contains("terminal.app") {
        return Some("terminal-app");
    }
    None
}

fn is_shell_comm(comm: &str) -> bool {
    matches!(
        basename_lower(comm).as_str(),
        "zsh" | "bash" | "sh" | "fish" | "nu" | "tcsh" | "ksh"
    )
}

/// Automatically detect the invoking agent, host application, working directory, and stable session ID.
pub fn detect_client_meta(
    explicit_session_id: Option<&str>,
    explicit_title: Option<&str>,
    explicit_agent: Option<&str>,
) -> ClientMeta {
    let self_pid = std::process::id();
    let parent_pid = unsafe { libc::getppid() as u32 };
    let ancestry = inspect_ancestry(parent_pid, 10);

    let mut detected_agent: Option<String> = None;
    let mut agent_anchor_pid: Option<u32> = None;
    let mut detected_host_app: Option<String> = None;
    let mut shell_anchor_pid: Option<u32> = None;

    for proc_info in &ancestry {
        if detected_agent.is_none() {
            if let Some(a) = classify_agent_from_comm(&proc_info.comm) {
                detected_agent = Some(a.to_string());
                agent_anchor_pid = Some(proc_info.pid);
            }
        }
        if detected_host_app.is_none() {
            if let Some(h) = classify_host_app_from_comm(&proc_info.comm) {
                detected_host_app = Some(h.to_string());
            }
        }
        if is_shell_comm(&proc_info.comm) {
            shell_anchor_pid = Some(proc_info.pid);
        }
    }

    // Refine host_app from environment markers
    if non_empty_env("PASEO_AGENT_ID").is_some() || non_empty_env("PASEO_WORKSPACE_ID").is_some() {
        detected_host_app = Some("paseo".to_string());
    } else if detected_host_app.is_none() {
        if non_empty_env("TMUX_PANE").is_some() {
            detected_host_app = Some("tmux".to_string());
        } else if non_empty_env("ITERM_SESSION_ID").is_some() {
            detected_host_app = Some("iterm2".to_string());
        } else if non_empty_env("VSCODE_PID").is_some() || non_empty_env("VSCODE_IPC_HOOK_CLI").is_some() {
            detected_host_app = Some("vscode".to_string());
        }
    }

    // Refine agent from environment markers if not already explicit
    let agent = explicit_agent
        .and_then(|s| sanitize_field(s, 48))
        .or_else(|| non_empty_env("OPS_AGENT_NAME").and_then(|s| sanitize_field(&s, 48)))
        .or(detected_agent)
        .or_else(|| {
            if non_empty_env("ANTIGRAVITY_CONVERSATION_ID").is_some()
                || non_empty_env("ANTIGRAVITY_AGENT").is_some()
            {
                Some("antigravity".to_string())
            } else if non_empty_env("CLAUDE_SESSION_ID").is_some()
                || non_empty_env("CLAUDECODE").is_some()
                || non_empty_env("CLAUDE_CODE_ENTRYPOINT").is_some()
            {
                Some("claude-code".to_string())
            } else if non_empty_env("CODEX_THREAD_ID").is_some()
                || non_empty_env("CODEX_CI").is_some()
            {
                Some("codex".to_string())
            } else if non_empty_env("CURSOR_SESSION_ID").is_some()
                || non_empty_env("CURSOR_TRACE_ID").is_some()
            {
                Some("cursor".to_string())
            } else {
                Some("terminal".to_string())
            }
        });

    let agent_label = agent.as_deref().unwrap_or("terminal");

    // Stable unique session_id priority:
    // 1) Explicit --session-id or OPS_SESSION_ID
    // 2) Paseo per-conversation agent ID (uniquely separates multiple chats in the same project)
    // 3) Antigravity conversation ID
    // 4) Other agent-provided session IDs
    // 5) Ancestor agent PID
    // 6) Terminal session ID or top-most shell PID
    let session_id = explicit_session_id
        .and_then(|s| sanitize_field(s, 128))
        .or_else(|| non_empty_env("OPS_SESSION_ID").and_then(|s| sanitize_field(&s, 128)))
        .or_else(|| {
            non_empty_env("PASEO_AGENT_ID")
                .map(|id| format!("paseo:{id}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("ANTIGRAVITY_CONVERSATION_ID")
                .map(|id| format!("antigravity:{id}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("CLAUDE_SESSION_ID")
                .map(|id| format!("claude:{id}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("CODEX_THREAD_ID")
                .map(|id| format!("codex:{id}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("CURSOR_SESSION_ID")
                .map(|id| format!("cursor:{id}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            agent_anchor_pid.map(|pid| format!("{agent_label}:pid:{pid}"))
        })
        .or_else(|| {
            non_empty_env("TMUX_PANE")
                .map(|p| format!("tmux:{p}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("ITERM_SESSION_ID")
                .map(|p| format!("iterm:{p}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            non_empty_env("TERM_SESSION_ID")
                .map(|p| format!("term:{p}"))
                .and_then(|s| sanitize_field(&s, 128))
        })
        .or_else(|| {
            shell_anchor_pid.map(|pid| format!("{agent_label}:pid:{pid}"))
        })
        .or_else(|| Some(format!("{agent_label}:pid:{parent_pid}")));

    let session_title = explicit_title
        .and_then(|s| sanitize_field(s, 160))
        .or_else(|| non_empty_env("OPS_SESSION_TITLE").and_then(|s| sanitize_field(&s, 160)));

    let cwd = non_empty_env("PASEO_AGENT_CWD")
        .or_else(|| {
            env::current_dir()
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .and_then(|s| sanitize_field(&s, 512));

    ClientMeta {
        session_id,
        session_title,
        agent,
        host_app: detected_host_app,
        cwd,
        client_pid: Some(self_pid),
    }
}

/// Extract kernel-verified peer UID & PID from an accepted Unix Domain Socket stream.
pub fn extract_peer_cred(stream: &UnixStream) -> PeerCred {
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "macos")]
    {
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let uid = if unsafe { libc::getpeereid(fd, &mut euid, &mut egid) } == 0 {
            Some(euid)
        } else {
            None
        };

        let mut peer_pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SOL_LOCAL = 0, LOCAL_PEERPID = 0x002 on Darwin/macOS
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 0x002;
        let pid = if unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                (&mut peer_pid as *mut libc::pid_t).cast::<libc::c_void>(),
                &mut len,
            )
        } == 0
            && peer_pid > 0
        {
            Some(peer_pid as u32)
        } else {
            None
        };

        PeerCred { uid, pid }
    }

    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
                &mut len,
            )
        } == 0;
        if ok {
            PeerCred {
                uid: Some(cred.uid),
                pid: if cred.pid > 0 {
                    Some(cred.pid as u32)
                } else {
                    None
                },
            }
        } else {
            PeerCred::default()
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        PeerCred::default()
    }
}
