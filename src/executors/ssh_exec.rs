//! Safe subprocess & OpenSSH execution layer (direct execve, BatchMode=yes, timeout killer).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{GlobalPolicy, ServerProfile};

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, argv: &[String], stdin_data: Option<&str>, timeout_secs: u64) -> CommandResult;
}

pub struct SubprocessRunner;

impl CommandRunner for SubprocessRunner {
    fn run(&self, argv: &[String], stdin_data: Option<&str>, timeout_secs: u64) -> CommandResult {
        if argv.is_empty() {
            return CommandResult {
                exit_code: 1,
                stdout: String::new(),
                stderr: "Empty argv.".to_string(),
                timed_out: false,
            };
        }

        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .stdin(if stdin_data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return CommandResult {
                    exit_code: 127,
                    stdout: String::new(),
                    stderr: format!("Failed to spawn '{}': {e}", argv[0]),
                    timed_out: false,
                };
            }
        };

        if let Some(data) = stdin_data {
            if let Some(mut stdin) = child.stdin.take() {
                let owned = data.as_bytes().to_vec();
                thread::spawn(move || {
                    let _ = stdin.write_all(&owned);
                });
            }
        }

        let stdout_handle = child.stdout.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                String::from_utf8_lossy(&buf).into_owned()
            })
        });
        let stderr_handle = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                String::from_utf8_lossy(&buf).into_owned()
            })
        });

        let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
        let mut timed_out = false;
        let exit_code = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code().unwrap_or(1),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        break 124;
                    }
                    thread::sleep(Duration::from_millis(15));
                }
                Err(_) => break 1,
            }
        };

        let stdout = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let mut stderr = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        if timed_out && stderr.is_empty() {
            stderr = format!("Command timed out after {timeout_secs}s.");
        }

        CommandResult {
            exit_code,
            stdout,
            stderr,
            timed_out,
        }
    }
}

/// POSIX shell single-quote escaping (equivalent to Python's shlex.quote).
pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-' | b'_')
    });
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

pub fn shell_join(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| shell_quote(t))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone)]
pub struct SSHExecutor {
    global_cfg: GlobalPolicy,
    runner: Arc<dyn CommandRunner>,
}

impl SSHExecutor {
    pub fn new(global_cfg: GlobalPolicy, runner: Option<Arc<dyn CommandRunner>>) -> Self {
        Self {
            global_cfg,
            runner: runner.unwrap_or_else(|| Arc::new(SubprocessRunner)),
        }
    }

    pub fn build_ssh_base_options(&self, profile: &ServerProfile, use_sync_key: bool) -> Vec<String> {
        let key_path = if use_sync_key {
            profile.effective_sync_key()
        } else {
            &profile.key_file
        };
        let mut opts = vec![
            "ssh".to_string(),
            "-i".to_string(),
            key_path.to_string_lossy().into_owned(),
            "-p".to_string(),
            profile.port.to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-o".to_string(),
            "ForwardAgent=no".to_string(),
            "-o".to_string(),
            format!(
                "StrictHostKeyChecking={}",
                self.global_cfg.strict_host_key_checking
            ),
            "-o".to_string(),
            "ConnectTimeout=10".to_string(),
            "-o".to_string(),
            "ServerAliveInterval=15".to_string(),
            "-o".to_string(),
            "ServerAliveCountMax=2".to_string(),
        ];
        if let Some(ref kh) = self.global_cfg.known_hosts_file {
            opts.push("-o".to_string());
            opts.push(format!("UserKnownHostsFile={}", kh.display()));
        }
        opts
    }

    pub fn build_rsh_string(&self, profile: &ServerProfile, use_sync_key: bool) -> String {
        let opts = self.build_ssh_base_options(profile, use_sync_key);
        shell_join(&opts)
    }

    pub fn run_remote(
        &self,
        profile: &ServerProfile,
        remote_tokens: &[String],
        stdin_data: Option<&str>,
        timeout_secs: Option<u64>,
    ) -> Result<CommandResult, String> {
        if remote_tokens.is_empty() {
            return Err("Remote command tokens must not be empty.".to_string());
        }
        let remote_cmd = shell_join(remote_tokens);
        let mut argv = self.build_ssh_base_options(profile, false);
        argv.push("--".to_string());
        argv.push(format!("{}@{}", profile.user, profile.host));
        argv.push(remote_cmd);
        let timeout = timeout_secs.unwrap_or(self.global_cfg.default_timeout_seconds);
        Ok(self.runner.run(&argv, stdin_data, timeout))
    }

    pub fn run_local(
        &self,
        argv: &[String],
        stdin_data: Option<&str>,
        timeout_secs: Option<u64>,
    ) -> CommandResult {
        let timeout = timeout_secs.unwrap_or(self.global_cfg.default_timeout_seconds);
        self.runner.run(argv, stdin_data, timeout)
    }
}
