//! Action risk classification and static high-risk command detection.

use std::sync::OnceLock;

use regex::Regex;

/// Classify an opsd RPC method into L0 / L1 / L2 / ADMIN.
pub fn action_risk_level(action: &str) -> &'static str {
    if action.starts_with("admin.") {
        return "ADMIN";
    }
    match action {
        "capabilities" | "logs" | "docker.status" | "config.read" | "config.backups" => "L0",
        "docker.restart_plan"
        | "docker.restart_apply"
        | "config.rollback_plan"
        | "config.rollback_apply" => "L1",
        "rsync.preview"
        | "rsync.apply"
        | "config.plan"
        | "config.apply"
        | "exec.plan"
        | "exec.apply" => "L2",
        _ => "L0",
    }
}

/// Returns true for mutating or change-planning actions (non-L0).
pub fn is_write_action(action: &str) -> bool {
    matches!(action_risk_level(action), "L1" | "L2")
}

struct RiskRule {
    regex: Regex,
    warning: &'static str,
}

fn command_risk_rules() -> &'static [RiskRule] {
    static RULES: OnceLock<Vec<RiskRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let defs: &[(&str, &str)] = &[
            (
                r"(?i)\brm\s+[^\n]*(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive[^\n]*--force|--force[^\n]*--recursive)",
                "DESTRUCTIVE_RM: Recursive forced deletion (rm -rf) detected",
            ),
            (
                r"(?i)\b(mkfs(\.[a-z0-9]+)?|wipefs|fdisk|parted|shred)\b|\bdd\s+[^\n]*\bof=/dev/",
                "DISK_DESTRUCTIVE: Low-level disk, partition, or filesystem write detected",
            ),
            (
                r"(?i)\bchmod\s+[^\n]*\b0?777\b|\bchmod\s+-[a-zA-Z]*R\b|\bchown\s+-[a-zA-Z]*R\s+[^\n]*\s+/(?:$|etc|usr|var|bin|sbin|lib|root)",
                "BROAD_PERMISSION_CHANGE: Broad chmod/chown permission modification detected",
            ),
            (
                r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|python3?|perl)\b",
                "REMOTE_PIPE_EXEC: Piping remote script directly into an interpreter",
            ),
            (
                r"(?i)\bdocker\s+(rm|rmi|system\s+prune|volume\s+(rm|prune)|container\s+prune)\b|\bdocker\s+compose\s+[^\n]*\bdown\s+[^\n]*(-v|--volumes)\b",
                "DOCKER_DESTRUCTIVE: Destructive Docker remove or prune operation",
            ),
            (
                r"(?i)\b(systemctl\s+(stop|disable|mask)|shutdown|reboot|poweroff|halt)\b|\b(kill\s+-9|pkill\s+-9|killall)\b",
                "SERVICE_DISRUPTION: Stops services, force-kills processes, or reboots host",
            ),
            (
                r"(?i)(^|[;&|]\s*)(sudo|su)\s+|\b(crontab\s+-r|iptables\s+-F|ufw\s+disable)\b|>\s*/etc/",
                "PRIVILEGE_OR_SYSTEM_MODIFY: Privilege escalation, firewall, or /etc modification",
            ),
            (
                r"(?i)\b(DROP\s+(DATABASE|SCHEMA|TABLE)|TRUNCATE\s+TABLE|FLUSHALL|FLUSHDB)\b",
                "DATA_DESTRUCTIVE: Destructive database or cache statement detected",
            ),
        ];

        defs.iter()
            .map(|(pat, warn)| RiskRule {
                regex: Regex::new(pat).expect("valid static risk rule regex"),
                warning: warn,
            })
            .collect()
    })
}

/// Statically inspect a shell command and return human-readable high-risk warnings.
pub fn assess_command_risk(command: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    if command.trim().is_empty() {
        return warnings;
    }
    for rule in command_risk_rules() {
        if rule.regex.is_match(command) {
            warnings.push(rule.warning.to_string());
        }
    }
    warnings
}

/// Assess rsync delete risk flags for plan/audit visibility.
pub fn assess_rsync_risk(allow_delete: bool, deleted_count: usize) -> Vec<String> {
    let mut warnings = Vec::new();
    if allow_delete && deleted_count > 0 {
        warnings.push(format!(
            "RSYNC_DELETE: Sync will delete {deleted_count} remote file(s)"
        ));
    } else if allow_delete {
        warnings.push("RSYNC_DELETE_ENABLED: --delete flag is enabled for this sync".to_string());
    }
    warnings
}
