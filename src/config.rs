//! Strict literal parsers for opsd.conf, .ssh-servers.env, and YAML parser for policy.yaml.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use regex::Regex;
use serde::Deserialize;

use crate::protocol::{DEFAULT_ADMIN_SOCKET_PATH, DEFAULT_SOCKET_PATH};

pub const DEFAULT_DAEMON_CONFIG_REL: &str = ".local/config/opsd/opsd.conf";

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub servers_env: PathBuf,
    pub policy: PathBuf,
    pub socket: PathBuf,
    pub admin_socket: PathBuf,
    pub audit_log: PathBuf,
    pub socket_group: Option<String>,
    pub check_ownership: bool,
}

#[derive(Debug, Clone)]
pub struct ServerProfile {
    pub alias: String,
    pub host: String,
    pub user: String,
    pub port: u16,
    pub key_file: PathBuf,
    pub sync_key_file: Option<PathBuf>,
}

impl ServerProfile {
    pub fn effective_sync_key(&self) -> &Path {
        self.sync_key_file.as_deref().unwrap_or(&self.key_file)
    }
}

#[derive(Debug, Clone)]
pub struct LogSourcePolicy {
    pub log_id: String,
    pub source_type: String, // "file" | "docker"
    pub path: Option<String>,
    pub container: Option<String>,
    pub max_lines: usize,
}

#[derive(Debug, Clone)]
pub struct ComposeStackPolicy {
    pub stack_id: String,
    pub workdir: String,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DockerPolicy {
    pub allowed_containers: Vec<String>,
    pub allowed_compose: BTreeMap<String, ComposeStackPolicy>,
}

impl DockerPolicy {
    pub fn has_target(&self, target: &str) -> bool {
        if self.allowed_containers.iter().any(|c| c == target) {
            return true;
        }
        if let Some((stack_id, svc)) = target.split_once(':') {
            if let Some(stack) = self.allowed_compose.get(stack_id) {
                return stack.services.iter().any(|s| s == svc);
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct ConfigFilePolicy {
    pub config_id: String,
    pub path: String,
    pub backup_dir: String,
    pub validator: Option<String>,
    pub reload_action: Option<String>,
    pub redact_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServerPolicy {
    pub alias: String,
    pub description: String,
    pub allow_exec: bool,
    pub logs: BTreeMap<String, LogSourcePolicy>,
    pub docker: DockerPolicy,
    pub configs: BTreeMap<String, ConfigFilePolicy>,
    pub sync_targets: BTreeMap<String, SyncTargetPolicy>,
}

#[derive(Debug, Clone)]
pub struct SyncTargetPolicy {
    pub target_id: String,
    pub server: String,
    pub direction: String, // "push" | "pull"
    pub local_base: PathBuf,
    pub remote_base: String,
    pub description: String,
    pub use_rrsync: bool,
    pub allow_delete: bool,
    pub max_delete_files: usize,
    pub max_files: usize,
    pub max_size_mb: u64,
    pub exclude_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct GlobalPolicy {
    pub plan_ttl_seconds: u64,
    pub max_output_bytes: usize,
    pub default_timeout_seconds: u64,
    pub gate_mode: bool,
    pub allow_unlisted_servers: bool,
    pub unlisted_staging_root: PathBuf,
    pub strict_host_key_checking: String,
    pub known_hosts_file: Option<PathBuf>,
    pub global_excludes: Vec<String>,
}

impl Default for GlobalPolicy {
    fn default() -> Self {
        Self {
            plan_ttl_seconds: 180,
            max_output_bytes: 65536,
            default_timeout_seconds: 20,
            gate_mode: true,
            allow_unlisted_servers: false,
            unlisted_staging_root: PathBuf::from("/var/tmp/sshops-staging"),
            strict_host_key_checking: "yes".to_string(),
            known_hosts_file: None,
            global_excludes: default_global_excludes(),
        }
    }
}

pub fn default_global_excludes() -> Vec<String> {
    vec![
        ".git/".to_string(),
        ".env".to_string(),
        ".env.*".to_string(),
        "*.pem".to_string(),
        "*.key".to_string(),
        "node_modules/".to_string(),
        "wp-config.php".to_string(),
    ]
}

#[derive(Debug, Clone)]
pub struct OpsPolicy {
    pub global_cfg: GlobalPolicy,
    pub servers: BTreeMap<String, ServerPolicy>,
}

pub fn home_dir() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME environment variable is not set.".to_string())
}

pub fn expand_path(raw: &str, base_dir: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(rest) = raw.strip_prefix("~/") {
        return Ok(home_dir()?.join(rest));
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        Ok(p)
    } else if let Some(base) = base_dir {
        Ok(base.join(p))
    } else {
        Ok(p)
    }
}

fn ensure_safe_regular_file(
    path: &Path,
    label: &str,
    check_ownership: bool,
) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|_| format!("{label} does not exist or cannot be accessed: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !meta.is_file() {
        return Err(format!("{label} must be a regular file: {}", path.display()));
    }
    if check_ownership {
        let current_uid = unsafe { libc::geteuid() };
        if meta.uid() != current_uid {
            return Err(format!("{label} must be owned by the current daemon user."));
        }
    }
    Ok(())
}

fn strip_literal_quotes(val: &str) -> &str {
    if val.len() >= 2
        && ((val.starts_with('"') && val.ends_with('"'))
            || (val.starts_with('\'') && val.ends_with('\'')))
    {
        &val[1..val.len() - 1]
    } else {
        val
    }
}

fn parse_bool(raw: &str, field: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("Invalid boolean value for '{field}': {raw:?}")),
    }
}

fn validate_alias(val: &str, label: &str) -> Result<(), String> {
    let re = Regex::new(r"^[a-z][a-z0-9_-]{0,31}$").unwrap();
    if !re.is_match(val) {
        return Err(format!("Invalid {label}: {val:?}"));
    }
    Ok(())
}

pub fn validate_id(val: &str, label: &str) -> Result<(), String> {
    let re = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").unwrap();
    if !re.is_match(val) {
        return Err(format!("Invalid {label}: {val:?}"));
    }
    Ok(())
}

pub fn validate_abs_posix(val: &str, label: &str) -> Result<String, String> {
    if !val.starts_with('/') {
        return Err(format!("{label} must be an absolute path: {val:?}"));
    }
    for comp in Path::new(val).components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!("{label} must not contain '..': {val:?}"));
        }
    }
    Ok(val.to_string())
}

/// Block reading or overwriting ultra-sensitive system/credential paths in default_open mode.
pub fn check_not_sensitive_system_path(abs_path: &str) -> Result<(), String> {
    let low = abs_path.to_ascii_lowercase();
    let blocked_exact = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/master.passwd",
    ];
    if blocked_exact.iter().any(|&p| low == p) {
        return Err(format!(
            "Refusing access to sensitive system file: '{abs_path}'"
        ));
    }
    if low.starts_with("/etc/sudoers.d/")
        || low.contains("/.ssh/")
        || low.ends_with("/authorized_keys")
        || low.ends_with("/id_rsa")
        || low.ends_with("/id_ed25519")
        || low.ends_with(".pem")
        || low.ends_with(".key")
    {
        return Err(format!(
            "Refusing access to credential or privilege path: '{abs_path}'"
        ));
    }
    Ok(())
}

pub fn load_daemon_config(
    conf_path: &Path,
    check_ownership: bool,
) -> Result<DaemonConfig, String> {
    ensure_safe_regular_file(conf_path, "Daemon config file", check_ownership)?;
    let content = fs::read_to_string(conf_path)
        .map_err(|e| format!("Failed to read {}: {e}", conf_path.display()))?;

    let allowed = [
        "servers_env",
        "policy",
        "socket",
        "admin_socket",
        "audit_log",
        "socket_group",
        "check_ownership",
    ];
    let mut fields: HashMap<String, String> = HashMap::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.trim_end_matches('\r').trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("Malformed line {lineno} in opsd.conf."));
        };
        let key = k.trim();
        let val = strip_literal_quotes(v.trim());
        if !allowed.contains(&key) {
            return Err(format!("Unsupported key '{key}' at line {lineno} in opsd.conf."));
        }
        if fields.contains_key(key) {
            return Err(format!("Duplicate key '{key}' at line {lineno} in opsd.conf."));
        }
        fields.insert(key.to_string(), val.to_string());
    }

    let servers_env_raw = fields
        .get("servers_env")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "opsd.conf is missing required key 'servers_env'.".to_string())?;
    let policy_raw = fields
        .get("policy")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "opsd.conf is missing required key 'policy'.".to_string())?;

    let base_dir = conf_path.parent();
    let socket_raw = fields
        .get("socket")
        .map(String::as_str)
        .unwrap_or(DEFAULT_SOCKET_PATH);
    let admin_raw = fields
        .get("admin_socket")
        .map(String::as_str)
        .unwrap_or(DEFAULT_ADMIN_SOCKET_PATH);
    let audit_raw = fields
        .get("audit_log")
        .map(String::as_str)
        .unwrap_or("~/.local/state/opsd/audit.jsonl");

    let socket_group = fields
        .get("socket_group")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let check_own = match fields.get("check_ownership") {
        Some(raw) => parse_bool(raw, "check_ownership")?,
        None => false,
    };

    Ok(DaemonConfig {
        servers_env: expand_path(servers_env_raw, base_dir)?,
        policy: expand_path(policy_raw, base_dir)?,
        socket: expand_path(socket_raw, base_dir)?,
        admin_socket: expand_path(admin_raw, base_dir)?,
        audit_log: expand_path(audit_raw, base_dir)?,
        socket_group,
        check_ownership: check_own,
    })
}

pub fn load_server_profiles(
    env_path: &Path,
    check_ownership: bool,
    require_keys_exist: bool,
) -> Result<BTreeMap<String, ServerProfile>, String> {
    ensure_safe_regular_file(env_path, "Server profiles file", check_ownership)?;
    let content = fs::read_to_string(env_path)
        .map_err(|e| format!("Failed to read {}: {e}", env_path.display()))?;

    let section_re = Regex::new(r"^\[([a-z][a-z0-9_-]{0,31})\]\s*$").unwrap();
    let host_re = Regex::new(r"^[A-Za-z0-9:][A-Za-z0-9_.:%-]*$").unwrap();
    let user_re = Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*\$?$").unwrap();

    let mut raw_profiles: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();
    let mut current_alias: Option<String> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.trim_end_matches('\r').trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(caps) = section_re.captures(line) {
            let alias = caps[1].to_string();
            if raw_profiles.contains_key(&alias) {
                return Err(format!("Duplicate server alias '{alias}' at line {lineno}."));
            }
            raw_profiles.insert(alias.clone(), HashMap::new());
            current_alias = Some(alias);
            continue;
        }
        let Some(alias) = current_alias.as_deref() else {
            return Err(format!("Malformed line {lineno} in server profiles file."));
        };
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("Malformed line {lineno} in server profiles file."));
        };
        let key = k.trim();
        let val = strip_literal_quotes(v.trim());
        if !matches!(key, "HOST" | "USER" | "PORT" | "KEY_FILE" | "SYNC_KEY_FILE") {
            return Err(format!("Unsupported field '{key}' at line {lineno}."));
        }
        let entry = raw_profiles.get_mut(alias).unwrap();
        if entry.contains_key(key) {
            return Err(format!(
                "Duplicate field '{key}' in [{alias}] at line {lineno}."
            ));
        }
        entry.insert(key.to_string(), val.to_string());
    }

    let base_dir = env_path.parent();
    let mut profiles = BTreeMap::new();
    for (alias, fields) in raw_profiles {
        for req in ["HOST", "USER", "PORT", "KEY_FILE"] {
            if fields.get(req).map(|s| s.is_empty()).unwrap_or(true) {
                return Err(format!("Server [{alias}] is missing required field '{req}'."));
            }
        }
        let host = fields["HOST"].clone();
        let user = fields["USER"].clone();
        let port_raw = &fields["PORT"];
        if !host_re.is_match(&host) {
            return Err(format!("Invalid HOST format in [{alias}]."));
        }
        if !user_re.is_match(&user) {
            return Err(format!("Invalid USER format in [{alias}]."));
        }
        let port: u16 = port_raw
            .parse::<u16>()
            .ok()
            .filter(|&p| p >= 1)
            .ok_or_else(|| format!("PORT out of range (1-65535) in [{alias}]."))?;

        let key_file = expand_path(&fields["KEY_FILE"], base_dir)?;
        let sync_key_file = match fields.get("SYNC_KEY_FILE") {
            Some(raw) if !raw.is_empty() => Some(expand_path(raw, base_dir)?),
            _ => None,
        };

        if require_keys_exist {
            let kmeta = fs::metadata(&key_file).map_err(|_| {
                format!("KEY_FILE for [{alias}] does not exist or is unreadable.")
            })?;
            if !kmeta.is_file() || kmeta.len() == 0 {
                return Err(format!("KEY_FILE for [{alias}] does not exist or is empty."));
            }
            if let Some(ref sk) = sync_key_file {
                let smeta = fs::metadata(sk).map_err(|_| {
                    format!("SYNC_KEY_FILE for [{alias}] does not exist or is unreadable.")
                })?;
                if !smeta.is_file() || smeta.len() == 0 {
                    return Err(format!(
                        "SYNC_KEY_FILE for [{alias}] does not exist or is empty."
                    ));
                }
            }
        }

        profiles.insert(
            alias.clone(),
            ServerProfile {
                alias,
                host,
                user,
                port,
                key_file,
                sync_key_file,
            },
        );
    }
    Ok(profiles)
}

#[derive(Debug, Deserialize)]
struct RawPolicyRoot {
    #[serde(default)]
    global: RawGlobal,
    #[serde(default)]
    servers: BTreeMap<String, RawServer>,
    #[serde(default)]
    sync_targets: BTreeMap<String, RawSyncTarget>,
}

#[derive(Debug, Deserialize, Default)]
struct RawGlobal {
    plan_ttl_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
    default_timeout_seconds: Option<u64>,
    gate_mode: Option<bool>,
    allow_unlisted_servers: Option<bool>,
    unlisted_staging_root: Option<String>,
    strict_host_key_checking: Option<String>,
    known_hosts_file: Option<String>,
    global_excludes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
struct RawServer {
    #[serde(default)]
    description: String,
    #[serde(default)]
    allow_exec: bool,
    #[serde(default)]
    logs: BTreeMap<String, RawLog>,
    #[serde(default)]
    docker: RawDocker,
    #[serde(default)]
    configs: BTreeMap<String, RawConfig>,
    #[serde(default)]
    sync_targets: BTreeMap<String, RawServerSyncTarget>,
}

#[derive(Debug, Deserialize)]
struct RawServerSyncTarget {
    direction: Option<String>,
    local_base: String,
    remote_base: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    use_rrsync: bool,
    #[serde(default)]
    allow_delete: bool,
    max_delete_files: Option<usize>,
    max_files: Option<usize>,
    max_size_mb: Option<u64>,
    exclude_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLog {
    #[serde(rename = "type")]
    source_type: String,
    path: Option<String>,
    container: Option<String>,
    max_lines: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct RawDocker {
    #[serde(default)]
    allowed_containers: Vec<String>,
    #[serde(default)]
    allowed_compose: BTreeMap<String, RawCompose>,
}

#[derive(Debug, Deserialize)]
struct RawCompose {
    workdir: String,
    #[serde(default)]
    services: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    path: String,
    backup_dir: String,
    validator: Option<String>,
    reload_action: Option<String>,
    #[serde(default)]
    redact_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawSyncTarget {
    server: String,
    direction: Option<String>,
    local_base: String,
    remote_base: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    use_rrsync: bool,
    #[serde(default)]
    allow_delete: bool,
    max_delete_files: Option<usize>,
    max_files: Option<usize>,
    max_size_mb: Option<u64>,
    exclude_file: Option<String>,
}

pub fn load_policy(
    policy_path: &Path,
    known_servers: Option<&HashSet<String>>,
    check_ownership: bool,
) -> Result<OpsPolicy, String> {
    ensure_safe_regular_file(policy_path, "Policy file", check_ownership)?;
    let raw_text = fs::read_to_string(policy_path)
        .map_err(|e| format!("Failed to read policy file: {e}"))?;
    let root: RawPolicyRoot =
        serde_yaml::from_str(&raw_text).map_err(|e| format!("Invalid policy YAML: {e}"))?;

    let shkc = root
        .global
        .strict_host_key_checking
        .unwrap_or_else(|| "yes".to_string());
    if shkc != "yes" && shkc != "accept-new" {
        return Err(
            "global.strict_host_key_checking must be 'yes' or 'accept-new' (never 'no')."
                .to_string(),
        );
    }

    let plan_ttl_seconds = root.global.plan_ttl_seconds.unwrap_or(180);
    if !(10..=3600).contains(&plan_ttl_seconds) {
        return Err("global.plan_ttl_seconds must be between 10 and 3600.".to_string());
    }
    let max_output_bytes = root.global.max_output_bytes.unwrap_or(65536);
    if max_output_bytes < 1024 {
        return Err("global.max_output_bytes must be >= 1024.".to_string());
    }

    let known_hosts_file = match root.global.known_hosts_file {
        Some(ref s) if !s.is_empty() => Some(expand_path(s, None)?),
        _ => None,
    };

    let unlisted_staging_root = match root.global.unlisted_staging_root {
        Some(ref s) if !s.is_empty() => expand_path(s, None)?,
        _ => PathBuf::from("/var/tmp/sshops-staging"),
    };

    let global_cfg = GlobalPolicy {
        plan_ttl_seconds,
        max_output_bytes,
        default_timeout_seconds: root.global.default_timeout_seconds.unwrap_or(20),
        gate_mode: root.global.gate_mode.unwrap_or(true),
        allow_unlisted_servers: root.global.allow_unlisted_servers.unwrap_or(false),
        unlisted_staging_root,
        strict_host_key_checking: shkc,
        known_hosts_file,
        global_excludes: root
            .global
            .global_excludes
            .unwrap_or_else(default_global_excludes),
    };

    let mut servers = BTreeMap::new();
    for (alias, sdata) in root.servers {
        validate_alias(&alias, "server alias")?;
        if let Some(known) = known_servers {
            if !known.contains(&alias) {
                return Err(format!("Policy references unknown server alias '{alias}'."));
            }
        }

        let mut logs = BTreeMap::new();
        for (log_id, ldata) in sdata.logs {
            validate_id(&log_id, "log_id")?;
            let max_lines = ldata.max_lines.unwrap_or(500);
            if !(1..=5000).contains(&max_lines) {
                return Err(format!("max_lines out of range for log '{log_id}'."));
            }
            match ldata.source_type.as_str() {
                "file" => {
                    let lpath = validate_abs_posix(
                        ldata.path.as_deref().unwrap_or(""),
                        &format!("logs.{log_id}.path"),
                    )?;
                    logs.insert(
                        log_id.clone(),
                        LogSourcePolicy {
                            log_id,
                            source_type: "file".to_string(),
                            path: Some(lpath),
                            container: None,
                            max_lines,
                        },
                    );
                }
                "docker" => {
                    let cname = ldata.container.as_deref().unwrap_or("");
                    validate_id(cname, &format!("logs.{log_id}.container"))?;
                    logs.insert(
                        log_id.clone(),
                        LogSourcePolicy {
                            log_id,
                            source_type: "docker".to_string(),
                            path: None,
                            container: Some(cname.to_string()),
                            max_lines,
                        },
                    );
                }
                other => {
                    return Err(format!("Unsupported log type '{other}' for '{log_id}'."));
                }
            }
        }

        for c in &sdata.docker.allowed_containers {
            validate_id(c, "docker container")?;
        }
        let mut allowed_compose = BTreeMap::new();
        for (stack_id, cdata) in sdata.docker.allowed_compose {
            validate_id(&stack_id, "compose stack_id")?;
            let workdir =
                validate_abs_posix(&cdata.workdir, &format!("compose.{stack_id}.workdir"))?;
            if cdata.services.is_empty() {
                return Err(format!(
                    "compose stack '{stack_id}' must declare at least one service."
                ));
            }
            for svc in &cdata.services {
                validate_id(svc, "compose service")?;
            }
            allowed_compose.insert(
                stack_id.clone(),
                ComposeStackPolicy {
                    stack_id,
                    workdir,
                    services: cdata.services,
                },
            );
        }

        let mut configs = BTreeMap::new();
        for (cfg_id, cfgdata) in sdata.configs {
            validate_id(&cfg_id, "config_id")?;
            let cpath = validate_abs_posix(&cfgdata.path, &format!("configs.{cfg_id}.path"))?;
            let bdir =
                validate_abs_posix(&cfgdata.backup_dir, &format!("configs.{cfg_id}.backup_dir"))?;
            if let Some(ref v) = cfgdata.validator {
                validate_id(v, &format!("configs.{cfg_id}.validator"))?;
            }
            if let Some(ref r) = cfgdata.reload_action {
                validate_id(r, &format!("configs.{cfg_id}.reload_action"))?;
            }
            for pat in &cfgdata.redact_patterns {
                Regex::new(pat).map_err(|e| {
                    format!("Invalid regex in configs.{cfg_id}.redact_patterns: {e}")
                })?;
            }
            configs.insert(
                cfg_id.clone(),
                ConfigFilePolicy {
                    config_id: cfg_id,
                    path: cpath,
                    backup_dir: bdir,
                    validator: cfgdata.validator,
                    reload_action: cfgdata.reload_action,
                    redact_patterns: cfgdata.redact_patterns,
                },
            );
        }

        let mut server_sync_targets = BTreeMap::new();
        for (target_id, tdata) in sdata.sync_targets {
            validate_id(&target_id, "sync_target")?;
            let direction = tdata.direction.unwrap_or_else(|| "push".to_string());
            if direction != "push" && direction != "pull" {
                return Err(format!(
                    "sync_target '{target_id}' on '{alias}' direction must be 'push' or 'pull'."
                ));
            }
            if tdata.local_base.trim().is_empty() {
                return Err(format!(
                    "sync_target '{target_id}' on '{alias}' missing local_base."
                ));
            }
            let local_base = expand_path(&tdata.local_base, None)?;
            let remote_base = validate_abs_posix(
                &tdata.remote_base,
                &format!("servers.{alias}.sync_targets.{target_id}.remote_base"),
            )?;
            let exclude_file = match tdata.exclude_file {
                Some(ref s) if !s.is_empty() => Some(expand_path(s, None)?),
                _ => None,
            };
            server_sync_targets.insert(
                target_id.clone(),
                SyncTargetPolicy {
                    target_id,
                    server: alias.clone(),
                    direction,
                    local_base,
                    remote_base,
                    description: tdata.description,
                    use_rrsync: tdata.use_rrsync,
                    allow_delete: tdata.allow_delete,
                    max_delete_files: tdata.max_delete_files.unwrap_or(20),
                    max_files: tdata.max_files.unwrap_or(300),
                    max_size_mb: tdata.max_size_mb.unwrap_or(50),
                    exclude_file,
                },
            );
        }

        servers.insert(
            alias.clone(),
            ServerPolicy {
                alias,
                description: sdata.description,
                allow_exec: sdata.allow_exec,
                logs,
                docker: DockerPolicy {
                    allowed_containers: sdata.docker.allowed_containers,
                    allowed_compose,
                },
                configs,
                sync_targets: server_sync_targets,
            },
        );
    }

    // Backwards-compatible fallback: merge legacy top-level `sync_targets:` into `servers.<alias>.sync_targets`.
    for (target_id, tdata) in root.sync_targets {
        validate_id(&target_id, "sync_target")?;
        validate_alias(&tdata.server, "sync_target server")?;
        if let Some(known) = known_servers {
            if !known.contains(&tdata.server) {
                return Err(format!(
                    "sync_target '{target_id}' references unknown server '{}'.",
                    tdata.server
                ));
            }
        }
        let direction = tdata.direction.unwrap_or_else(|| "push".to_string());
        if direction != "push" && direction != "pull" {
            return Err(format!(
                "sync_target '{target_id}' direction must be 'push' or 'pull'."
            ));
        }
        if tdata.local_base.trim().is_empty() {
            return Err(format!("sync_target '{target_id}' missing local_base."));
        }
        let local_base = expand_path(&tdata.local_base, None)?;
        let remote_base = validate_abs_posix(
            &tdata.remote_base,
            &format!("sync_targets.{target_id}.remote_base"),
        )?;
        let exclude_file = match tdata.exclude_file {
            Some(ref s) if !s.is_empty() => Some(expand_path(s, None)?),
            _ => None,
        };
        let srv_entry = servers
            .entry(tdata.server.clone())
            .or_insert_with(|| ServerPolicy {
                alias: tdata.server.clone(),
                description: String::new(),
                allow_exec: false,
                logs: BTreeMap::new(),
                docker: DockerPolicy::default(),
                configs: BTreeMap::new(),
                sync_targets: BTreeMap::new(),
            });
        if srv_entry.sync_targets.contains_key(&target_id) {
            return Err(format!(
                "Duplicate sync_target '{target_id}' for server '{}'.",
                tdata.server
            ));
        }
        srv_entry.sync_targets.insert(
            target_id.clone(),
            SyncTargetPolicy {
                target_id,
                server: tdata.server,
                direction,
                local_base,
                remote_base,
                description: tdata.description,
                use_rrsync: tdata.use_rrsync,
                allow_delete: tdata.allow_delete,
                max_delete_files: tdata.max_delete_files.unwrap_or(20),
                max_files: tdata.max_files.unwrap_or(300),
                max_size_mb: tdata.max_size_mb.unwrap_or(50),
                exclude_file,
            },
        );
    }

    Ok(OpsPolicy {
        global_cfg,
        servers,
    })
}
