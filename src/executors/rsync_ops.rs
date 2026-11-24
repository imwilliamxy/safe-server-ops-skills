//! L2 two-phase rsync deployment executor with symlink escape scan, TOCTOU manifest hash, and delete fuse.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{
    check_not_sensitive_system_path, validate_abs_posix, OpsPolicy, ServerProfile, SyncTargetPolicy,
};
use crate::executors::logs::{resolve_server_access, ServerAccess};
use crate::executors::ssh_exec::{CommandResult, SSHExecutor};
use crate::planner::{PlanPayload, PlanStore};
use crate::redactor::{truncate_output, Redactor};

/// Simple wildcard matcher supporting '*' and '?' (compatible with basic rsync/fnmatch patterns).
fn glob_match(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(s) = star_idx {
            pi = s + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn load_exclude_patterns(policy: &OpsPolicy, exclude_file: Option<&Path>) -> Vec<String> {
    let mut patterns = policy.global_cfg.global_excludes.clone();
    if let Some(ex_path) = exclude_file {
        if let Ok(text) = fs::read_to_string(ex_path) {
            for raw in text.lines() {
                let line = raw.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    patterns.push(line.to_string());
                }
            }
        }
    }
    let mut seen = HashSet::new();
    patterns.retain(|p| seen.insert(p.clone()));
    patterns
}

fn is_excluded(rel_posix: &str, is_dir: bool, patterns: &[String]) -> bool {
    let parts: Vec<&str> = rel_posix.split('/').collect();
    let name = *parts.last().unwrap_or(&"");
    for pat in patterns {
        let clean = pat.trim_end_matches('/');
        if pat.ends_with('/') {
            if is_dir && (glob_match(name, clean) || glob_match(rel_posix, clean)) {
                return true;
            }
            if parts.len() > 1 && parts[..parts.len() - 1].iter().any(|p| glob_match(p, clean)) {
                return true;
            }
        } else if glob_match(name, pat)
            || glob_match(rel_posix, pat)
            || parts.iter().any(|p| glob_match(p, pat))
        {
            return true;
        }
    }
    false
}

fn walk_dir_safe(
    resolved_base: &Path,
    current: &Path,
    patterns: &[String],
    out: &mut Vec<(String, PathBuf, bool)>,
) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(current)
        .map_err(|e| format!("Failed to scan staging directory: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to read staging directory entry: {e}"))?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Failed to stat staging entry: {e}"))?;
        let rel = path
            .strip_prefix(resolved_base)
            .map_err(|e| format!("Path prefix error: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");

        if meta.file_type().is_symlink() {
            let target_real = fs::canonicalize(&path).map_err(|_| {
                format!("Refusing sync: broken or unreadable symlink '{rel}' in staging root.")
            })?;
            if !target_real.starts_with(resolved_base) {
                return Err(format!(
                    "Refusing sync: symlink '{rel}' points outside staging root."
                ));
            }
            if !is_excluded(&rel, target_real.is_dir(), patterns) {
                out.push((rel, path, true));
            }
            continue;
        }

        if meta.is_dir() {
            if is_excluded(&rel, true, patterns) {
                continue;
            }
            walk_dir_safe(resolved_base, &path, patterns, out)?;
        } else if meta.is_file() {
            if is_excluded(&rel, false, patterns) {
                continue;
            }
            out.push((rel, path, false));
        }
    }
    Ok(())
}

pub fn scan_and_fingerprint(
    local_base: &Path,
    exclude_patterns: &[String],
    max_files: usize,
    max_size_mb: u64,
) -> Result<(String, usize, u64), String> {
    let base_meta = fs::symlink_metadata(local_base)
        .map_err(|_| format!("Staging directory does not exist: {}", local_base.display()))?;
    if base_meta.file_type().is_symlink() {
        return Err("Staging directory local_base must not be a symlink.".to_string());
    }
    if !base_meta.is_dir() {
        return Err(format!(
            "Staging directory is not a directory: {}",
            local_base.display()
        ));
    }

    let resolved_base = fs::canonicalize(local_base)
        .map_err(|e| format!("Failed to resolve staging directory: {e}"))?;

    let mut entries = Vec::new();
    walk_dir_safe(&resolved_base, &resolved_base, exclude_patterns, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    if entries.len() > max_files {
        return Err(format!(
            "Refusing sync: {} files exceeds max_files limit ({max_files}).",
            entries.len()
        ));
    }

    let max_bytes = max_size_mb.saturating_mul(1024 * 1024);
    let mut total_bytes: u64 = 0;
    let mut manifest = Sha256::new();
    let mut buf = [0u8; 65536];

    for (rel, path, is_link) in &entries {
        manifest.update(rel.as_bytes());
        manifest.update([0u8]);
        if *is_link {
            let link_target = fs::read_link(path)
                .map_err(|e| format!("Failed to read symlink '{rel}': {e}"))?;
            manifest.update(b"L:");
            manifest.update(link_target.to_string_lossy().as_bytes());
            manifest.update([0u8]);
        } else {
            let meta = fs::metadata(path)
                .map_err(|e| format!("Failed to stat file '{rel}': {e}"))?;
            total_bytes = total_bytes.saturating_add(meta.len());
            if total_bytes > max_bytes {
                return Err(format!(
                    "Refusing sync: total size exceeds max_size_mb limit ({max_size_mb} MiB)."
                ));
            }
            let mut fhash = Sha256::new();
            let mut fh = File::open(path)
                .map_err(|e| format!("Failed to read file '{rel}': {e}"))?;
            loop {
                let n = fh
                    .read(&mut buf)
                    .map_err(|e| format!("Failed to hash file '{rel}': {e}"))?;
                if n == 0 {
                    break;
                }
                fhash.update(&buf[..n]);
            }
            manifest.update(b"F:");
            manifest.update(hex::encode(fhash.finalize()).as_bytes());
            manifest.update([0u8]);
        }
    }

    Ok((hex::encode(manifest.finalize()), entries.len(), total_bytes))
}

pub fn parse_itemize_changes(stdout: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();

    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("*deleting ") {
            deleted.push(rest.trim().to_string());
            continue;
        }
        let bytes = line.as_bytes();
        if bytes.len() > 12
            && bytes[11] == b' '
            && matches!(bytes[0], b'<' | b'>' | b'c' | b'h' | b'.')
        {
            let code = &line[..11];
            let rel_path = line[12..].to_string();
            if bytes[1] == b'd' {
                continue;
            }
            if code.contains("+++++++++") {
                added.push(rel_path);
            } else if matches!(bytes[0], b'<' | b'>' | b'c' | b'h') {
                modified.push(rel_path);
            }
        }
    }
    (added, modified, deleted)
}

struct TempFileGuard(PathBuf);
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn create_temp_excludes(patterns: &[String]) -> Result<TempFileGuard, String> {
    let mut rand_bytes = [0u8; 8];
    getrandom::getrandom(&mut rand_bytes)
        .map_err(|e| format!("Failed to generate temp exclude filename: {e}"))?;
    let tmp_path = std::env::temp_dir().join(format!("opsd-excl-{}.txt", hex::encode(rand_bytes)));
    let mut fh = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create temp exclude file: {e}"))?;
    for pat in patterns {
        writeln!(fh, "{pat}").map_err(|e| format!("Failed to write temp exclude file: {e}"))?;
    }
    Ok(TempFileGuard(tmp_path))
}

#[allow(clippy::too_many_arguments)]
fn build_rsync_argv(
    ssh: &SSHExecutor,
    profile: &ServerProfile,
    direction: &str,
    local_base: &Path,
    remote_base: &str,
    use_rrsync: bool,
    allow_delete: bool,
    exclude_file: &Path,
    dry_run: bool,
) -> Vec<String> {
    let rsh_cmd = ssh.build_rsh_string(profile, true);
    let remote_path = if use_rrsync {
        ".".to_string()
    } else {
        format!("{}/", remote_base.trim_end_matches('/'))
    };
    let local_path = format!("{}/", local_base.to_string_lossy().trim_end_matches('/'));
    let remote_spec = format!("{}@{}:{}", profile.user, profile.host, remote_path);

    let mut argv = vec![
        "rsync".to_string(),
        "-rltz".to_string(),
        "--no-owner".to_string(),
        "--no-group".to_string(),
        "--no-perms".to_string(),
        "--no-devices".to_string(),
        "--no-specials".to_string(),
        "--safe-links".to_string(),
        "--itemize-changes".to_string(),
        "--stats".to_string(),
        "--timeout=30".to_string(),
        "-e".to_string(),
        rsh_cmd,
        format!("--exclude-from={}", exclude_file.display()),
    ];
    if dry_run {
        argv.push("--dry-run".to_string());
    }
    if allow_delete {
        argv.push("--delete".to_string());
    }
    argv.push("--".to_string());
    if direction == "push" {
        argv.push(local_path);
        argv.push(remote_spec);
    } else {
        argv.push(remote_spec);
        argv.push(local_path);
    }
    argv
}

#[allow(clippy::too_many_arguments)]
fn run_rsync_with_excludes(
    ssh: &SSHExecutor,
    profile: &ServerProfile,
    direction: &str,
    local_base: &Path,
    remote_base: &str,
    use_rrsync: bool,
    allow_delete: bool,
    patterns: &[String],
    dry_run: bool,
    timeout: u64,
) -> Result<CommandResult, String> {
    let guard = create_temp_excludes(patterns)?;
    let argv = build_rsync_argv(
        ssh,
        profile,
        direction,
        local_base,
        remote_base,
        use_rrsync,
        allow_delete,
        &guard.0,
        dry_run,
    );
    Ok(ssh.run_local(&argv, None, Some(timeout)))
}

struct EffectiveRsyncSpec {
    target_id: Option<String>,
    label: String,
    server: String,
    direction: String,
    local_base: PathBuf,
    remote_base: String,
    use_rrsync: bool,
    allow_delete: bool,
    max_delete_files: usize,
    max_files: usize,
    max_size_mb: u64,
    exclude_file: Option<PathBuf>,
}

fn preview_with_spec(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    spec: EffectiveRsyncSpec,
) -> Result<Value, String> {
    let profile = profiles.get(&spec.server).ok_or_else(|| {
        format!(
            "Server profile '{}' not found for target '{}'.",
            spec.server, spec.label
        )
    })?;

    let patterns = load_exclude_patterns(policy, spec.exclude_file.as_deref());
    let (manifest_sha, local_file_count, local_total_bytes) = if spec.direction == "push" {
        scan_and_fingerprint(
            &spec.local_base,
            &patterns,
            spec.max_files,
            spec.max_size_mb,
        )?
    } else {
        fs::create_dir_all(&spec.local_base)
            .map_err(|e| format!("Failed to prepare pull directory: {e}"))?;
        (String::new(), 0usize, 0u64)
    };

    let timeout = policy.global_cfg.default_timeout_seconds.max(45);
    let res = run_rsync_with_excludes(
        ssh,
        profile,
        &spec.direction,
        &spec.local_base,
        &spec.remote_base,
        spec.use_rrsync,
        spec.allow_delete,
        &patterns,
        true,
        timeout,
    )?;

    let local_str = spec.local_base.to_string_lossy().into_owned();
    let extra = [
        (spec.remote_base.as_str(), "[TARGET_REMOTE_ROOT]"),
        (local_str.as_str(), "[TARGET_LOCAL_ROOT]"),
    ];

    let safe_stdout = truncate_output(
        &redactor.redact(&res.stdout, Some(profile), &extra),
        policy.global_cfg.max_output_bytes,
    );
    let safe_stderr = truncate_output(
        &redactor.redact(&res.stderr, Some(profile), &extra),
        policy.global_cfg.max_output_bytes.min(8192),
    );

    if res.exit_code != 0 {
        let msg = if !safe_stderr.is_empty() {
            safe_stderr
        } else {
            safe_stdout
        };
        return Err(format!(
            "rsync preview failed (exit_code={}): {msg}",
            res.exit_code
        ));
    }

    let (added, modified, deleted) = parse_itemize_changes(&res.stdout);
    let deleted_count = deleted.len();
    if spec.allow_delete && deleted_count > 0 {
        if deleted_count > spec.max_delete_files {
            return Err(format!(
                "Delete circuit breaker triggered: {deleted_count} deletions exceed max_delete_files ({}).",
                spec.max_delete_files
            ));
        }
        if local_file_count > 0
            && (deleted_count as f64 / (local_file_count + deleted_count).max(1) as f64) > 0.30
        {
            return Err(format!(
                "Delete circuit breaker triggered: {deleted_count} deletions exceed 30% of files."
            ));
        }
    }

    let summary = format!(
        "rsync {} '{}' -> '{}': +{} added, ~{} modified, -{} deleted (local files={}, bytes={})",
        spec.direction,
        spec.label,
        spec.server,
        added.len(),
        modified.len(),
        deleted_count,
        local_file_count,
        local_total_bytes
    );

    let mut diff_lines = Vec::new();
    for p in &added {
        diff_lines.push(format!("+ {p}"));
    }
    for p in &modified {
        diff_lines.push(format!("~ {p}"));
    }
    for p in &deleted {
        diff_lines.push(format!("- {p}"));
    }
    let diff_text = truncate_output(
        &redactor.redact(&diff_lines.join("\n"), Some(profile), &extra),
        16384,
    );

    let plan = planner.create(
        spec.server.clone(),
        spec.label.clone(),
        format!("rsync {} {}", spec.direction, spec.label),
        summary,
        diff_text,
        PlanPayload::RsyncSync {
            target_id: spec.target_id,
            server: spec.server,
            direction: spec.direction.clone(),
            local_base: spec.local_base,
            remote_base: spec.remote_base,
            use_rrsync: spec.use_rrsync,
            allow_delete: spec.allow_delete,
            max_files: spec.max_files,
            max_size_mb: spec.max_size_mb,
            manifest_sha256: manifest_sha.clone(),
            local_file_count,
            local_total_bytes,
            exclude_patterns: patterns,
        },
    )?;

    let mut out = plan.to_public_json(true);
    out["direction"] = Value::String(spec.direction);
    out["manifest_sha256"] = Value::String(manifest_sha);
    out["changes"] = json!({
        "added": added,
        "modified": modified,
        "deleted": deleted,
    });
    out["preview_output"] = Value::String(safe_stdout);
    Ok(out)
}

pub fn rsync_preview(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    server: &str,
    target_id: &str,
) -> Result<Value, String> {
    let spol = policy
        .servers
        .get(server)
        .ok_or_else(|| format!("Unknown or unpermitted server alias: '{server}'"))?;
    let target: &SyncTargetPolicy = spol.sync_targets.get(target_id).ok_or_else(|| {
        format!("Sync target '{target_id}' is not declared under server '{server}'.")
    })?;
    let spec = EffectiveRsyncSpec {
        target_id: Some(target.target_id.clone()),
        label: target.target_id.clone(),
        server: target.server.clone(),
        direction: target.direction.clone(),
        local_base: target.local_base.clone(),
        remote_base: target.remote_base.clone(),
        use_rrsync: target.use_rrsync,
        allow_delete: target.allow_delete,
        max_delete_files: target.max_delete_files,
        max_files: target.max_files,
        max_size_mb: target.max_size_mb,
        exclude_file: target.exclude_file.clone(),
    };
    preview_with_spec(policy, profiles, ssh, redactor, planner, spec)
}

#[allow(clippy::too_many_arguments)]
pub fn rsync_preview_dynamic(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    server: &str,
    local_path_raw: &str,
    remote_base_raw: &str,
    direction: &str,
    allow_delete: bool,
) -> Result<Value, String> {
    match resolve_server_access(policy, profiles, server)? {
        ServerAccess::DefaultOpen(_) => {}
        ServerAccess::Restricted(_, _) => {
            return Err(format!(
                "Server '{server}' is in restricted policy mode; declare a sync_target in policy.yaml instead of dynamic rsync."
            ));
        }
    }
    if direction != "push" && direction != "pull" {
        return Err("direction must be 'push' or 'pull'.".to_string());
    }
    let remote_base = validate_abs_posix(remote_base_raw, "remote_base")?;
    check_not_sensitive_system_path(&remote_base)?;

    // Enforce that dynamic local_base stays strictly inside unlisted_staging_root!
    let staging_root = &policy.global_cfg.unlisted_staging_root;
    let resolved_root = fs::canonicalize(staging_root).map_err(|_| {
        format!(
            "unlisted_staging_root does not exist: {}",
            staging_root.display()
        )
    })?;

    let req_path = Path::new(local_path_raw);
    for comp in req_path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err("Dynamic rsync local path must not contain '..'.".to_string());
        }
    }
    let candidate = if req_path.is_absolute() {
        req_path.to_path_buf()
    } else {
        resolved_root.join(req_path)
    };
    if direction == "pull" && !candidate.exists() {
        fs::create_dir_all(&candidate)
            .map_err(|e| format!("Failed to create staging pull subdir: {e}"))?;
    }
    let resolved_local = fs::canonicalize(&candidate).map_err(|_| {
        format!(
            "Dynamic rsync local directory does not exist: {}",
            candidate.display()
        )
    })?;
    if !resolved_local.starts_with(&resolved_root) {
        return Err(format!(
            "Refusing dynamic rsync: local path must stay inside unlisted_staging_root ({}).",
            staging_root.display()
        ));
    }

    let label = format!("dynamic:{server}:{remote_base}");
    let spec = EffectiveRsyncSpec {
        target_id: None,
        label,
        server: server.to_string(),
        direction: direction.to_string(),
        local_base: resolved_local,
        remote_base,
        use_rrsync: false,
        allow_delete,
        max_delete_files: 20,
        max_files: 300,
        max_size_mb: 50,
        exclude_file: None,
    };
    preview_with_spec(policy, profiles, ssh, redactor, planner, spec)
}

pub fn rsync_apply(
    policy: &OpsPolicy,
    profiles: &BTreeMap<String, ServerProfile>,
    ssh: &SSHExecutor,
    redactor: &Redactor,
    planner: &PlanStore,
    plan_token: &str,
) -> Result<Value, String> {
    let plan = planner.consume_approved(plan_token, "rsync_sync")?;
    let (
        target_id,
        server,
        direction,
        local_base,
        remote_base,
        use_rrsync,
        allow_delete,
        max_files,
        max_size_mb,
        expected_sha,
        patterns,
    ) = match plan.payload {
        PlanPayload::RsyncSync {
            target_id,
            server,
            direction,
            local_base,
            remote_base,
            use_rrsync,
            allow_delete,
            max_files,
            max_size_mb,
            manifest_sha256,
            exclude_patterns,
            ..
        } => (
            target_id,
            server,
            direction,
            local_base,
            remote_base,
            use_rrsync,
            allow_delete,
            max_files,
            max_size_mb,
            manifest_sha256,
            exclude_patterns,
        ),
        _ => return Err("Unexpected plan payload for rsync_sync.".to_string()),
    };

    let profile = profiles
        .get(&server)
        .ok_or_else(|| format!("Unknown server '{server}'."))?;

    if direction == "push" {
        let (current_sha, _, _) =
            scan_and_fingerprint(&local_base, &patterns, max_files, max_size_mb)?;
        if current_sha != expected_sha {
            return Err(
                "TOCTOU check failed: staging directory changed after rsync preview. Please re-run rsync preview."
                    .to_string(),
            );
        }
    }

    let timeout = policy.global_cfg.default_timeout_seconds.max(120);
    let res = run_rsync_with_excludes(
        ssh,
        profile,
        &direction,
        &local_base,
        &remote_base,
        use_rrsync,
        allow_delete,
        &patterns,
        false,
        timeout,
    )?;

    let local_str = local_base.to_string_lossy().into_owned();
    let extra = [
        (remote_base.as_str(), "[TARGET_REMOTE_ROOT]"),
        (local_str.as_str(), "[TARGET_LOCAL_ROOT]"),
    ];
    let safe_stdout = truncate_output(
        &redactor.redact(&res.stdout, Some(profile), &extra),
        policy.global_cfg.max_output_bytes,
    );
    let safe_stderr = truncate_output(
        &redactor.redact(&res.stderr, Some(profile), &extra),
        policy.global_cfg.max_output_bytes.min(8192),
    );
    let (added, modified, deleted) = parse_itemize_changes(&res.stdout);

    Ok(json!({
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": server,
        "target": target_id.unwrap_or_else(|| plan.target.clone()),
        "direction": direction,
        "manifest_sha256": expected_sha,
        "exit_code": res.exit_code,
        "changes": {
            "added": added,
            "modified": modified,
            "deleted": deleted,
        },
        "stdout": safe_stdout,
        "stderr": safe_stderr,
    }))
}
