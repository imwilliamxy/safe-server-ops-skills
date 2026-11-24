"""L2 two-phase rsync deployment executor with symlink scan, TOCTOU manifest hash, and delete fuse."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

from ..config import OpsPolicy, ServerProfile, SyncTargetPolicy
from ..planner import PlanStore
from ..redactor import Redactor, truncate_output
from .ssh_exec import ExecutionError, SSHExecutor


class RsyncSecurityError(ExecutionError):
    """Raised when local staging fails symlink, size, file-count, delete-fuse, or TOCTOU checks."""


def _load_exclude_patterns(policy: OpsPolicy, target: SyncTargetPolicy) -> list[str]:
    patterns: list[str] = list(policy.global_cfg.global_excludes)
    if target.exclude_file is not None and target.exclude_file.is_file():
        for raw in target.exclude_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    # Preserve order while deduplicating
    seen: set[str] = set()
    unique: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def _is_excluded(rel_posix: str, is_dir: bool, patterns: list[str]) -> bool:
    parts = rel_posix.split("/")
    name = parts[-1]
    for pat in patterns:
        clean = pat.rstrip("/")
        if pat.endswith("/"):
            # Directory rule matches any path component equal to clean
            if is_dir and (fnmatch.fnmatch(name, clean) or fnmatch.fnmatch(rel_posix, clean)):
                return True
            if any(fnmatch.fnmatch(part, clean) for part in parts[:-1]):
                return True
        else:
            if (
                fnmatch.fnmatch(name, pat)
                or fnmatch.fnmatch(rel_posix, pat)
                or any(fnmatch.fnmatch(part, pat) for part in parts)
            ):
                return True
    return False


def scan_and_fingerprint(
    local_base: Path,
    exclude_patterns: list[str],
    *,
    max_files: int,
    max_size_mb: int,
) -> tuple[str, int, int]:
    """Scan local staging dir for escaping symlinks, enforce limits, and compute Manifest SHA256.

    Returns (manifest_sha256, file_count, total_bytes).
    """
    if local_base.is_symlink():
        raise RsyncSecurityError("Staging directory local_base must not be a symlink.")
    if not local_base.is_dir():
        raise RsyncSecurityError(f"Staging directory does not exist: {local_base}")

    resolved_base = local_base.resolve()
    entries: list[tuple[str, Path, bool]] = []

    for root, dirs, files in os.walk(resolved_base, followlinks=False):
        root_path = Path(root)
        # Filter excluded directories in-place (and check dir symlinks!)
        kept_dirs: list[str] = []
        for d in sorted(dirs):
            dpath = root_path / d
            rel = dpath.relative_to(resolved_base).as_posix()
            if dpath.is_symlink():
                target_real = Path(os.path.realpath(dpath))
                if not target_real.is_relative_to(resolved_base):
                    raise RsyncSecurityError(
                        f"Refusing sync: directory symlink '{rel}' points outside staging root."
                    )
                if not _is_excluded(rel, True, exclude_patterns):
                    entries.append((rel, dpath, True))
                continue
            if _is_excluded(rel, True, exclude_patterns):
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in sorted(files):
            fpath = root_path / fname
            rel = fpath.relative_to(resolved_base).as_posix()
            if fpath.is_symlink():
                target_real = Path(os.path.realpath(fpath))
                if not target_real.is_relative_to(resolved_base):
                    raise RsyncSecurityError(
                        f"Refusing sync: file symlink '{rel}' points outside staging root."
                    )
                if not _is_excluded(rel, False, exclude_patterns):
                    entries.append((rel, fpath, True))
                continue
            if _is_excluded(rel, False, exclude_patterns):
                continue
            if fpath.is_file():
                entries.append((rel, fpath, False))

    entries.sort(key=lambda item: item[0])

    if len(entries) > max_files:
        raise RsyncSecurityError(
            f"Refusing sync: {len(entries)} files exceeds max_files limit ({max_files})."
        )

    max_bytes = max_size_mb * 1024 * 1024
    total_bytes = 0
    digest = hashlib.sha256()

    for rel, fpath, is_link in entries:
        digest.update(rel.encode("utf-8") + b"\x00")
        if is_link:
            link_target = os.readlink(fpath)
            digest.update(b"L:" + link_target.encode("utf-8") + b"\x00")
        else:
            st = fpath.stat()
            total_bytes += st.st_size
            if total_bytes > max_bytes:
                raise RsyncSecurityError(
                    f"Refusing sync: total size exceeds max_size_mb limit ({max_size_mb} MiB)."
                )
            file_hash = hashlib.sha256()
            with fpath.open("rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    file_hash.update(chunk)
            digest.update(b"F:" + file_hash.hexdigest().encode("ascii") + b"\x00")

    return digest.hexdigest(), len(entries), total_bytes


def parse_itemize_changes(stdout: str) -> dict[str, list[str]]:
    """Parse rsync --itemize-changes output into added, modified, and deleted path lists."""
    added: list[str] = []
    modified: list[str] = []
    deleted: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("*deleting "):
            deleted.append(line[len("*deleting "):].strip())
            continue
        # Standard itemize format: 11-char code + single space + path (e.g. '>f+++++++++ foo.php')
        if len(line) > 12 and line[11] == " " and line[0] in {"<", ">", "c", "h", "."}:
            code = line[:11]
            rel_path = line[12:]
            if code[1] == "d":
                continue  # skip directory timestamp updates
            if "+++++++++" in code:
                added.append(rel_path)
            elif code[0] in {"<", ">", "c", "h"}:
                modified.append(rel_path)
    return {"added": added, "modified": modified, "deleted": deleted}


def _build_rsync_argv(
    *,
    ssh: SSHExecutor,
    profile: ServerProfile,
    target: SyncTargetPolicy,
    exclude_file_path: Path,
    dry_run: bool,
) -> list[str]:
    rsh_cmd = ssh.build_rsh_string(profile, use_sync_key=True)
    remote_path = "." if target.use_rrsync else target.remote_base.rstrip("/") + "/"
    local_path = str(target.local_base).rstrip("/") + "/"
    remote_spec = f"{profile.user}@{profile.host}:{remote_path}"

    argv = [
        "rsync",
        "-rltz",
        "--no-owner",
        "--no-group",
        "--no-perms",
        "--no-devices",
        "--no-specials",
        "--safe-links",
        "--itemize-changes",
        "--stats",
        "--timeout=30",
        "-e",
        rsh_cmd,
        f"--exclude-from={exclude_file_path}",
    ]
    if dry_run:
        argv.append("--dry-run")
    if target.allow_delete:
        argv.append("--delete")
    argv.append("--")
    if target.direction == "push":
        argv.extend([local_path, remote_spec])
    else:
        argv.extend([remote_spec, local_path])
    return argv


def _run_rsync_with_temp_excludes(
    *,
    ssh: SSHExecutor,
    profile: ServerProfile,
    target: SyncTargetPolicy,
    patterns: list[str],
    dry_run: bool,
    timeout: int,
):
    fd, tmp_path_str = tempfile.mkstemp(prefix="opsd-excl-", text=True)
    tmp_path = Path(tmp_path_str)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for pat in patterns:
                fh.write(pat + "\n")
        argv = _build_rsync_argv(
            ssh=ssh,
            profile=profile,
            target=target,
            exclude_file_path=tmp_path,
            dry_run=dry_run,
        )
        return ssh.run_local(argv, timeout=timeout)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def rsync_preview(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    target_id: str,
) -> dict[str, Any]:
    """Run symlink scan, size check, rsync --dry-run, delete circuit breaker, and issue Plan Token."""
    target = policy.sync_targets.get(target_id)
    if target is None:
        raise ExecutionError(f"Unknown or unpermitted sync_target: '{target_id}'")
    profile = profiles.get(target.server)
    if profile is None:
        raise ExecutionError(f"Server profile '{target.server}' not found for target '{target_id}'.")

    patterns = _load_exclude_patterns(policy, target)
    manifest_sha = ""
    local_file_count = 0
    local_total_bytes = 0

    if target.direction == "push":
        manifest_sha, local_file_count, local_total_bytes = scan_and_fingerprint(
            target.local_base,
            patterns,
            max_files=target.max_files,
            max_size_mb=target.max_size_mb,
        )
    else:
        target.local_base.mkdir(parents=True, exist_ok=True)

    res = _run_rsync_with_temp_excludes(
        ssh=ssh,
        profile=profile,
        target=target,
        patterns=patterns,
        dry_run=True,
        timeout=max(45, policy.global_cfg.default_timeout_seconds),
    )

    extra_literals = [
        (target.remote_base, "[TARGET_REMOTE_ROOT]"),
        (str(target.local_base), "[TARGET_LOCAL_ROOT]"),
    ]
    safe_stdout = truncate_output(
        redactor.redact(res.stdout, active_profile=profile, extra_literals=extra_literals),
        policy.global_cfg.max_output_bytes,
    )
    safe_stderr = truncate_output(
        redactor.redact(res.stderr, active_profile=profile, extra_literals=extra_literals),
        min(8192, policy.global_cfg.max_output_bytes),
    )

    if res.exit_code != 0:
        raise ExecutionError(
            f"rsync preview failed (exit_code={res.exit_code}): {safe_stderr or safe_stdout}"
        )

    changes = parse_itemize_changes(res.stdout)
    deleted_count = len(changes["deleted"])
    if target.allow_delete and deleted_count > 0:
        if deleted_count > target.max_delete_files:
            raise RsyncSecurityError(
                f"Delete circuit breaker triggered: {deleted_count} deletions exceed max_delete_files ({target.max_delete_files})."
            )
        if local_file_count > 0 and (deleted_count / max(1, local_file_count + deleted_count)) > 0.30:
            raise RsyncSecurityError(
                f"Delete circuit breaker triggered: {deleted_count} deletions exceed 30% of files."
            )

    summary = (
        f"rsync {target.direction} '{target_id}' -> '{target.server}': "
        f"+{len(changes['added'])} added, ~{len(changes['modified'])} modified, "
        f"-{deleted_count} deleted (local files={local_file_count}, bytes={local_total_bytes})"
    )
    diff_lines = (
        [f"+ {p}" for p in changes["added"]]
        + [f"~ {p}" for p in changes["modified"]]
        + [f"- {p}" for p in changes["deleted"]]
    )
    diff_text = truncate_output(
        redactor.redact("\n".join(diff_lines), active_profile=profile, extra_literals=extra_literals),
        16384,
    )

    plan = planner.create(
        kind="rsync_sync",
        server=target.server,
        target=target_id,
        reason=f"rsync {target.direction} {target_id}",
        summary=summary,
        diff=diff_text,
        payload={
            "target_id": target_id,
            "manifest_sha256": manifest_sha,
            "local_file_count": local_file_count,
            "local_total_bytes": local_total_bytes,
            "exclude_patterns": patterns,
        },
    )

    out = plan.to_public_dict(include_diff=True)
    out["direction"] = target.direction
    out["manifest_sha256"] = manifest_sha
    out["changes"] = changes
    out["preview_output"] = safe_stdout
    return out


def rsync_apply(
    *,
    policy: OpsPolicy,
    profiles: dict[str, ServerProfile],
    ssh: SSHExecutor,
    redactor: Redactor,
    planner: PlanStore,
    plan_token: str,
) -> dict[str, Any]:
    """Consume an APPROVED rsync plan, re-verify TOCTOU manifest hash, and execute sync."""
    plan = planner.consume_approved(plan_token, expected_kind="rsync_sync")
    target_id = str(plan.payload["target_id"])
    target = policy.sync_targets[target_id]
    profile = profiles[target.server]
    patterns = list(plan.payload["exclude_patterns"])

    if target.direction == "push":
        current_sha, _, _ = scan_and_fingerprint(
            target.local_base,
            patterns,
            max_files=target.max_files,
            max_size_mb=target.max_size_mb,
        )
        expected_sha = str(plan.payload["manifest_sha256"])
        if current_sha != expected_sha:
            raise RsyncSecurityError(
                "TOCTOU check failed: staging directory changed after rsync preview. Please re-run rsync preview."
            )

    res = _run_rsync_with_temp_excludes(
        ssh=ssh,
        profile=profile,
        target=target,
        patterns=patterns,
        dry_run=False,
        timeout=max(120, policy.global_cfg.default_timeout_seconds),
    )

    extra_literals = [
        (target.remote_base, "[TARGET_REMOTE_ROOT]"),
        (str(target.local_base), "[TARGET_LOCAL_ROOT]"),
    ]
    safe_stdout = truncate_output(
        redactor.redact(res.stdout, active_profile=profile, extra_literals=extra_literals),
        policy.global_cfg.max_output_bytes,
    )
    safe_stderr = truncate_output(
        redactor.redact(res.stderr, active_profile=profile, extra_literals=extra_literals),
        min(8192, policy.global_cfg.max_output_bytes),
    )
    changes = parse_itemize_changes(res.stdout)

    return {
        "plan_token": plan.token,
        "approved_by": plan.approved_by,
        "server": target.server,
        "target": target_id,
        "direction": target.direction,
        "manifest_sha256": plan.payload["manifest_sha256"],
        "exit_code": res.exit_code,
        "changes": changes,
        "stdout": safe_stdout,
        "stderr": safe_stderr,
    }
