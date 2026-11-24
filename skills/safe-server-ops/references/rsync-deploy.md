# Safe `rsync` Deployment Workflow (L2)

Production file syncs use pre-declared `sync_targets` managed by `opsd`. You never specify remote hosts, remote absolute paths, or raw `rsync` flags.

## Step 1: Prepare Artifacts in the Staging Directory

1. Run `opsctl capabilities` to inspect the `sync_targets` list and confirm the target name and direction (`push` or `pull`).
2. Build and place only the final release artifacts into the target's configured staging directory (`local_base`).
3. **Never** put symlinks pointing outside the staging directory, `.git/`, `.env`, or private keys inside the staging directory—`opsd` will scan and reject escaping symlinks and always enforce global excludes.

## Step 2: Dry-Run Preview

```bash
# Pre-declared sync_target under a server
opsctl rsync preview prod-web-1 wp-plugin-release

# Or dynamic rsync on a default_open server (local must stay inside unlisted_staging_root)
opsctl rsync preview <server> --local <staging_subdir> --remote /var/www/my-app
```

`opsd` will:
- Scan for escaping symlinks and enforce `max_files` / `max_size_mb` limits.
- Run `rsync --dry-run --itemize-changes --stats`.
- Enforce `--delete` circuit breakers (aborting if deletions exceed `max_delete_files` or 30% of files).
- Compute a content `manifest_sha256` over the staging directory and issue a short-lived `plan_token`.

## Step 3: Human Approval

Show the user:
- Target name and direction
- Added / modified / deleted file counts and file list
- Total transfer size and `plan_token`

Wait for the user to approve via `ops-approve`.

> **Important (TOCTOU protection)**: Do **NOT** modify any file in the staging directory between `preview` and `apply`. If anything changes, the manifest hash check will fail and you must re-run `rsync preview`.

## Step 4: Apply Sync

```bash
opsctl rsync apply <plan_token>
```

Verify `exit_code=0` and report the redacted summary back to the user.
