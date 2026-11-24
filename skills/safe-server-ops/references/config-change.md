# Safe Production Config Change & Rollback (L2)

Only explicitly whitelisted configuration IDs (`configs`) can be read or modified.

## Step 1: Read Current Config

```bash
opsctl config read prod-web-1 nginx-site
```

Record the returned `base_sha256` and content.
- Sensitive values matching `redact_patterns` appear as `{{REDACTED_SECRET_1}}`, `{{REDACTED_SECRET_2}}`, etc.
- **Do NOT delete, rename, or alter** those `{{REDACTED_SECRET_N}}` placeholders unless you intend to fail validation—`opsd` restores real secrets in memory right before validation and writing.

## Step 2: Write Draft Locally & Plan

Save the updated config to a temporary local draft file (for example `/tmp/nginx-site.draft.conf`), then generate a validated plan:

```bash
opsctl config plan prod-web-1 nginx-site \
  --file /tmp/nginx-site.draft.conf \
  --base-sha <base_sha256> \
  --reason "Increase upstream proxy_read_timeout to 60s"
```

`opsd` will:
1. Verify the remote file still matches `base_sha256` (prevents overwriting concurrent edits).
2. Restore untouched secret placeholders in memory.
3. Run syntax checks (local JSON/YAML check if applicable + remote validator such as `nginx -t`). If validation fails, no `plan_token` is issued.
4. Return a redacted **Unified Diff** and a `plan_token`.

## Step 3: Human Approval & Apply

Present the Unified Diff and `plan_token` to the user and wait for approval. After approval:

```bash
opsctl config apply <plan_token>
```

`opsd` automatically:
1. Re-verifies the remote file hash.
2. Saves a timestamped backup (`backup_id`).
3. Atomically replaces the target file.
4. Runs the configured `reload_action` (if any). **If reload fails, `opsd` automatically restores the backup and reloads again.**

## Step 4: Manual Rollback (If Needed Later)

```bash
# List backups or plan rollback to a specific backup_id
opsctl config backups prod-web-1 nginx-site
opsctl config rollback-plan prod-web-1 nginx-site <backup_id> --reason "Revert timeout change"
# After human approval:
opsctl config rollback-apply <plan_token>
```
