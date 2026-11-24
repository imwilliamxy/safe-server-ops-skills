# Logs & Docker Operations

## 1. Read Whitelisted Logs (L0)

First check available `<server>` and `<log_id>` via `opsctl capabilities`.

```bash
opsctl logs prod-web-1 nginx-error --lines 100
opsctl logs prod-web-1 app-container --lines 200 --keyword "ERROR"
```

- `--lines` is clamped to the policy's `max_lines`.
- `--keyword` performs fixed literal substring matching inside `opsd` (not shell grep), safe against regex ReDoS and command injection.
- Output is automatically redacted and truncated to `max_output_bytes`.

## 2. Check Docker Container / Compose Status (L0)

```bash
opsctl docker status prod-web-1
opsctl docker status prod-web-1 web-app
```

- Only whitelisted containers / compose services are returned.
- Container environment variables (`Env`) are intentionally never returned to prevent secret leakage.

## 3. Restart Docker Service (L1 — Two-Phase)

Always inspect logs and status **before** proposing a restart.

```bash
# Step 1: Create restart plan (returns plan_token)
opsctl docker restart-plan prod-web-1 web-app --reason "Container unhealthy after OOM"
```

Present the `plan_token`, target, and reason to the user and wait for human approval.

```bash
# Step 2: After user confirms approval
opsctl docker restart-apply <plan_token>
```

`restart-apply` restarts the target, waits briefly, and returns the post-restart container health/status together with the last 30 redacted startup log lines so you can verify recovery.
