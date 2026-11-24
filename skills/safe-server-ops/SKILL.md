---
name: safe-server-ops
description: Safely inspect logs, check or restart Docker services, preview and apply rsync deployments, and update whitelisted production server configs through the credential-isolated opsctl CLI without ever accessing SSH keys, IPs, or usernames. Use whenever the user asks to operate, troubleshoot, deploy to, or inspect a production or remote server.
---

# Safe Server Ops (`opsctl`)

You operate production servers **exclusively** through the credential-less CLI `opsctl`, which talks to the isolated background daemon `opsd` over a Unix Domain Socket.

## Non-Negotiable Security Rules

1. **Never touch credentials**: Do NOT read `~/.ssh/`, `~/.local/config/ssh_login/`, `/Users/sshops/`, or run raw `ssh` / `scp` / `rsync` against production hosts.
2. **Use logical IDs only**: Always start by discovering allowed server aliases, log IDs, Docker targets, config IDs, and sync targets via `opsctl capabilities`. Never ask the user for server IPs, usernames, or private keys.
3. **Never self-approve**: All mutating operations (Docker restart, `rsync apply`, config changes, rollbacks) require a two-phase flow (`plan/preview` → human out-of-band approval via `ops-approve` → `apply`). You cannot and must not attempt to bypass approval.
4. **Respect redacted placeholders**: Responses are automatically redacted (`[REDACTED_HOST]`, `[REDACTED_IP]`, `{{REDACTED_SECRET_N}}`). Keep `{{REDACTED_SECRET_N}}` intact when editing configs; never attempt to extract or replace hidden secrets.

## Progressive Reference Loading

Read **only** the reference file matching the current task before running mutating commands:

- Logs & Docker status / restart → [references/logs-and-docker.md](references/logs-and-docker.md)
- `rsync` file deployment → [references/rsync-deploy.md](references/rsync-deploy.md)
- Production config editing & rollback → [references/config-change.md](references/config-change.md)

## Quick Command Overview

```bash
# L0: Discover allowed servers and targets (read-only)
opsctl capabilities

# L0: Logs & Docker inspection (read-only)
#   restricted server  -> use whitelisted log_id / docker target
#   default_open server -> pass safe absolute path or docker:<container>; omit target to list all containers
opsctl logs <server> <log_id_or_path> --lines 100 [--keyword STR]
opsctl docker status <server> [target]

# L1: Docker restart (two-phase: plan -> human approve -> apply)
opsctl docker restart-plan <server> <target> --reason "<why>"
opsctl docker restart-apply <plan_token>

# L2: rsync sync (two-phase: preview -> human approve -> apply)
opsctl rsync preview <server> <target_id>
opsctl rsync preview <server> --local <staging_subdir> --remote <remote_dir>
opsctl rsync apply <plan_token>

# L2: Config change & rollback (two-phase; default_open servers accept safe absolute path as config_id)
opsctl config read <server> <config_id_or_path>
opsctl config plan <server> <config_id_or_path> --file <draft_path> --base-sha <sha> --reason "<why>"
opsctl config apply <plan_token>
opsctl config rollback-plan <server> <config_id> <backup_id> --reason "<why>"
opsctl config rollback-apply <plan_token>

# L2: Custom remote command (two-phase; available on default_open servers or allow_exec=true with gate_mode=false)
opsctl exec plan <server> --cmd "<command>" --reason "<why>"
opsctl exec apply <plan_token>
```

## Human Approval Handoff

When any `plan` or `preview` command returns a `plan_token`:
1. Present the exact target, change summary / Diff, and `plan_token` clearly to the user.
2. Tell the user to approve it in their own terminal (e.g. `sudo -u sshops /Users/sshops/.local/bin/ops-approve approve <plan_token>`, or inspect first with `--show <plan_token>`).
3. Wait for the user to confirm approval before calling the matching `apply <plan_token>` command.
