# safe-server-ops-skill

A credential-isolated gateway for AI coding agents that operate production servers. It combines a progressively loaded skill with three standalone Rust binaries: `opsctl`, `opsd`, and `ops-approve`.

[简体中文](README_zh.md)

* [Architecture and security boundaries](docs/DESIGN.md)
* [macOS isolation setup and production server hardening](docs/INSTALL.md)

## Key features

* **Standalone Rust binaries.** The build produces three native executables (`opsd`, `opsctl`, and `ops-approve`). The host can run them without Python, a virtual environment, or a package manager. Sensitive configuration data is cleared from memory with `zeroize` after use.
* **Low context overhead.** The [skill entry point](skills/safe-server-ops/SKILL.md) uses about 30 tokens for its description and loads individual reference documents on demand.
* **OS-level credential isolation.** The `opsd` daemon runs under a dedicated non-login system account (`sshops`) with exclusive access to `/Users/sshops/.local/` and the SSH private keys. The agent uses logical aliases and the credential-free client at `/Users/<username>/.local/bin/opsctl`.
* **Separate Unix sockets for operations and approvals.**
  * `ops.sock` handles operations and rejects approval methods.
  * `admin.sock` is accessible only to its owner (`0600`). A human approves each `plan_token` with `sudo -u sshops /Users/sshops/.local/bin/ops-approve` using a password or Touch ID. The setup prohibits `NOPASSWD` for approvals.
* **Production operations.**
  * **L0 read-only inspection.** Read allowlisted logs with local literal filtering, redaction, and truncation. Inspect Docker status with environment variables excluded.
  * **L1 Docker restart.** Run `restart-plan`, obtain human approval, and run `restart-apply`. The client returns the new status and the 30 most recent startup log lines with sensitive values redacted.
  * **L2 `rsync` deployment.** Check for symlinks that escape the staging directory, enforce file count and size limits, and preview changes with `--dry-run`. A SHA-256 manifest detects changes between preview and apply. Deletion safeguards and server-side `rrsync` are supported.
  * **L2 configuration edits and rollback.** Sensitive values are redacted with placeholders and restored after integrity checks. The workflow uses optimistic locking with `base_sha256`, local JSON/YAML validation, remote validation such as `nginx -t`, a unified diff, automatic backups, and rollback on reload failure.
* **Embedded read-only audit dashboard** (defaults to `http://127.0.0.1:10100`).
  * The dashboard binds to the loopback interface and accepts only `GET` and `HEAD` requests.
  * The left pane groups activity by agent session, with detection for Paseo (`PASEO_AGENT_ID`), Antigravity, Claude Code, Codex, and terminal sessions. Use `--session-title` to give a session a descriptive name. The right pane streams the 100 most recent calls over Server-Sent Events (SSE), showing remote commands, redacted output, diffs, approval history, and high-risk command warnings.
  * Audit logs rotate by size, with five archives retained by default and a 20 MiB rotation threshold. Reload configuration without interruption using `ops-approve reload` or `SIGHUP`.

## Build and test locally

```bash
# Run unit tests and end-to-end tests of the binaries and both Unix sockets.
cargo test

# Build optimized binaries in target/release/{opsd,opsctl,ops-approve}.
cargo build --release

# Show help for each executable.
./target/release/opsctl --help
./target/release/opsd --help
./target/release/ops-approve --help
```

## Try it locally with one user

```bash
# Copy the configuration templates. Keep your edited files out of Git.
cp deploy/ssh-servers.example.env /tmp/dev-servers.env
cp deploy/policy.example.yaml /tmp/dev-policy.yaml

# Edit the files as needed, then start opsd.
./target/release/opsd \
  --servers-env /tmp/dev-servers.env \
  --policy /tmp/dev-policy.yaml \
  --socket /tmp/ops.sock \
  --admin-socket /tmp/ops-admin.sock \
  --audit-log /tmp/ops-audit.jsonl

# In another terminal, check that opsctl can reach the daemon.
export OPS_SOCKET=/tmp/ops.sock
./target/release/opsctl capabilities
```

## Deploy with credential isolation on macOS

The [installation guide](docs/INSTALL.md) covers all eight steps, including server hardening, verification, and troubleshooting. The bootstrap script provisions the `sshops` account, keys, configuration templates, skill, and `launchd` service.

```bash
cargo build --release
sudo ./deploy/0-bootstrap-macos.sh <username>
sudo ./deploy/4-add-server.sh --import-ssh-login --key-mode ai
```

## Install the skill for other AI coding agents

All local agents can share the same `opsd` daemon and credential-free `opsctl` client.

### Ask your agent to install the skill

Replace the example path with your local repository path and send this prompt to Claude Code, Codex, Cursor, Antigravity, or another local coding agent.

```text
Install the local safe-server-ops skill for this agent.

1. Use /path/to/safe-server-ops-skill/skills/safe-server-ops as the source. It contains SKILL.md and references/.
2. Find this agent's user-level skills directory, such as ~/.claude/skills, ~/.codex/skills, ~/.cursor/skills, ~/.gemini/config/skills, or ~/.agents/skills. Use ln -sfn to link the source as <skills-directory>/safe-server-ops.
3. Run which opsctl to check that opsctl is on PATH, then run the read-only command opsctl capabilities to verify that the client can reach the local opsd daemon.
4. Keep /Users/sshops/, ~/.ssh/, SSH configuration files, and private keys off-limits. For production or remote server operations, follow the safe-server-ops skill and use only opsctl. Wait for my approval through ops-approve before applying write operations.
5. Report the symlink path, the result of opsctl capabilities, and whether a new session is required to load the skill.
```

### Create the symlinks manually

```bash
SKILL_SRC="/path/to/safe-server-ops-skill/skills/safe-server-ops"

# Antigravity (the bootstrap script already creates this link)
mkdir -p ~/.gemini/config/skills && ln -sfn "$SKILL_SRC" ~/.gemini/config/skills/safe-server-ops

# Claude Code
mkdir -p ~/.claude/skills && ln -sfn "$SKILL_SRC" ~/.claude/skills/safe-server-ops

# OpenAI Codex CLI
mkdir -p ~/.codex/skills && ln -sfn "$SKILL_SRC" ~/.codex/skills/safe-server-ops

# Cursor and agents that use the shared skills directory
mkdir -p ~/.cursor/skills ~/.agents/skills
ln -sfn "$SKILL_SRC" ~/.cursor/skills/safe-server-ops
ln -sfn "$SKILL_SRC" ~/.agents/skills/safe-server-ops
```
