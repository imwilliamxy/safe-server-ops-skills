#!/usr/bin/env bash
# One-shot macOS bootstrap script for safe-server-ops-skill (idempotent).
# Integrates:
#   1. Create hidden non-login user 'sshops' & group 'opsclients'
#   2. Prepare isolated directories & permissions
#   3. Build (if needed) & install zero-dependency Rust binaries (opsd, ops-approve, opsctl)
#   4. Generate dedicated AI SSH keys under /Users/sshops/.ssh/ (if missing)
#   5. Initialize /Users/sshops/.local/config/opsd/{opsd.conf,.ssh-servers.env,policy.yaml} (if missing)
#   6. Link progressive Skill into ~/.gemini/config/skills/safe-server-ops
#   7. Install & start/restart launchd service com.local.safe-server-opsd
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo ./deploy/0-bootstrap-macos.sh [options] [daily_username]

Options:
  --skip-launchd   Do not install/start the launchd service yet
  --skip-skill     Do not symlink the Skill into ~/.gemini/config/skills/safe-server-ops
  -h, --help       Show this help message
EOF
}

SKIP_LAUNCHD=0
SKIP_SKILL=0
DAILY_USER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-launchd) SKIP_LAUNCHD=1; shift ;;
        --skip-skill) SKIP_SKILL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) DAILY_USER="$1"; shift ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Please run with sudo: sudo $0 [your_daily_username]" >&2
    exit 1
fi

if [[ -z "$DAILY_USER" ]]; then
    DAILY_USER="${SUDO_USER:-}"
fi
if [[ -z "$DAILY_USER" || "$DAILY_USER" == "root" ]]; then
    echo "ERROR: Please specify your daily non-root macOS username." >&2
    usage >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OPS_USER="sshops"
OPS_GROUP="opsclients"
OPS_HOME="/Users/${OPS_USER}"
DAILY_HOME=$(dscl . -read "/Users/${DAILY_USER}" NFSHomeDirectory | awk '{print $2}')
DAILY_GROUP=$(id -gn "$DAILY_USER")

echo "==> Step 1/7: Ensure hidden restricted user '${OPS_USER}' & group '${OPS_GROUP}'"
"${SCRIPT_DIR}/1-create-sshops-user.sh" "$DAILY_USER"

echo "==> Step 2/7: Ensure isolated directories & permissions"
"${SCRIPT_DIR}/2-setup-macos-isolation.sh" "$DAILY_USER"

echo "==> Step 3/7: Install zero-dependency Rust binaries (opsd, ops-approve, opsctl)"
"${SCRIPT_DIR}/3-install.sh" "$DAILY_USER"

echo "==> Step 4/7: Ensure dedicated AI SSH keys exist under ${OPS_HOME}/.ssh/"
OPS_KEY="${OPS_HOME}/.ssh/id_ed25519_ai_ops"
SYNC_KEY="${OPS_HOME}/.ssh/id_ed25519_ai_rrsync"
KNOWN_HOSTS="${OPS_HOME}/.ssh/known_hosts"

if [[ ! -f "$OPS_KEY" ]]; then
    sudo -u "$OPS_USER" ssh-keygen -t ed25519 -N "" -C "ai-ops" -f "$OPS_KEY"
else
    echo "  Keeping existing ${OPS_KEY}"
fi
if [[ ! -f "$SYNC_KEY" ]]; then
    sudo -u "$OPS_USER" ssh-keygen -t ed25519 -N "" -C "ai-rrsync" -f "$SYNC_KEY"
else
    echo "  Keeping existing ${SYNC_KEY}"
fi
if [[ ! -f "$KNOWN_HOSTS" ]]; then
    install -m 600 -o "$OPS_USER" -g "$OPS_GROUP" /dev/null "$KNOWN_HOSTS"
fi
chown "${OPS_USER}:${OPS_GROUP}" "$OPS_KEY" "${OPS_KEY}.pub" "$SYNC_KEY" "${SYNC_KEY}.pub" "$KNOWN_HOSTS"
chmod 600 "$OPS_KEY" "$SYNC_KEY" "$KNOWN_HOSTS"
chmod 644 "${OPS_KEY}.pub" "${SYNC_KEY}.pub"

echo "==> Step 5/7: Initialize config templates under ${OPS_HOME}/.local/config/opsd/ (if missing)"
CFG_DIR="${OPS_HOME}/.local/config/opsd"
copy_if_missing() {
    local src="$1" dst="$2"
    if [[ ! -f "$dst" ]]; then
        cp "$src" "$dst"
        echo "  Created ${dst} from template"
    else
        echo "  Keeping existing ${dst}"
    fi
    chown "${OPS_USER}:${OPS_GROUP}" "$dst"
    chmod 600 "$dst"
}
copy_if_missing "${SCRIPT_DIR}/opsd.example.conf"       "${CFG_DIR}/opsd.conf"
copy_if_missing "${SCRIPT_DIR}/ssh-servers.example.env" "${CFG_DIR}/.ssh-servers.env"
copy_if_missing "${SCRIPT_DIR}/policy.example.yaml"     "${CFG_DIR}/policy.yaml"

if [[ "$SKIP_SKILL" -eq 0 ]]; then
    echo "==> Step 6/7: Link progressive Skill for '${DAILY_USER}'"
    SKILL_PARENT="${DAILY_HOME}/.gemini/config/skills"
    install -d -m 755 -o "$DAILY_USER" -g "$DAILY_GROUP" "${DAILY_HOME}/.gemini" "${DAILY_HOME}/.gemini/config" "$SKILL_PARENT"
    ln -sfn "${REPO_DIR}/skills/safe-server-ops" "${SKILL_PARENT}/safe-server-ops"
    chown -h "${DAILY_USER}:${DAILY_GROUP}" "${SKILL_PARENT}/safe-server-ops"
    echo "  Linked ${SKILL_PARENT}/safe-server-ops -> ${REPO_DIR}/skills/safe-server-ops"
else
    echo "==> Step 6/7: Skipped Skill symlink (--skip-skill)"
fi

if [[ "$SKIP_LAUNCHD" -eq 0 ]]; then
    echo "==> Step 7/7: Register & start launchd daemon com.local.safe-server-opsd"
    PLIST_DST="/Library/LaunchDaemons/com.local.safe-server-opsd.plist"
    cp "${SCRIPT_DIR}/com.local.safe-server-opsd.plist" "$PLIST_DST"
    chown root:wheel "$PLIST_DST"
    chmod 644 "$PLIST_DST"
    if launchctl print system/com.local.safe-server-opsd >/dev/null 2>&1; then
        launchctl kickstart -k system/com.local.safe-server-opsd
    else
        launchctl bootstrap system "$PLIST_DST"
    fi
    sleep 1
    if [[ -S /var/run/sshops/ops.sock && -S /var/run/sshops/admin.sock ]]; then
        echo "  opsd is running and listening on /var/run/sshops/{ops,admin}.sock"
    else
        echo "  WARNING: sockets not found yet; inspect: sudo tail -n 30 ${OPS_HOME}/.local/state/opsd/opsd.stderr.log" >&2
    fi
else
    echo "==> Step 7/7: Skipped launchd setup (--skip-launchd)"
fi

echo ""
echo "=================================================================="
echo "Bootstrap complete! Your AI public keys (for remote server setup):"
echo "------------------------------------------------------------------"
echo "[AI Ops Key] (logs / docker / config):"
cat "${OPS_KEY}.pub"
echo ""
echo "[AI Rsync Key] (file sync):"
cat "${SYNC_KEY}.pub"
echo "=================================================================="
cat <<EOF

Next steps:
  1. Register your real production server & trust its SSH host key:
       sudo ./deploy/4-add-server.sh
  2. Edit whitelist policies (logs, docker containers, configs, sync_targets):
       sudo vim ${CFG_DIR}/policy.yaml
       sudo launchctl kickstart -k system/com.local.safe-server-opsd
  3. On your production server (works with an existing user OR a new user):
       sudo ./remote/install-remote-gate.sh --user <remote_user> --ops-pubkey "<AI Ops Key>"
  4. Verify isolation in a terminal:
       opsctl capabilities
EOF
