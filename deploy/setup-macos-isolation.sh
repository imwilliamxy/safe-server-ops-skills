#!/usr/bin/env bash
# Helper script to prepare OS-level isolation directories on macOS:
# - Isolated user sshops home:  /Users/sshops/.local/{bin,config/opsd,state/opsd} + /Users/sshops/.ssh (700)
# - Shared socket dir:          /var/run/sshops (750, sshops:opsclients)
# - Staging transfer dir:       /var/tmp/sshops-staging (750, <daily_user>:opsclients)
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run as root: sudo $0 <your_daily_username>" >&2
    exit 1
fi

DAILY_USER="${1:-${SUDO_USER:-}}"
if [[ -z "$DAILY_USER" || "$DAILY_USER" == "root" ]]; then
    echo "Usage: sudo $0 <your_daily_username>" >&2
    exit 1
fi

OPS_USER="sshops"
OPS_GROUP="opsclients"
OPS_HOME="/Users/${OPS_USER}"

echo "[1/5] Ensure group '$OPS_GROUP' exists and includes '$DAILY_USER'..."
if ! dscl . -read "/Groups/$OPS_GROUP" >/dev/null 2>&1; then
    dseditgroup -o create "$OPS_GROUP"
fi
dseditgroup -o edit -a "$DAILY_USER" -t user "$OPS_GROUP"

echo "[2/5] Verify isolated user '$OPS_USER' exists..."
if ! id "$OPS_USER" >/dev/null 2>&1; then
    echo "User '$OPS_USER' does not exist yet." >&2
    echo "Create hidden non-login user '$OPS_USER' with NFSHomeDirectory ${OPS_HOME} and UserShell /usr/bin/false first, then re-run." >&2
    exit 1
fi
dseditgroup -o edit -a "$OPS_USER" -t user "$OPS_GROUP"

echo "[3/5] Create isolated home, config, socket, and staging directories..."
install -d -m 700 -o "$OPS_USER" -g "$OPS_GROUP" \
    "$OPS_HOME" \
    "${OPS_HOME}/.ssh" \
    "${OPS_HOME}/.local" \
    "${OPS_HOME}/.local/bin" \
    "${OPS_HOME}/.local/venv" \
    "${OPS_HOME}/.local/config" \
    "${OPS_HOME}/.local/config/opsd" \
    "${OPS_HOME}/.local/config/opsd/excludes" \
    "${OPS_HOME}/.local/state" \
    "${OPS_HOME}/.local/state/opsd"

install -d -m 750 -o "$OPS_USER" -g "$OPS_GROUP" /var/run/sshops
install -d -m 750 -o "$DAILY_USER" -g "$OPS_GROUP" /var/tmp/sshops-staging

echo "[4/5] Directory permissions configured:"
ls -ld "$OPS_HOME" "${OPS_HOME}/.local/config/opsd" /var/run/sshops /var/tmp/sshops-staging

echo "[5/5] Next manual steps:"
cat <<EOF
  1. Generate dedicated AI keys owned by ${OPS_USER} (chmod 600) in ${OPS_HOME}/.ssh/
  2. Copy and edit configs into ${OPS_HOME}/.local/config/opsd/ (chmod 600, chown ${OPS_USER}):
       - opsd.conf         (from deploy/opsd.example.conf)
       - .ssh-servers.env  (from deploy/ssh-servers.example.env)
       - policy.yaml       (from deploy/policy.example.yaml)
  3. Pre-populate ${OPS_HOME}/.ssh/known_hosts with trusted production host keys
  4. Install binaries:
       sudo ./deploy/install.sh ${DAILY_USER}
     -> ${OPS_HOME}/.local/bin/{opsd,ops-approve} (isolated to ${OPS_USER})
     -> /Users/${DAILY_USER}/.local/bin/opsctl    (credential-less CLI for daily user & AI)
  5. Load launchd daemon:
       sudo cp deploy/com.local.safe-server-opsd.plist /Library/LaunchDaemons/
       sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.safe-server-opsd.plist
  6. Approve plans safely with Touch ID / password (NEVER configure NOPASSWD):
       sudo -u ${OPS_USER} ${OPS_HOME}/.local/bin/ops-approve --list
EOF
