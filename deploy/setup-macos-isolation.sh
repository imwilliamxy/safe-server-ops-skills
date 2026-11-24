#!/usr/bin/env bash
# Helper script to prepare OS-level isolation directories on macOS.
# Review carefully before executing with sudo!
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run as root (sudo $0 <your_daily_username>)" >&2
    exit 1
fi

DAILY_USER="${1:-}"
if [[ -z "$DAILY_USER" ]]; then
    echo "Usage: sudo $0 <your_daily_username>" >&2
    exit 1
fi

OPS_USER="sshops"
OPS_GROUP="opsclients"

echo "[1/5] Ensure group '$OPS_GROUP' exists and includes '$DAILY_USER'..."
if ! dscl . -read "/Groups/$OPS_GROUP" >/dev/null 2>&1; then
    dseditgroup -o create "$OPS_GROUP"
fi
dseditgroup -o edit -a "$DAILY_USER" -t user "$OPS_GROUP"

echo "[2/5] Verify isolated user '$OPS_USER' exists..."
if ! id "$OPS_USER" >/dev/null 2>&1; then
    echo "User '$OPS_USER' does not exist yet." >&2
    echo "Create a dedicated non-login user first (e.g. via sysadminctl or dscl with UserShell /usr/bin/false), then re-run this script." >&2
    exit 1
fi
dseditgroup -o edit -a "$OPS_USER" -t user "$OPS_GROUP"

echo "[3/5] Create credential, socket, log, and staging directories..."
install -d -m 700 -o "$OPS_USER" -g "$OPS_GROUP" /var/lib/sshops /var/lib/sshops/.ssh /var/lib/sshops/excludes
install -d -m 750 -o "$OPS_USER" -g "$OPS_GROUP" /var/run/sshops
install -d -m 700 -o "$OPS_USER" -g "$OPS_GROUP" /var/log/sshops
install -d -m 750 -o "$DAILY_USER" -g "$OPS_GROUP" /var/tmp/sshops-staging

echo "[4/5] Directory permissions configured:"
ls -ld /var/lib/sshops /var/run/sshops /var/log/sshops /var/tmp/sshops-staging

echo "[5/5] Next manual steps:"
cat <<'EOF'
  1. Generate dedicated AI keys owned by sshops (chmod 600) in /var/lib/sshops/.ssh/
  2. Populate /var/lib/sshops/.ssh-servers.env and /var/lib/sshops/policy.yaml (chmod 600, chown sshops)
  3. Pre-populate /var/lib/sshops/.ssh/known_hosts with trusted production host keys
  4. Install the package into /usr/local/venv/safe-server-ops
  5. Copy deploy/com.local.safe-server-opsd.plist to /Library/LaunchDaemons/ and load via:
       sudo launchctl bootstrap system /Library/LaunchDaemons/com.local.safe-server-opsd.plist
  6. Approve plans safely with Touch ID / password (NEVER configure NOPASSWD for ops-approve):
       sudo -u sshops /usr/local/venv/safe-server-ops/bin/ops-approve --list
EOF
