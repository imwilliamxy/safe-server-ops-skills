#!/usr/bin/env bash
# Install safe-server-ops in strict OS-isolated per-user layout on macOS:
# - Isolated user (sshops):
#     /Users/sshops/.local/bin/opsd
#     /Users/sshops/.local/bin/ops-approve
#     (backed by /Users/sshops/.local/venv/safe-server-ops, chmod 700, invisible to daily user & AI)
# - Daily user (<username>):
#     /Users/<username>/.local/bin/opsctl
#     (backed by /Users/<username>/.local/venv/safe-server-ops, zero credentials)
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run with sudo: sudo $0 [username]" >&2
    exit 1
fi

DAILY_USER="${1:-${SUDO_USER:-}}"
if [[ -z "$DAILY_USER" || "$DAILY_USER" == "root" ]]; then
    echo "Usage: sudo $0 <your_daily_username>" >&2
    exit 1
fi

OPS_USER="sshops"
OPS_GROUP="opsclients"

if ! id "$DAILY_USER" >/dev/null 2>&1; then
    echo "User '$DAILY_USER' does not exist." >&2
    exit 1
fi
if ! id "$OPS_USER" >/dev/null 2>&1; then
    echo "Isolated user '$OPS_USER' does not exist yet. Create '$OPS_USER' and run setup-macos-isolation.sh first." >&2
    exit 1
fi

DAILY_GROUP=$(id -gn "$DAILY_USER")
DAILY_HOME=$(dscl . -read "/Users/$DAILY_USER" NFSHomeDirectory | awk '{print $2}')
OPS_HOME=$(dscl . -read "/Users/$OPS_USER" NFSHomeDirectory | awk '{print $2}')

DAILY_VENV="${DAILY_HOME}/.local/venv/safe-server-ops"
DAILY_BIN="${DAILY_HOME}/.local/bin"
OPS_VENV="${OPS_HOME}/.local/venv/safe-server-ops"
OPS_BIN="${OPS_HOME}/.local/bin"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

UV_BIN="$(command -v uv || true)"
if [[ -z "$UV_BIN" && -x /opt/homebrew/bin/uv ]]; then
    UV_BIN="/opt/homebrew/bin/uv"
fi
if [[ -z "$UV_BIN" ]]; then
    echo "uv not found in PATH or /opt/homebrew/bin/uv." >&2
    exit 1
fi

echo "[1/4] Building wheel from ${REPO_DIR} into temporary staging..."
TMP_DIST=$(mktemp -d /tmp/safe-server-ops-dist.XXXXXX)
cleanup() { rm -rf -- "$TMP_DIST"; }
trap cleanup EXIT
"$UV_BIN" build --wheel --out-dir "$TMP_DIST" "$REPO_DIR"
WHEEL_FILE=$(ls -1 "${TMP_DIST}"/safe_server_ops-*.whl | head -n 1)
chmod 755 "$TMP_DIST"
chmod 644 "$WHEEL_FILE"

echo "[2/4] Installing isolated daemon & approval CLI into ${OPS_BIN} (owned by ${OPS_USER})..."
install -d -m 700 -o "$OPS_USER" -g "$OPS_GROUP" "${OPS_HOME}/.local" "${OPS_HOME}/.local/venv" "$OPS_BIN"
"$UV_BIN" venv --allow-existing --python 3.11 "$OPS_VENV"
"$UV_BIN" pip install --python "${OPS_VENV}/bin/python" --reinstall "$WHEEL_FILE"
ln -sfn "${OPS_VENV}/bin/opsd" "${OPS_BIN}/opsd"
ln -sfn "${OPS_VENV}/bin/ops-approve" "${OPS_BIN}/ops-approve"
chown -R "${OPS_USER}:${OPS_GROUP}" "${OPS_HOME}/.local/venv" "$OPS_BIN"
chmod -R go-rwx "${OPS_HOME}/.local/venv" "$OPS_BIN"

echo "[3/4] Installing credential-less 'opsctl' into ${DAILY_BIN} (owned by ${DAILY_USER})..."
install -d -m 755 -o "$DAILY_USER" -g "$DAILY_GROUP" "${DAILY_HOME}/.local" "${DAILY_HOME}/.local/venv" "$DAILY_BIN"
"$UV_BIN" venv --allow-existing --python 3.11 "$DAILY_VENV"
"$UV_BIN" pip install --python "${DAILY_VENV}/bin/python" --reinstall "$WHEEL_FILE"
ln -sfn "${DAILY_VENV}/bin/opsctl" "${DAILY_BIN}/opsctl"
chown -R "${DAILY_USER}:${DAILY_GROUP}" "$DAILY_VENV"
chown -h "${DAILY_USER}:${DAILY_GROUP}" "${DAILY_BIN}/opsctl"

echo "[4/4] Installation complete:"
ls -ld "${DAILY_BIN}/opsctl" "${OPS_BIN}/opsd" "${OPS_BIN}/ops-approve"
cat <<EOF

Layout summary:
  - Daily user & AI CLI : ${DAILY_BIN}/opsctl
  - Isolated daemon     : ${OPS_BIN}/opsd --config ${OPS_HOME}/.local/config/opsd/opsd.conf
  - Human approval CLI  : sudo -u ${OPS_USER} ${OPS_BIN}/ops-approve --list
EOF
