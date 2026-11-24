#!/usr/bin/env bash
# Build and install zero-dependency Rust binaries in strict OS-isolated per-user layout on macOS:
# - Isolated user (sshops):
#     /Users/sshops/.local/bin/opsd         (chmod 700, owned by sshops)
#     /Users/sshops/.local/bin/ops-approve  (chmod 700, owned by sshops)
# - Daily user (<username>):
#     /Users/<username>/.local/bin/opsctl   (chmod 755, zero credentials)
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
    echo "Isolated user '$OPS_USER' does not exist yet. Run 'sudo ./deploy/1-create-sshops-user.sh ${DAILY_USER}' and 'sudo ./deploy/2-setup-macos-isolation.sh ${DAILY_USER}' first." >&2
    exit 1
fi

DAILY_GROUP=$(id -gn "$DAILY_USER")
DAILY_HOME=$(dscl . -read "/Users/$DAILY_USER" NFSHomeDirectory | awk '{print $2}')
OPS_HOME=$(dscl . -read "/Users/$OPS_USER" NFSHomeDirectory | awk '{print $2}')

DAILY_BIN="${DAILY_HOME}/.local/bin"
OPS_BIN="${OPS_HOME}/.local/bin"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
RELEASE_DIR="${REPO_DIR}/target/release"

if [[ ! -x "${RELEASE_DIR}/opsd" || ! -x "${RELEASE_DIR}/opsctl" || ! -x "${RELEASE_DIR}/ops-approve" ]]; then
    echo "[1/3] Building release binaries as ${DAILY_USER} (cargo build --release)..."
    CARGO_BIN="${DAILY_HOME}/.cargo/bin/cargo"
    if [[ ! -x "$CARGO_BIN" ]]; then
        CARGO_BIN="$(command -v cargo || true)"
    fi
    if [[ -z "$CARGO_BIN" ]]; then
        echo "cargo not found. Build first with 'cargo build --release' as ${DAILY_USER}, then re-run." >&2
        exit 1
    fi
    sudo -u "$DAILY_USER" bash -c "cd $(printf '%q' "$REPO_DIR") && $(printf '%q' "$CARGO_BIN") build --release"
else
    echo "[1/3] Using existing release binaries in ${RELEASE_DIR}..."
fi

echo "[2/3] Installing isolated binaries into ${OPS_BIN} (owned by ${OPS_USER}, chmod 700)..."
install -d -m 700 -o "$OPS_USER" -g "$OPS_GROUP" "${OPS_HOME}/.local" "$OPS_BIN"
install -m 700 -o "$OPS_USER" -g "$OPS_GROUP" "${RELEASE_DIR}/opsd" "${OPS_BIN}/opsd"
install -m 700 -o "$OPS_USER" -g "$OPS_GROUP" "${RELEASE_DIR}/ops-approve" "${OPS_BIN}/ops-approve"

echo "[3/3] Installing credential-less 'opsctl' into ${DAILY_BIN} (owned by ${DAILY_USER})..."
install -d -m 755 -o "$DAILY_USER" -g "$DAILY_GROUP" "${DAILY_HOME}/.local" "$DAILY_BIN"
install -m 755 -o "$DAILY_USER" -g "$DAILY_GROUP" "${RELEASE_DIR}/opsctl" "${DAILY_BIN}/opsctl"

echo "Installation complete (zero Python / venv dependencies):"
ls -lh "${DAILY_BIN}/opsctl" "${OPS_BIN}/opsd" "${OPS_BIN}/ops-approve"
cat <<EOF

Layout summary:
  - Daily user & AI CLI : ${DAILY_BIN}/opsctl
  - Isolated daemon     : ${OPS_BIN}/opsd --config ${OPS_HOME}/.local/config/opsd/opsd.conf
  - Human approval CLI  : sudo -u ${OPS_USER} ${OPS_BIN}/ops-approve --list
EOF
