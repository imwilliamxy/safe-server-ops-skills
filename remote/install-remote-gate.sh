#!/usr/bin/env bash
# Production Linux server installer for safe-server-ops ForceCommand gate & rrsync.
# Supports reusing an EXISTING SSH user (no new Linux user required!) OR creating a dedicated user.
#
# Because OpenSSH authorized_keys applies 'command="..."' per public key, your personal login key
# continues to get a normal interactive shell, while AI keys are strictly locked to ai-ops-gate / rrsync.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo ./install-remote-gate.sh --user <linux_user> [options]

Options:
  --user <name>           Target Linux username (can be an EXISTING user like 'ubuntu', 'deploy', or 'root')
  --create-user           Create the target user if it does not exist yet
  --ops-pubkey "<key>"    AI ops public key to bind to ForceCommand ai-ops-ssh-entry.sh
  --sync-pubkey "<key>"   AI rsync public key to bind to ForceCommand rrsync
  --sync-dir <abs_dir>    Target directory for rrsync (required when --sync-pubkey is set)
  --sync-mode <wo|ro|rw>  rrsync mode: wo (write-only, default), ro (read-only), rw (read-write)
  --force-gate            Overwrite existing /usr/local/bin/ai-ops-gate.sh (default preserves your whitelists)
  -h, --help              Show this help message

Example (reusing existing 'ubuntu' user, no new user created):
  sudo ./install-remote-gate.sh \
    --user ubuntu \
    --ops-pubkey "ssh-ed25519 AAAA... ai-ops" \
    --sync-pubkey "ssh-ed25519 AAAA... ai-rrsync" \
    --sync-dir /var/www/html/wp-content/plugins/my-plugin
EOF
}

TARGET_USER=""
CREATE_USER=0
OPS_PUBKEY=""
SYNC_PUBKEY=""
SYNC_DIR=""
SYNC_MODE="wo"
FORCE_GATE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user) TARGET_USER="$2"; shift 2 ;;
        --create-user) CREATE_USER=1; shift ;;
        --ops-pubkey) OPS_PUBKEY="$2"; shift 2 ;;
        --sync-pubkey) SYNC_PUBKEY="$2"; shift 2 ;;
        --sync-dir) SYNC_DIR="$2"; shift 2 ;;
        --sync-mode) SYNC_MODE="$2"; shift 2 ;;
        --force-gate) FORCE_GATE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Please run as root (sudo $0 ...)." >&2
    exit 1
fi
[[ -n "$TARGET_USER" ]] || { echo "ERROR: --user is required." >&2; usage >&2; exit 1; }
[[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { echo "ERROR: Invalid username: $TARGET_USER" >&2; exit 1; }

if [[ -n "$SYNC_PUBKEY" ]]; then
    [[ -n "$SYNC_DIR" && "$SYNC_DIR" == /* ]] || {
        echo "ERROR: --sync-dir must be an absolute path when --sync-pubkey is provided." >&2
        exit 1
    }
    [[ "$SYNC_MODE" =~ ^(wo|ro|rw)$ ]] || { echo "ERROR: --sync-mode must be wo, ro, or rw." >&2; exit 1; }
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/4] Checking target Linux user '${TARGET_USER}'..."
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    if [[ "$CREATE_USER" -eq 1 ]]; then
        useradd -m -s /bin/bash "$TARGET_USER"
        echo "  Created user '${TARGET_USER}' (NOT added to docker group)."
    else
        echo "ERROR: User '${TARGET_USER}' does not exist. Pass --create-user to create it, or use an existing user." >&2
        exit 1
    fi
else
    echo "  Reusing existing user '${TARGET_USER}' (existing personal SSH keys remain untouched)."
fi

TARGET_GROUP=$(id -gn "$TARGET_USER")
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
[[ -n "$TARGET_HOME" ]] || { echo "ERROR: Failed to resolve home directory for ${TARGET_USER}." >&2; exit 1; }

echo "[2/4] Installing gate scripts into /usr/local/bin/..."
install -m 755 -o root -g root "${SCRIPT_DIR}/ai-ops-ssh-entry.sh" /usr/local/bin/ai-ops-ssh-entry.sh
if [[ ! -f /usr/local/bin/ai-ops-gate.sh || "$FORCE_GATE" -eq 1 ]]; then
    install -m 755 -o root -g root "${SCRIPT_DIR}/ai-ops-gate.sh" /usr/local/bin/ai-ops-gate.sh
    echo "  Installed /usr/local/bin/ai-ops-gate.sh (edit its top whitelists to match your server!)"
else
    echo "  Preserved existing /usr/local/bin/ai-ops-gate.sh (pass --force-gate to overwrite)."
fi

echo "[3/4] Configuring scoped sudoers rule..."
if [[ "$TARGET_USER" == "root" ]]; then
    echo "  Target user is root; no sudoers file needed."
else
    SUDOERS_DST="/etc/sudoers.d/safe-server-ops-${TARGET_USER}"
    tmp_sudo=$(mktemp)
    printf '%s ALL=(root) NOPASSWD: /usr/local/bin/ai-ops-gate.sh *\n' "$TARGET_USER" >"$tmp_sudo"
    chmod 440 "$tmp_sudo"
    if visudo -cf "$tmp_sudo" >/dev/null 2>&1; then
        mv -f "$tmp_sudo" "$SUDOERS_DST"
        chown root:root "$SUDOERS_DST"
        chmod 440 "$SUDOERS_DST"
        echo "  Installed validated sudoers rule: ${SUDOERS_DST}"
    else
        rm -f "$tmp_sudo"
        echo "ERROR: visudo syntax check failed; sudoers was NOT modified." >&2
        exit 1
    fi
fi

echo "[4/4] Updating ${TARGET_HOME}/.ssh/authorized_keys..."
SSH_DIR="${TARGET_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
install -d -m 700 -o "$TARGET_USER" -g "$TARGET_GROUP" "$SSH_DIR"
touch "$AUTH_KEYS"
chown "${TARGET_USER}:${TARGET_GROUP}" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

append_key_line() {
    local forced_cmd="$1" pubkey="$2"
    local key_body
    key_body=$(printf '%s\n' "$pubkey" | awk '{print $2}')
    if [[ -z "$key_body" ]]; then
        echo "ERROR: Invalid SSH public key format: $pubkey" >&2
        exit 1
    fi
    if grep -Fq "$key_body" "$AUTH_KEYS"; then
        echo "  Key already present in ${AUTH_KEYS}; skipping duplicate."
        return 0
    fi
    printf 'command="%s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s\n' \
        "$forced_cmd" "$pubkey" >>"$AUTH_KEYS"
    echo "  Added ForceCommand key entry (${forced_cmd})."
}

if [[ -n "$OPS_PUBKEY" ]]; then
    append_key_line "/usr/local/bin/ai-ops-ssh-entry.sh" "$OPS_PUBKEY"
fi

if [[ -n "$SYNC_PUBKEY" ]]; then
    RRSYNC_BIN=""
    for cand in /usr/bin/rrsync /usr/local/bin/rrsync /usr/share/doc/rsync/scripts/rrsync; do
        if [[ -x "$cand" ]]; then
            RRSYNC_BIN="$cand"
            break
        fi
    done
    if [[ -z "$RRSYNC_BIN" ]]; then
        echo "ERROR: rrsync executable not found. Install rsync or extract /usr/share/doc/rsync/scripts/rrsync.gz to /usr/local/bin/rrsync." >&2
        exit 1
    fi
    case "$SYNC_MODE" in
        wo) rrsync_cmd="${RRSYNC_BIN} -wo ${SYNC_DIR}" ;;
        ro) rrsync_cmd="${RRSYNC_BIN} -ro ${SYNC_DIR}" ;;
        rw) rrsync_cmd="${RRSYNC_BIN} ${SYNC_DIR}" ;;
    esac
    append_key_line "$rrsync_cmd" "$SYNC_PUBKEY"
fi

echo ""
echo "Remote gate installation complete!"
echo "IMPORTANT: Edit /usr/local/bin/ai-ops-gate.sh to whitelist your actual log paths, Docker containers, and config paths."
