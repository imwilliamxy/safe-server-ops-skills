#!/usr/bin/env bash
# Create the dedicated hidden non-login macOS user 'sshops' and shared group 'opsclients'.
# Safe & idempotent: automatically picks a free system UID (450-499), locks password,
# disables interactive shell (/usr/bin/false), hides from login window, and sets home to /Users/sshops.
set -euo pipefail

OPS_USER="sshops"
OPS_GROUP="opsclients"
OPS_HOME="/Users/${OPS_USER}"
REQUESTED_UID=""
DRY_RUN=0
DAILY_USER=""

usage() {
    cat <<'EOF'
Usage:
  sudo ./deploy/1-create-sshops-user.sh [options] [daily_username]

Options:
  --uid <N>     Specify UID explicitly (recommended 450-499). Default: auto-pick free UID.
  --dry-run     Inspect current state and print actions without modifying the system.
  -h, --help    Show this help message.

Examples:
  ./deploy/1-create-sshops-user.sh --dry-run john
  sudo ./deploy/1-create-sshops-user.sh john
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --uid)
            [[ $# -ge 2 ]] || { echo "ERROR: --uid requires a numeric value." >&2; exit 1; }
            REQUESTED_UID="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [[ -n "$DAILY_USER" ]]; then
                echo "ERROR: Unexpected extra argument: $1" >&2
                exit 1
            fi
            DAILY_USER="$1"
            shift
            ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: This script is intended for macOS (Darwin) only." >&2
    exit 1
fi

if [[ -z "$DAILY_USER" ]]; then
    DAILY_USER="${SUDO_USER:-${USER:-}}"
fi
if [[ -z "$DAILY_USER" || "$DAILY_USER" == "root" || "$DAILY_USER" == "$OPS_USER" ]]; then
    echo "ERROR: Please provide your daily non-root macOS username." >&2
    usage >&2
    exit 1
fi
if ! id "$DAILY_USER" >/dev/null 2>&1; then
    echo "ERROR: Daily user '$DAILY_USER' does not exist." >&2
    exit 1
fi

if [[ "$DRY_RUN" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Please run with sudo: sudo $0 $DAILY_USER" >&2
    exit 1
fi

run_cmd() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

uid_in_use() {
    dscl . -list /Users UniqueID | awk -v target="$1" '$2 == target { found=1 } END { exit !found }'
}

pick_free_uid() {
    local candidate
    if [[ -n "$REQUESTED_UID" ]]; then
        [[ "$REQUESTED_UID" =~ ^[0-9]+$ ]] || { echo "ERROR: --uid must be an integer." >&2; exit 1; }
        if uid_in_use "$REQUESTED_UID"; then
            echo "ERROR: Requested UID $REQUESTED_UID is already in use." >&2
            exit 1
        fi
        echo "$REQUESTED_UID"
        return 0
    fi
    # Prefer 455..499 then 450..454 (macOS hidden system account range < 500)
    for candidate in $(seq 455 499) $(seq 450 454); do
        if ! uid_in_use "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    echo "ERROR: Could not find a free UID in range 450-499. Pass --uid explicitly." >&2
    exit 1
}

echo "[1/3] Ensuring group '${OPS_GROUP}' exists and includes '${DAILY_USER}'..."
if dscl . -read "/Groups/${OPS_GROUP}" >/dev/null 2>&1; then
    echo "  Group '${OPS_GROUP}' already exists."
else
    run_cmd dseditgroup -o create "$OPS_GROUP"
fi
run_cmd dseditgroup -o edit -a "$DAILY_USER" -t user "$OPS_GROUP"

if dscl . -read "/Groups/${OPS_GROUP}" >/dev/null 2>&1; then
    OPS_GID=$(dscl . -read "/Groups/${OPS_GROUP}" PrimaryGroupID | awk '{print $2}')
else
    OPS_GID="<newly-created-opsclients-gid>"
fi

echo "[2/3] Ensuring restricted hidden user '${OPS_USER}' exists..."
if dscl . -read "/Users/${OPS_USER}" >/dev/null 2>&1; then
    EXISTING_SHELL=$(dscl . -read "/Users/${OPS_USER}" UserShell | awk '{print $2}')
    EXISTING_HOME=$(dscl . -read "/Users/${OPS_USER}" NFSHomeDirectory | awk '{print $2}')
    if [[ "$EXISTING_SHELL" != "/usr/bin/false" || "$EXISTING_HOME" != "$OPS_HOME" ]]; then
        echo "ERROR: User '${OPS_USER}' already exists with unexpected settings (shell=${EXISTING_SHELL}, home=${EXISTING_HOME}). Refusing to overwrite." >&2
        exit 1
    fi
    echo "  User '${OPS_USER}' already exists with safe settings (shell=${EXISTING_SHELL}, home=${EXISTING_HOME})."
    run_cmd dseditgroup -o edit -a "$OPS_USER" -t user "$OPS_GROUP"
else
    CHOSEN_UID=$(pick_free_uid)
    echo "  Creating '${OPS_USER}' (UID=${CHOSEN_UID}, GID=${OPS_GID}, Home=${OPS_HOME}, Shell=/usr/bin/false, IsHidden=1)..."
    run_cmd dscl . -create "/Users/${OPS_USER}"
    run_cmd dscl . -create "/Users/${OPS_USER}" UserShell /usr/bin/false
    run_cmd dscl . -create "/Users/${OPS_USER}" RealName "Safe Server Ops Daemon"
    run_cmd dscl . -create "/Users/${OPS_USER}" UniqueID "$CHOSEN_UID"
    run_cmd dscl . -create "/Users/${OPS_USER}" PrimaryGroupID "$OPS_GID"
    run_cmd dscl . -create "/Users/${OPS_USER}" NFSHomeDirectory "$OPS_HOME"
    run_cmd dscl . -create "/Users/${OPS_USER}" Password '*'
    run_cmd dscl . -create "/Users/${OPS_USER}" IsHidden 1
    run_cmd dseditgroup -o edit -a "$OPS_USER" -t user "$OPS_GROUP"
fi

echo "[3/3] Summary:"
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  Dry-run complete. Re-run with sudo (without --dry-run) to apply."
else
    dscl . -read "/Users/${OPS_USER}" UniqueID PrimaryGroupID NFSHomeDirectory UserShell IsHidden
    cat <<EOF

Done! Next steps:
  1. Open a NEW terminal window (so '${DAILY_USER}' picks up the '${OPS_GROUP}' group; verify with 'id').
  2. Initialize isolated directories & permissions:
       sudo ./deploy/2-setup-macos-isolation.sh ${DAILY_USER}
EOF
fi
