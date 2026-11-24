#!/usr/bin/env bash
# Add or import server profiles into /Users/sshops/.local/config/opsd/.ssh-servers.env,
# fetch & trust SSH host keys into /Users/sshops/.ssh/known_hosts, and reload opsd.
#
# Supports BOTH:
#   1. Interactive single-server addition:
#        sudo ./deploy/4-add-server.sh
#   2. Direct conversion/import from ssh_login.sh's ~/.local/config/ssh_login/.ssh-servers.env:
#        sudo ./deploy/4-add-server.sh --import-ssh-login [--only a,b] [--key-mode ai|copy]
#
# Original ssh_login.sh config and original private key files are NEVER modified, moved, or chmod'd.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  sudo ./deploy/4-add-server.sh                                # Interactive mode
  sudo ./deploy/4-add-server.sh --import-ssh-login [options]   # Import from $SUDO_USER's ssh_login.sh config
  sudo ./deploy/4-add-server.sh --import-from <file> [options] # Import from a specific .ssh-servers.env file

Import options:
  --key-mode <ai|copy>   How to set KEY_FILE for imported profiles (default: ai)
                           ai   : Point KEY_FILE to /Users/sshops/.ssh/id_ed25519_ai_ops
                                  (and SYNC_KEY_FILE to id_ed25519_ai_rrsync if present). Recommended.
                           copy : Copy each original key into /Users/sshops/.ssh/imported_<alias>_key
                                  (chmod 600, owned by sshops). Original key is NEVER modified.
  --only <a,b,...>       Only import the listed comma-separated server aliases
  --no-scan              Skip ssh-keyscan host key discovery
  --trust-all            Auto-trust scanned host keys without interactive prompt
  --dry-run              Preview what would be imported without writing any files
  -h, --help             Show this help message
EOF
}

IMPORT_FILE=""
IMPORT_DEFAULT_SSH_LOGIN=0
KEY_MODE="ai"
ONLY_LIST=""
DO_SCAN=1
TRUST_ALL=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --import-ssh-login) IMPORT_DEFAULT_SSH_LOGIN=1; shift ;;
        --import-from)
            [[ $# -ge 2 ]] || { echo "ERROR: --import-from requires a file path." >&2; exit 1; }
            IMPORT_FILE="$2"; shift 2 ;;
        --key-mode)
            [[ $# -ge 2 ]] || { echo "ERROR: --key-mode requires 'ai' or 'copy'." >&2; exit 1; }
            KEY_MODE="$2"; shift 2 ;;
        --only)
            [[ $# -ge 2 ]] || { echo "ERROR: --only requires a comma-separated alias list." >&2; exit 1; }
            ONLY_LIST="$2"; shift 2 ;;
        --no-scan) DO_SCAN=0; shift ;;
        --trust-all) TRUST_ALL=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

[[ "$KEY_MODE" == "ai" || "$KEY_MODE" == "copy" ]] || {
    echo "ERROR: --key-mode must be 'ai' or 'copy'." >&2; exit 1;
}

if [[ "$DRY_RUN" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Please run with sudo: sudo $0 $*" >&2
    exit 1
fi

OPS_USER="sshops"
OPS_GROUP="opsclients"
OPS_HOME="/Users/${OPS_USER}"
ENV_FILE="${OPS_HOME}/.local/config/opsd/.ssh-servers.env"
KNOWN_HOSTS="${OPS_HOME}/.ssh/known_hosts"
DEFAULT_OPS_KEY="${OPS_HOME}/.ssh/id_ed25519_ai_ops"
DEFAULT_SYNC_KEY="${OPS_HOME}/.ssh/id_ed25519_ai_rrsync"

if [[ "$DRY_RUN" -eq 0 ]] && ! id "$OPS_USER" >/dev/null 2>&1; then
    echo "ERROR: User '${OPS_USER}' not found. Run 'sudo ./deploy/0-bootstrap-macos.sh <username>' first." >&2
    exit 1
fi

SOURCE_USER="${SUDO_USER:-${USER:-}}"
SOURCE_HOME=""
if [[ -n "$SOURCE_USER" && "$SOURCE_USER" != "root" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        SOURCE_HOME=$(dscl . -read "/Users/${SOURCE_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)
    fi
fi
[[ -n "$SOURCE_HOME" ]] || SOURCE_HOME="${HOME:-}"

if [[ "$IMPORT_DEFAULT_SSH_LOGIN" -eq 1 ]]; then
    IMPORT_FILE="${SOURCE_HOME}/.local/config/ssh_login/.ssh-servers.env"
fi

scan_and_trust_host() {
    local host_val="$1" port_val="$2"
    [[ "$DO_SCAN" -eq 1 ]] || return 0
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [dry-run] Would ssh-keyscan -p ${port_val} ${host_val} into ${KNOWN_HOSTS}"
        return 0
    fi
    echo "  Scanning SSH host key for ${host_val}:${port_val}..."
    local tmp_scan
    tmp_scan=$(mktemp)
    if ssh-keyscan -p "$port_val" -T 10 "$host_val" >"$tmp_scan" 2>/dev/null && [[ -s "$tmp_scan" ]]; then
        ssh-keygen -lf "$tmp_scan" | sed 's/^/    /'
        local trust_ans="Y"
        if [[ "$TRUST_ALL" -eq 0 ]]; then
            read -r -p "  Trust and add these host keys to ${KNOWN_HOSTS}? [Y/n]: " trust_ans
        fi
        if [[ "${trust_ans:-Y}" =~ ^[Yy]$ ]]; then
            cat "$tmp_scan" >>"$KNOWN_HOSTS"
            sort -u "$KNOWN_HOSTS" -o "$KNOWN_HOSTS"
            chown "${OPS_USER}:${OPS_GROUP}" "$KNOWN_HOSTS"
            chmod 600 "$KNOWN_HOSTS"
            echo "  Updated ${KNOWN_HOSTS}"
        fi
    else
        echo "  WARNING: ssh-keyscan failed or timed out for ${host_val}:${port_val}." >&2
    fi
    rm -f -- "$tmp_scan"
}

alias_exists_in_target() {
    local target_alias="$1"
    [[ -f "$ENV_FILE" ]] && grep -qE "^\[${target_alias}\][[:space:]]*$" "$ENV_FILE"
}

append_profile_atomic() {
    local a_name="$1" h_val="$2" u_val="$3" p_val="$4" k_val="$5" sk_val="$6"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [dry-run] Would append [${a_name}] (USER=${u_val}, PORT=${p_val}, KEY_FILE=${k_val}${sk_val:+, SYNC_KEY_FILE=${sk_val}})"
        return 0
    fi
    umask 077
    local tmp_env
    tmp_env=$(mktemp "${ENV_FILE}.XXXXXX")
    if [[ -f "$ENV_FILE" ]]; then
        cat -- "$ENV_FILE" >"$tmp_env"
        printf '\n' >>"$tmp_env"
    else
        printf '# SSH server profiles: literal values, never shell code.\n' >"$tmp_env"
    fi
    {
        printf '\n[%s]\n' "$a_name"
        printf 'HOST=%s\n' "$h_val"
        printf 'USER=%s\n' "$u_val"
        printf 'PORT=%s\n' "$p_val"
        printf 'KEY_FILE=%s\n' "$k_val"
        if [[ -n "$sk_val" ]]; then
            printf 'SYNC_KEY_FILE=%s\n' "$sk_val"
        fi
    } >>"$tmp_env"
    chown "${OPS_USER}:${OPS_GROUP}" "$tmp_env"
    chmod 600 "$tmp_env"
    mv -f -- "$tmp_env" "$ENV_FILE"
}

reload_opsd_if_running() {
    [[ "$DRY_RUN" -eq 0 ]] || return 0
    if command -v launchctl >/dev/null 2>&1 && launchctl print system/com.local.safe-server-opsd >/dev/null 2>&1; then
        echo "Reloading opsd..."
        launchctl kickstart -k system/com.local.safe-server-opsd
    fi
}

alias_selected() {
    local candidate="$1"
    [[ -z "$ONLY_LIST" ]] && return 0
    local IFS=',' item
    for item in $ONLY_LIST; do
        [[ "$item" == "$candidate" ]] && return 0
    done
    return 1
}

resolve_source_key() {
    local raw="$1" src_dir="$2"
    case "$raw" in
        '~/'*) printf '%s/%s\n' "$SOURCE_HOME" "${raw:2}" ;;
        /*)    printf '%s\n' "$raw" ;;
        *)     printf '%s/%s\n' "$src_dir" "$raw" ;;
    esac
}

# ==============================================================================
# Mode 1: Import & convert existing ssh_login.sh .ssh-servers.env (literal parse)
# ==============================================================================
if [[ -n "$IMPORT_FILE" ]]; then
    [[ ! -L "$IMPORT_FILE" && -f "$IMPORT_FILE" ]] || {
        echo "ERROR: Source config file not found or is a symlink: ${IMPORT_FILE}" >&2
        exit 1
    }
    SRC_DIR="$(cd -- "$(dirname -- "$IMPORT_FILE")" && pwd)"
    echo "Importing from: ${IMPORT_FILE} (key-mode=${KEY_MODE})"

    aliases=(); hosts=(); users=(); ports=(); keys=()
    count=0
    idx=-1
    section_re='^\[([a-z][a-z0-9_-]{0,31})\][[:space:]]*$'
    lineno=0

    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        lineno=$((lineno + 1))
        line=${raw_line%$'\r'}
        line=${line#"${line%%[![:space:]]*}"}
        [[ -n "$line" && "$line" != \#* ]] || continue
        if [[ "$line" =~ $section_re ]]; then
            idx=$count
            aliases[idx]="${BASH_REMATCH[1]}"
            hosts[idx]=''; users[idx]=''; ports[idx]='22'; keys[idx]=''
            count=$((count + 1))
            continue
        fi
        [[ "$idx" -ge 0 && "$line" == *=* ]] || {
            echo "ERROR: Malformed line ${lineno} in ${IMPORT_FILE}." >&2; exit 1;
        }
        k=${line%%=*}
        k=${k%"${k##*[![:space:]]}"}
        v=${line#*=}
        v=${v#"${v%%[![:space:]]*}"}
        if [[ ${#v} -ge 2 ]]; then
            case "$v" in
                \"*\"|\'*\') v=${v:1:${#v}-2} ;;
            esac
        fi
        case "$k" in
            HOST) hosts[idx]="$v" ;;
            USER) users[idx]="$v" ;;
            PORT) ports[idx]="$v" ;;
            KEY_FILE) keys[idx]="$v" ;;
            SYNC_KEY_FILE) ;;
            *) echo "ERROR: Unsupported field '${k}' at line ${lineno}." >&2; exit 1 ;;
        esac
    done <"$IMPORT_FILE"

    if [[ "$count" -eq 0 ]]; then
        echo "No server profiles found in ${IMPORT_FILE}."
        exit 0
    fi

    imported=0
    for ((i=0; i<count; i++)); do
        a="${aliases[i]}"
        h="${hosts[i]}"
        u="${users[i]}"
        p="${ports[i]}"
        src_k="${keys[i]}"

        if ! alias_selected "$a"; then
            continue
        fi
        if [[ -z "$h" || -z "$u" || -z "$p" || -z "$src_k" ]]; then
            echo "WARNING: Skipping [${a}] due to missing required fields." >&2
            continue
        fi
        if alias_exists_in_target "$a"; then
            echo "Skipping [${a}]: already exists in ${ENV_FILE}."
            continue
        fi

        echo "Processing [${a}]..."
        target_key=""
        target_sync_key=""

        if [[ "$KEY_MODE" == "ai" ]]; then
            target_key="$DEFAULT_OPS_KEY"
            if [[ -s "$DEFAULT_SYNC_KEY" ]]; then
                target_sync_key="$DEFAULT_SYNC_KEY"
            fi
        else
            resolved_src_k=$(resolve_source_key "$src_k" "$SRC_DIR")
            if [[ ! -f "$resolved_src_k" || ! -s "$resolved_src_k" ]]; then
                echo "WARNING: Skipping [${a}]: original KEY_FILE not found or empty (${resolved_src_k})." >&2
                continue
            fi
            target_key="${OPS_HOME}/.ssh/imported_${a}_key"
            if [[ "$DRY_RUN" -eq 1 ]]; then
                echo "  [dry-run] Would copy original key -> ${target_key} (chmod 600, owned by ${OPS_USER}; original untouched)"
            else
                install -m 600 -o "$OPS_USER" -g "$OPS_GROUP" "$resolved_src_k" "$target_key"
                echo "  Copied key to ${target_key} (original key untouched)"
            fi
        fi

        scan_and_trust_host "$h" "$((10#$p))"
        append_profile_atomic "$a" "$h" "$u" "$((10#$p))" "$target_key" "$target_sync_key"
        imported=$((imported + 1))
    done

    echo "Import finished: ${imported} profile(s) processed."
    if [[ "$imported" -gt 0 ]]; then
        reload_opsd_if_running
        echo "Next: declare whitelists (logs/docker/configs/sync_targets) for imported server(s) in ${OPS_HOME}/.local/config/opsd/policy.yaml."
    fi
    exit 0
fi

# ==============================================================================
# Mode 2: Interactive single-server addition
# ==============================================================================
read -r -p "Server logical alias (e.g. prod-web-1): " alias_name
[[ "$alias_name" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || { echo "ERROR: Invalid alias format." >&2; exit 1; }

if alias_exists_in_target "$alias_name"; then
    echo "ERROR: Alias '[${alias_name}]' already exists in ${ENV_FILE}." >&2
    exit 1
fi

read -r -p "Remote host (IP or domain): " host_val
[[ "$host_val" =~ ^[A-Za-z0-9:][A-Za-z0-9_.:%-]*$ ]] || { echo "ERROR: Invalid host format." >&2; exit 1; }

read -r -p "Remote SSH username (existing user or ai-ops): " user_val
[[ "$user_val" =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*\$?$ ]] || { echo "ERROR: Invalid username format." >&2; exit 1; }

read -r -p "Remote SSH port [22]: " port_val
port_val="${port_val:-22}"
[[ "$port_val" =~ ^[0-9]{1,5}$ ]] && (( 10#$port_val >= 1 && 10#$port_val <= 65535 )) || {
    echo "ERROR: Port must be 1-65535." >&2; exit 1;
}
port_val=$((10#$port_val))

read -r -p "Ops private key path [${DEFAULT_OPS_KEY}]: " key_val
key_val="${key_val:-$DEFAULT_OPS_KEY}"
[[ "$DRY_RUN" -eq 1 || ( -f "$key_val" && -s "$key_val" ) ]] || {
    echo "ERROR: Key file does not exist or is empty: ${key_val}" >&2; exit 1;
}

read -r -p "Rsync private key path (optional) [${DEFAULT_SYNC_KEY}]: " sync_key_val
sync_key_val="${sync_key_val:-$DEFAULT_SYNC_KEY}"
if [[ -n "$sync_key_val" && "$DRY_RUN" -eq 0 && ! -s "$sync_key_val" ]]; then
    echo "  Note: ${sync_key_val} not found; omitting SYNC_KEY_FILE."
    sync_key_val=""
fi

scan_and_trust_host "$host_val" "$port_val"
append_profile_atomic "$alias_name" "$host_val" "$user_val" "$port_val" "$key_val" "$sync_key_val"
echo "Saved [${alias_name}] to ${ENV_FILE}."
reload_opsd_if_running
echo "Done! Remember to also declare '${alias_name}' in ${OPS_HOME}/.local/config/opsd/policy.yaml."
