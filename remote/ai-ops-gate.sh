#!/usr/bin/env bash
# Production server sudoers-gated command dispatcher.
# Install as root:root, chmod 755 /usr/local/bin/ai-ops-gate.sh
#
# /etc/sudoers.d/ai-ops (NEVER add ai-ops to the docker group!):
#   ai-ops ALL=(root) NOPASSWD: /usr/local/bin/ai-ops-gate.sh *
set -euo pipefail
umask 077

# ==============================================================================
# EDIT THESE WHITELISTS FOR YOUR PRODUCTION SERVER
# ==============================================================================
resolve_log_file() {
    case "$1" in
        nginx-error) echo "/var/log/nginx/error.log" ;;
        *) return 1 ;;
    esac
}

is_allowed_container() {
    case "$1" in
        web-app|nginx-proxy) return 0 ;;
        *) return 1 ;;
    esac
}

resolve_compose_dir() {
    case "$1" in
        web-stack) echo "/srv/stacks/web" ;;
        *) return 1 ;;
    esac
}

is_allowed_compose_service() {
    case "$1:$2" in
        web-stack:web|web-stack:worker) return 0 ;;
        *) return 1 ;;
    esac
}

resolve_config_spec() {
    # Format: "<config_path>|<backup_dir>"
    case "$1" in
        nginx-site) echo "/etc/nginx/conf.d/app.conf|/var/backups/ai-ops/nginx" ;;
        *) return 1 ;;
    esac
}

run_validator() {
    case "$1" in
        nginx_test) nginx -t ;;
        *) echo "Unknown validator: $1" >&2; return 1 ;;
    esac
}

run_reload() {
    case "$1" in
        nginx_reload) nginx -s reload ;;
        *) echo "Unknown reload action: $1" >&2; return 1 ;;
    esac
}
# ==============================================================================

die() { printf '%s\n' "$1" >&2; exit 1; }

valid_pos_int() {
    [[ "$1" =~ ^[1-9][0-9]{0,3}$ ]] && [[ "$1" -le 5000 ]]
}

action="${1:-}"
shift || true

case "$action" in
    logs-file)
        [[ $# -eq 2 ]] || die "Usage: logs-file <log_id> <lines>"
        log_path=$(resolve_log_file "$1") || die "Log ID not whitelisted: $1"
        valid_pos_int "$2" || die "Invalid line count: $2"
        exec tail -n "$2" -- "$log_path"
        ;;

    logs-docker)
        [[ $# -eq 2 ]] || die "Usage: logs-docker <container> <lines>"
        is_allowed_container "$1" || die "Container not whitelisted: $1"
        valid_pos_int "$2" || die "Invalid line count: $2"
        exec docker logs --tail "$2" -- "$1"
        ;;

    docker-status)
        [[ $# -eq 1 ]] || die "Usage: docker-status <container>"
        is_allowed_container "$1" || die "Container not whitelisted: $1"
        exec docker inspect --format '{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t{{.RestartCount}}\t{{.State.StartedAt}}' -- "$1"
        ;;

    docker-restart)
        [[ $# -eq 1 ]] || die "Usage: docker-restart <container>"
        is_allowed_container "$1" || die "Container not whitelisted: $1"
        exec docker restart -- "$1"
        ;;

    compose-status)
        [[ $# -eq 2 ]] || die "Usage: compose-status <stack_id> <service>"
        cdir=$(resolve_compose_dir "$1") || die "Compose stack not whitelisted: $1"
        is_allowed_compose_service "$1" "$2" || die "Compose service not whitelisted: $1:$2"
        exec docker compose --project-directory "$cdir" ps --format '{{.Name}}\t{{.State}}\t{{.Health}}\t{{.Status}}' "$2"
        ;;

    compose-restart)
        [[ $# -eq 2 ]] || die "Usage: compose-restart <stack_id> <service>"
        cdir=$(resolve_compose_dir "$1") || die "Compose stack not whitelisted: $1"
        is_allowed_compose_service "$1" "$2" || die "Compose service not whitelisted: $1:$2"
        exec docker compose --project-directory "$cdir" restart "$2"
        ;;

    compose-logs)
        [[ $# -eq 3 ]] || die "Usage: compose-logs <stack_id> <service> <lines>"
        cdir=$(resolve_compose_dir "$1") || die "Compose stack not whitelisted: $1"
        is_allowed_compose_service "$1" "$2" || die "Compose service not whitelisted: $1:$2"
        valid_pos_int "$3" || die "Invalid line count: $3"
        exec docker compose --project-directory "$cdir" logs --tail "$3" "$2"
        ;;

    config-read)
        [[ $# -eq 1 ]] || die "Usage: config-read <config_id>"
        spec=$(resolve_config_spec "$1") || die "Config ID not whitelisted: $1"
        cfg_path="${spec%%|*}"
        exec cat -- "$cfg_path"
        ;;

    config-validate)
        [[ $# -eq 2 ]] || die "Usage: config-validate <config_id> <validator>"
        spec=$(resolve_config_spec "$1") || die "Config ID not whitelisted: $1"
        cfg_path="${spec%%|*}"
        validator="$2"
        # Validate candidate by swapping safely into a temporary validation sandbox or backup-and-restore test
        tmp_new=$(mktemp "${cfg_path}.validate.XXXXXX")
        tmp_orig=$(mktemp "${cfg_path}.orig.XXXXXX")
        cleanup_val() {
            rm -f -- "$tmp_new" "$tmp_orig"
        }
        trap cleanup_val EXIT
        cat >"$tmp_new"
        cp -p -- "$cfg_path" "$tmp_orig"
        chmod --reference="$cfg_path" "$tmp_new" 2>/dev/null || true
        chown --reference="$cfg_path" "$tmp_new" 2>/dev/null || true
        mv -f -- "$tmp_new" "$cfg_path"
        rc=0
        run_validator "$validator" || rc=$?
        mv -f -- "$tmp_orig" "$cfg_path"
        exit "$rc"
        ;;

    config-apply)
        [[ $# -ge 1 ]] || die "Usage: config-apply <config_id> [--validator=V] [--reload=R]"
        cfg_id="$1"; shift
        spec=$(resolve_config_spec "$cfg_id") || die "Config ID not whitelisted: $cfg_id"
        cfg_path="${spec%%|*}"
        bak_dir="${spec#*|}"
        validator=""
        reload_act=""
        for opt in "$@"; do
            case "$opt" in
                --validator=*) validator="${opt#--validator=}" ;;
                --reload=*) reload_act="${opt#--reload=}" ;;
                *) die "Unsupported option: $opt" ;;
            esac
        done

        mkdir -p -- "$bak_dir"
        backup_id="${cfg_id}.$(date -u +%Y%m%dT%H%M%SZ).bak"
        backup_path="${bak_dir}/${backup_id}"
        cp -p -- "$cfg_path" "$backup_path"

        tmp_new=$(mktemp "${cfg_path}.apply.XXXXXX")
        cat >"$tmp_new"
        chmod --reference="$cfg_path" "$tmp_new" 2>/dev/null || true
        chown --reference="$cfg_path" "$tmp_new" 2>/dev/null || true
        mv -f -- "$tmp_new" "$cfg_path"

        if [[ -n "$validator" ]]; then
            if ! run_validator "$validator" >&2; then
                cp -p -- "$backup_path" "$cfg_path"
                printf '{"backup_id":"%s","reloaded":false,"rolled_back":true}\n' "$backup_id"
                exit 1
            fi
        fi

        reloaded="false"
        if [[ -n "$reload_act" ]]; then
            if ! run_reload "$reload_act" >&2; then
                cp -p -- "$backup_path" "$cfg_path"
                run_reload "$reload_act" >&2 || true
                printf '{"backup_id":"%s","reloaded":false,"rolled_back":true}\n' "$backup_id"
                exit 1
            fi
            reloaded="true"
        fi

        printf '{"backup_id":"%s","reloaded":%s,"rolled_back":false}\n' "$backup_id" "$reloaded"
        ;;

    config-backups)
        [[ $# -eq 1 ]] || die "Usage: config-backups <config_id>"
        spec=$(resolve_config_spec "$1") || die "Config ID not whitelisted: $1"
        bak_dir="${spec#*|}"
        [[ -d "$bak_dir" ]] || exit 0
        ls -1t -- "$bak_dir" | grep -E "^${1}\..+\.bak$" || true
        ;;

    config-rollback)
        [[ $# -ge 2 ]] || die "Usage: config-rollback <config_id> <backup_id> [--validator=V] [--reload=R]"
        cfg_id="$1"; backup_id="$2"; shift 2
        spec=$(resolve_config_spec "$cfg_id") || die "Config ID not whitelisted: $cfg_id"
        cfg_path="${spec%%|*}"
        bak_dir="${spec#*|}"
        [[ "$backup_id" =~ ^[A-Za-z0-9._-]+\.bak$ ]] || die "Invalid backup_id."
        backup_path="${bak_dir}/${backup_id}"
        [[ -f "$backup_path" ]] || die "Backup not found: $backup_id"

        validator=""
        reload_act=""
        for opt in "$@"; do
            case "$opt" in
                --validator=*) validator="${opt#--validator=}" ;;
                --reload=*) reload_act="${opt#--reload=}" ;;
                *) die "Unsupported option: $opt" ;;
            esac
        done

        cp -p -- "$backup_path" "$cfg_path"
        if [[ -n "$validator" ]]; then
            run_validator "$validator"
        fi
        if [[ -n "$reload_act" ]]; then
            run_reload "$reload_act"
        fi
        printf 'Rolled back %s to %s\n' "$cfg_id" "$backup_id"
        ;;

    *)
        die "Action not permitted: ${action:-<empty>}"
        ;;
esac
