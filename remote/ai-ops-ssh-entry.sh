#!/usr/bin/env bash
# Production server ForceCommand entry point for ~/.ssh/authorized_keys:
#   command="/usr/local/bin/ai-ops-ssh-entry.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... ai-ops
#
# Works for dedicated 'ai-ops' account, existing non-root sudo account, or existing root account.
# Install as root:root, chmod 755 /usr/local/bin/ai-ops-ssh-entry.sh
set -euo pipefail

if [[ -z "${SSH_ORIGINAL_COMMAND:-}" ]]; then
    echo "Interactive shell access is disabled for this AI ops key." >&2
    exit 126
fi

# Strictly reject shell metacharacters before tokenizing
if [[ "$SSH_ORIGINAL_COMMAND" =~ [\;\|\&\$\`\<\>\\] ]]; then
    echo "Rejected disallowed shell metacharacters in command." >&2
    exit 126
fi

# Split safely on whitespace (no globbing)
set -f
# shellcheck disable=SC2206
argv=($SSH_ORIGINAL_COMMAND)
set +f

if [[ ${#argv[@]} -eq 0 ]]; then
    echo "Empty command." >&2
    exit 126
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    exec /usr/local/bin/ai-ops-gate.sh "${argv[@]}"
else
    exec sudo -n /usr/local/bin/ai-ops-gate.sh "${argv[@]}"
fi
