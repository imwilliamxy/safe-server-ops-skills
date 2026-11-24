#!/usr/bin/env bash
# Production server ForceCommand entry point for ~/.ssh/authorized_keys:
#   command="/usr/local/bin/ai-ops-ssh-entry.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... ai-ops
#
# Install as root:root, chmod 755 /usr/local/bin/ai-ops-ssh-entry.sh
set -euo pipefail

if [[ -z "${SSH_ORIGINAL_COMMAND:-}" ]]; then
    echo "Interactive shell access is disabled for ai-ops." >&2
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

exec sudo -n /usr/local/bin/ai-ops-gate.sh "${argv[@]}"
