#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_USER="${WAZUH_VM_USER:-ubuntuser}"
VM_HOST="${WAZUH_VM_HOST:-192.168.56.101}"
CONTROL_SOCKET="/tmp/threatintel-wazuh-tunnel.sock"

if [[ -S "$CONTROL_SOCKET" ]]; then
  ssh -F /dev/null -S "$CONTROL_SOCKET" -O exit "$VM_USER@$VM_HOST" >/dev/null
  echo "Wazuh tunnel stopped."
else
  echo "Wazuh tunnel is not running."
fi
