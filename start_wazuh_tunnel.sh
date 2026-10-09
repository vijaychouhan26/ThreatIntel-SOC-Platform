#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_USER="${WAZUH_VM_USER:-ubuntuser}"
VM_HOST="${WAZUH_VM_HOST:-192.168.56.101}"
SSH_KEY="${WAZUH_SSH_KEY:-/home/kali/.ssh/id_ed25519_wazuh_cti}"
CONTROL_SOCKET="/tmp/threatintel-wazuh-tunnel.sock"
KNOWN_HOSTS="$ROOT_DIR/work/wazuh-known-hosts"

mkdir -p "$ROOT_DIR/work"

if ssh -F /dev/null -S "$CONTROL_SOCKET" -O check "$VM_USER@$VM_HOST" >/dev/null 2>&1; then
  echo "Wazuh tunnel is already running."
  exit 0
fi

rm -f "$CONTROL_SOCKET"
ssh -F /dev/null \
  -M -S "$CONTROL_SOCKET" -fNT \
  -i "$SSH_KEY" \
  -o BatchMode=yes \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  -R 127.0.0.1:18006:127.0.0.1:8006 \
  "$VM_USER@$VM_HOST"

echo "Wazuh tunnel ready: VM 127.0.0.1:18006 -> Kali 127.0.0.1:8006"
