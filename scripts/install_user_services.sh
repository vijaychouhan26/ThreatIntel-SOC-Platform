#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$UNIT_DIR"

for name in threatintel-api threatintel-wazuh-tunnel; do
  sed \
    -e "s|@PROJECT_DIR@|$PROJECT_DIR|g" \
    -e "s|@USER_HOME@|$HOME|g" \
    "$PROJECT_DIR/deploy/systemd/$name.service.in" > "$UNIT_DIR/$name.service"
done

systemctl --user daemon-reload
systemctl --user enable --now threatintel-api.service threatintel-wazuh-tunnel.service
echo "ThreatIntel API and Wazuh tunnel user services are enabled."
