#!/bin/bash
# Installs one safe daily refresh at 03:15 local time. Re-running is idempotent.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON_LINE="15 3 * * * $SCRIPT_DIR/run_pipeline.sh >> $SCRIPT_DIR/logs/scheduled_refresh.log 2>&1 # threatintel-refresh"
(crontab -l 2>/dev/null | grep -v 'threatintel-refresh' || true; echo "$CRON_LINE") | crontab -
echo "Scheduled daily refresh installed: 03:15 local time"
