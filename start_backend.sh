#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DATA="$ROOT_DIR/work/pgdata"
PG_LOG="$ROOT_DIR/work/postgres.log"
PG_PORT="55432"

PG_CTL="$(command -v pg_ctl || true)"
PG_ISREADY="$(command -v pg_isready || true)"
[[ -n "$PG_CTL" ]] || PG_CTL="/usr/lib/postgresql/18/bin/pg_ctl"
[[ -n "$PG_ISREADY" ]] || PG_ISREADY="/usr/lib/postgresql/18/bin/pg_isready"

if [[ ! -x "$PG_CTL" || ! -x "$PG_ISREADY" ]]; then
  echo "PostgreSQL command-line tools were not found." >&2
  exit 1
fi

if ! "$PG_CTL" status -D "$PG_DATA" >/dev/null 2>&1; then
  echo "Starting PostgreSQL on port $PG_PORT..."
  "$PG_CTL" start -D "$PG_DATA" -l "$PG_LOG"
fi

for _ in {1..20}; do
  "$PG_ISREADY" -h 127.0.0.1 -p "$PG_PORT" -d threatintel >/dev/null 2>&1 && break
  sleep 0.25
done
if ! "$PG_ISREADY" -h 127.0.0.1 -p "$PG_PORT" -d threatintel >/dev/null 2>&1; then
  echo "PostgreSQL did not become ready on port $PG_PORT." >&2
  exit 1
fi

API_HOST="${API_HOST:-127.0.0.1}"
echo "Starting ThreatIntel API on $API_HOST:8006"

if [[ "${START_WAZUH_TUNNEL:-true}" == "true" && -x "$ROOT_DIR/start_wazuh_tunnel.sh" ]]; then
  "$ROOT_DIR/start_wazuh_tunnel.sh" || echo "Warning: Wazuh VM tunnel is unavailable; backend will still start."
fi

cd "$ROOT_DIR/backend"
exec ./venv/bin/uvicorn api:app --host "$API_HOST" --port 8006
