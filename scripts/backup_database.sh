#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$PROJECT_DIR/backend/.env"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_DIR/backups}"
PG_DUMP_BIN="$(command -v pg_dump || true)"
[[ -n "$PG_DUMP_BIN" ]] || PG_DUMP_BIN="/usr/lib/postgresql/18/bin/pg_dump"
[[ -x "$PG_DUMP_BIN" ]] || { echo "pg_dump not found" >&2; exit 1; }

mapfile -d '' -t DB_CONFIG < <(
  "$PROJECT_DIR/backend/venv/bin/python" - "$ENV_FILE" <<'PY'
import os
import sys
from dotenv import dotenv_values

values = dotenv_values(sys.argv[1])
for key, default in (
    ("DB_HOST", "127.0.0.1"), ("DB_PORT", "5432"),
    ("DB_NAME", ""), ("DB_USER", ""), ("DB_PASSWORD", ""),
):
    sys.stdout.write((values.get(key) or default) + "\0")
PY
)
DB_HOST="${DB_CONFIG[0]}"
DB_PORT="${DB_CONFIG[1]}"
DB_NAME="${DB_CONFIG[2]}"
DB_USER="${DB_CONFIG[3]}"
DB_PASSWORD="${DB_CONFIG[4]}"
mkdir -p "$BACKUP_DIR"
umask 077
OUTPUT="$BACKUP_DIR/threatintel_$(date +%Y%m%d_%H%M%S).dump"
PGPASSWORD="$DB_PASSWORD" "$PG_DUMP_BIN" \
  -h "$DB_HOST" -p "$DB_PORT" \
  -U "$DB_USER" -d "$DB_NAME" -Fc -f "$OUTPUT"
echo "$OUTPUT"
