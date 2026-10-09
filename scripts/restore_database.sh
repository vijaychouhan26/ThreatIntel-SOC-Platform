#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || "$2" != "--yes" ]]; then
  echo "Usage: $0 /absolute/path/to/backup.dump --yes" >&2
  echo "Restore overwrites objects in the configured database." >&2
  exit 2
fi

BACKUP_FILE="$(realpath "$1")"
[[ -f "$BACKUP_FILE" ]] || { echo "Backup not found: $BACKUP_FILE" >&2; exit 1; }
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mapfile -d '' -t DB_CONFIG < <(
  "$PROJECT_DIR/backend/venv/bin/python" - "$PROJECT_DIR/backend/.env" <<'PY'
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
PG_RESTORE_BIN="$(command -v pg_restore || true)"
[[ -n "$PG_RESTORE_BIN" ]] || PG_RESTORE_BIN="/usr/lib/postgresql/18/bin/pg_restore"
[[ -x "$PG_RESTORE_BIN" ]] || { echo "pg_restore not found" >&2; exit 1; }

PGPASSWORD="$DB_PASSWORD" "$PG_RESTORE_BIN" \
  -h "$DB_HOST" -p "$DB_PORT" \
  -U "$DB_USER" -d "$DB_NAME" --clean --if-exists --no-owner "$BACKUP_FILE"
echo "Database restored from $BACKUP_FILE"
