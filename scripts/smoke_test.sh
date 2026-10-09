#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:8006}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:5177}"

curl -fsS "$API_URL/auth/config" >/dev/null
curl -fsS "$FRONTEND_URL/" >/dev/null
echo "Smoke test passed: API and dashboard are reachable."
