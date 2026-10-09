#!/bin/bash
# Threat Intel Pipeline -- cron isko chalata hai
# Har run ka log banta hai taaki fail hone pe pata chale (DevSecOps: observability)

set -u  # undefined variable pe error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1
source venv/bin/activate

FORCE_REFRESH=false
if [ "${1:-}" = "--force" ]; then
  FORCE_REFRESH=true
  shift
fi

if [ "$FORCE_REFRESH" != true ] && [ "$(python pipeline_monitor.py get auto_refresh_enabled)" != "true" ]; then
  echo "Automatic refresh is paused. No feeds or external APIs were contacted."
  exit 0
fi

is_configured() {
  local result
  result=$(python - "$1" <<'PY'
import os
import sys
from dotenv import load_dotenv

load_dotenv(".env")
value = os.getenv(sys.argv[1], "")
placeholders = ("your_", "bcrypt_hash_here", "random_secret_here")
print("0" if not value or value.startswith(placeholders) or value.endswith("_here") else "1")
PY
)
  [ "$result" = "1" ]
}

LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
STAMP=$(date +%Y%m%d_%H%M%S)
LOG="$LOG_DIR/pipeline_$STAMP.log"
RUN_ID=$(python pipeline_monitor.py start "$LOG")

# jo connector arg me diya wahi chalao, warna sabhi
CONNECTORS=("$@")
if [ ${#CONNECTORS[@]} -eq 0 ]; then
  CONNECTORS=(connector_threatfox connector_rl_iocs connector_cisa_kev connector_hackernews connector_nvd connector_bleeping connector_mitre_attack)
fi

echo "=== Pipeline run: $STAMP ===" | tee -a "$LOG"

for c in "${CONNECTORS[@]}"; do
  if [ "$c" = "connector_threatfox" ] && ! is_configured ABUSECH_KEY; then
    echo "    SKIP: $c (ABUSECH_KEY is not configured)" | tee -a "$LOG"
    continue
  fi
  if [ "$c" = "connector_rl_iocs" ] && { ! is_configured RL_TOKEN || ! is_configured RL_BASE; }; then
    echo "    SKIP: $c (RL_TOKEN/RL_BASE are not configured)" | tee -a "$LOG"
    continue
  fi
  if [ "$c" = "connector_mitre_attack" ] && ! is_configured MITRE_ATTACK_SYNC; then
    echo "    SKIP: $c (MITRE_ATTACK_SYNC is not enabled)" | tee -a "$LOG"
    continue
  fi
  echo "--- Running $c ---" | tee -a "$LOG"
  if python "$c.py" >> "$LOG" 2>&1; then
    echo "    OK: $c" | tee -a "$LOG"
  else
    echo "    FAIL: $c (see log)" | tee -a "$LOG"
  fi
done

# processors -- raw se clean
echo "--- Running processor_structured ---" | tee -a "$LOG"
python processor_structured.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

OLLAMA_MODEL=$(python - <<'PY'
import os
from dotenv import load_dotenv
load_dotenv(".env")
print(os.getenv("OLLAMA_MODEL", "llama3.2"))
PY
)
if curl -fsS --max-time 2 http://localhost:11434/api/tags 2>/dev/null | grep -q "\"name\":\"${OLLAMA_MODEL}"; then
  echo "--- Running processor_articles ---" | tee -a "$LOG"
  python processor_articles.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: processor_articles (Ollama $OLLAMA_MODEL is not available)" | tee -a "$LOG"
fi

if is_configured ABUSEIPDB_KEY; then
  echo "--- Running enrich_abuseipdb ---" | tee -a "$LOG"
  python enrich_abuseipdb.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: enrich_abuseipdb (ABUSEIPDB_KEY is not configured)" | tee -a "$LOG"
fi

if is_configured SHODAN_KEY; then
  echo "--- Running enrich_shodan ---" | tee -a "$LOG"
  python enrich_shodan.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: enrich_shodan (SHODAN_KEY is not configured)" | tee -a "$LOG"
fi

if is_configured VT_API_KEY; then
  echo "--- Running enrich_virustotal ---" | tee -a "$LOG"
  python enrich_virustotal.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: enrich_virustotal (VT_API_KEY is not configured)" | tee -a "$LOG"
fi

if is_configured GREYNOISE_API_KEY; then
  echo "--- Running enrich_greynoise ---" | tee -a "$LOG"
  python enrich_greynoise.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: enrich_greynoise (GREYNOISE_API_KEY is not configured)" | tee -a "$LOG"
fi

if is_configured NVD_KEY; then
  echo "--- Running enrich_cves ---" | tee -a "$LOG"
  python enrich_cves.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"
else
  echo "    SKIP: enrich_cves (NVD_KEY is not configured)" | tee -a "$LOG"
fi

echo "--- Running compute_risk ---" | tee -a "$LOG"
python compute_risk.py >> "$LOG" 2>&1 && echo "    OK" | tee -a "$LOG" || echo "    FAIL" | tee -a "$LOG"

echo "=== Done: $(date +%H:%M:%S) ===" | tee -a "$LOG"
python pipeline_monitor.py finish "$RUN_ID" "COMPLETED" >> "$LOG" 2>&1 || true

# purane log 14 din se zyada hataao (disk bloat na ho)
find "$LOG_DIR" -name "pipeline_*.log" -mtime +14 -delete
