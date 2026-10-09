"""Safe, hybrid chatbot for threat-intelligence questions with LLM fallback."""
import os
import re
import json
import requests
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

DB_SCHEMA_CONTEXT = """
Database Schema (PostgreSQL):
1. iocs (id, ioc_type, value, malware, threat_type, reason, confidence, first_seen, last_seen, times_seen, is_active, risk_score, risk_level)
2. ioc_enrichment (ioc_id, abuse_score, abuse_reports, abuse_country, abuse_isp, abuse_usage, shodan_ports, shodan_org, enriched_at)
3. ioc_sightings (id, ioc_id, source, seen_at, raw_item_id)
4. cves (id, cve_id, cvss_score, severity, description, kev_listed, published, first_seen, last_seen, "references", affected_products)
5. articles (id, title, link, published, summary, apt_groups, malware, fetched_at)
6. apt_groups (id, name, first_seen, last_seen, times_seen, description, aliases, target_sectors, origin_country)
7. raw_items (id, source, kind, data, content_hash, processed, fetched_at)
"""

def _query(sql, params=()):
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("API_DB_USER", os.getenv("DB_USER")),
        password=os.getenv("API_DB_PASSWORD", os.getenv("DB_PASSWORD")),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout = '10s'")
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

def _result(rows, sql=None):
    return {"count": len(rows), "rows": rows, "sql": sql}

def call_ollama(prompt, system=""):
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json={
            "model": OLLAMA_MODEL,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }, timeout=30)
        if resp.status_code == 200:
            return json.loads(resp.json()["response"])
    except Exception as e:
        print(f"Ollama error: {e}")
    return None

def call_ollama_text(prompt, system=""):
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json={
            "model": OLLAMA_MODEL,
            "system": system,
            "prompt": prompt,
            "stream": False
        }, timeout=30)
        if resp.status_code == 200:
            return resp.json()["response"]
    except Exception as e:
        print(f"Ollama error: {e}")
    return None

def llm_fallback(question):
    system_prompt = f"""You are a SQL generator for a threat intelligence platform.
{DB_SCHEMA_CONTEXT}
Generate a PostgreSQL SELECT query to answer the user's question.
Only SELECT is allowed. Always use LIMIT (max 50).
Return ONLY valid JSON with exactly two keys: "sql" and "explanation".
"""

    gen_result = call_ollama(question, system_prompt)
    if not gen_result or "sql" not in gen_result:
        return {"error": "LLM features are currently unavailable or failed to generate SQL."}

    sql = gen_result.get("sql", "").strip()
    explanation = gen_result.get("explanation", "")

    # Validation
    if not sql.upper().startswith("SELECT"):
        return {"error": "Invalid SQL generated: Must start with SELECT."}

    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "GRANT", "REVOKE"]
    sql_upper = sql.upper()
    for word in forbidden:
        if re.search(rf"\b{word}\b", sql_upper):
            return {"error": f"Invalid SQL generated: Contains forbidden keyword {word}."}

    try:
        rows = _query(sql)
    except Exception as e:
        return {"error": f"Error executing generated SQL: {e}", "sql": sql}

    # Summarize with LLM
    summary_prompt = f"Question: {question}\nSQL Explanation: {explanation}\nSQL Results: {json.dumps(rows[:10], default=str)}\nSummarize the findings in a concise, human-readable way."

    answer = call_ollama_text(summary_prompt, "You are a threat analyst providing a helpful summary of database results.")
    if not answer:
        answer = explanation

    return {
        "answer": answer,
        "sql": sql,
        "rows": rows,
        "explanation": explanation
    }

def chat_query(question: str):
    """Map plain English to allow-listed parameterized SELECT queries only."""
    q = re.sub(r"[-_]+", " ", (question or "").strip().lower())
    if not q:
        return {"error": "Ask about IOC counts, CVEs, APT groups, risk, or malware."}

    if re.search(r"\b(hi|hello|help)\b", q):
        return {"count": 0, "rows": [], "message": (
            "Try: 'show VirusTotal detections', 'show malicious GreyNoise IPs', "
            "'what techniques does APT29 use', or 'latest high-risk threats'."
        )}

    actor_match = re.search(r"\b(?:apt|unc|ta)[ -]?\d{1,5}\b", q, flags=re.IGNORECASE)
    if actor_match and ("technique" in q or "ttp" in q or "attack mapping" in q):
        actor_key = re.sub(r"[- ]", "", actor_match.group(0).lower())
        return _result(_query(
            "SELECT group_name, technique_id, technique_name, tactics "
            "FROM apt_techniques WHERE regexp_replace(lower(group_name), '[- ]', '', 'g') = %s "
            "ORDER BY technique_id LIMIT 50",
            (actor_key,),
        ))

    if "virustotal" in q or "virus total" in q or re.search(r"\bvt\b", q):
        return _result(_query(
            "SELECT i.ioc_type, i.value, i.malware, e.vt_malicious, e.vt_suspicious, e.vt_reputation "
            "FROM iocs i JOIN ioc_enrichment e ON e.ioc_id=i.id "
            "WHERE COALESCE(e.vt_malicious, 0) > 0 "
            "ORDER BY e.vt_malicious DESC, e.vt_suspicious DESC, i.last_seen DESC LIMIT 50"
        ))

    if "greynoise" in q or "grey noise" in q:
        malicious_only = "malicious" in q
        return _result(_query(
            "SELECT i.value AS ip, i.malware, i.risk_score, e.greynoise_noise, e.greynoise_riot, "
            "e.greynoise_classification, e.greynoise_name, e.greynoise_last_seen "
            "FROM iocs i JOIN ioc_enrichment e ON e.ioc_id=i.id "
            "WHERE i.ioc_type='ip' AND e.greynoise_noise IS NOT NULL "
            + ("AND lower(COALESCE(e.greynoise_classification, '')) = 'malicious' " if malicious_only else "")
            + "ORDER BY i.risk_score DESC, e.greynoise_last_seen DESC NULLS LAST LIMIT 50"
        ))

    if "apt" in q and ("group" in q or "show" in q or "list" in q):
        return _result(_query(
            "SELECT name, times_seen, first_seen, last_seen "
            "FROM apt_groups ORDER BY times_seen DESC, name LIMIT 50"
        ))

    if any(term in q for term in ("news", "latest", "recent", "important")) and \
       any(term in q for term in ("news", "article", "feed", "threat", "update", "important")) and "high risk" not in q:
        return _result(_query(
            "SELECT title, published, link FROM articles ORDER BY id DESC LIMIT 10"
        ))

    severity_match = re.search(r"\b(critical|high|medium|low)\b", q)
    if severity_match and ("cve" in q or "vulnerabilit" in q):
        severity = severity_match.group(1).upper()
        return _result(_query(
            "SELECT cve_id, cvss_score, severity, kev_listed "
            "FROM cves WHERE severity = %s ORDER BY cvss_score DESC NULLS LAST LIMIT 50",
            (severity,),
        ))

    if ("how many" in q or "count" in q) and ("cve" in q or "vulnerabilit" in q):
        return _result(_query("SELECT COUNT(*)::int AS total_cves FROM cves"))

    if ("how many" in q or "count" in q) and ("ioc" in q or "indicator" in q):
        return _result(_query("SELECT COUNT(*)::int AS total_iocs FROM iocs"))

    if ("latest" in q or "recent" in q) and "high risk" in q:
        return _result(_query(
            "SELECT ioc_type, value, malware, risk_score, risk_level, last_seen "
            "FROM iocs WHERE risk_level='HIGH' ORDER BY last_seen DESC, risk_score DESC LIMIT 50"
        ))

    if "high risk" in q:
        return _result(_query(
            "SELECT ioc_type, value, malware, risk_score, risk_level "
            "FROM iocs WHERE risk_level = 'HIGH' ORDER BY risk_score DESC, last_seen DESC LIMIT 50"
        ))

    if "risk" in q and any(level in q for level in ("high", "medium", "low")):
        level = next(level.upper() for level in ("high", "medium", "low") if level in q)
        return _result(_query(
            "SELECT ioc_type, value, malware, risk_score, risk_level FROM iocs "
            "WHERE risk_level=%s ORDER BY risk_score DESC, last_seen DESC LIMIT 50",
            (level,),
        ))

    if "malware" in q and ("indicator" in q or "ioc" in q or "show" in q or "list" in q):
        return _result(_query(
            "SELECT ioc_type, value, malware, risk_score, risk_level "
            "FROM iocs WHERE malware IS NOT NULL AND malware <> '' "
            "ORDER BY risk_score DESC, last_seen DESC LIMIT 50"
        ))

    if "top malware" in q or "most common malware" in q:
        return _result(_query(
            "SELECT malware, COUNT(*)::int AS indicators FROM iocs "
            "WHERE malware IS NOT NULL AND malware <> '' GROUP BY malware "
            "ORDER BY indicators DESC, malware LIMIT 20"
        ))

    malware_match = re.search(r"(?:show|list)\s+(.+?)\s+(?:ip|ips|ioc|iocs|indicator|indicators)\b", q)
    if malware_match:
        malware = malware_match.group(1).strip()
        return _result(_query(
            "SELECT ioc_type, value, malware, risk_score, risk_level "
            "FROM iocs WHERE malware ILIKE %s "
            "ORDER BY risk_score DESC, last_seen DESC LIMIT 50",
            (f"%{malware}%",),
        ))

    # LLM Fallback
    return llm_fallback(question)
