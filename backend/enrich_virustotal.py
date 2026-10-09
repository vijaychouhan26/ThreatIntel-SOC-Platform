"""Rate-limited VirusTotal reputation enrichment for supported IOC types."""
import base64
import os
import time

import psycopg2
import requests
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv("VT_API_KEY")
BATCH = min(int(os.getenv("VT_BATCH", "4")), 4)  # Community API: 4 requests/minute
TYPE_PATH = {"ip": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files"}

if not KEY:
    raise SystemExit("VT_API_KEY is not configured")

conn = psycopg2.connect(host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"), dbname=os.getenv("DB_NAME"),
                        user=os.getenv("DB_USER"), password=os.getenv("DB_PASSWORD"))
cur = conn.cursor()
cur.execute("""SELECT i.id, i.ioc_type, i.value FROM iocs i
 LEFT JOIN ioc_enrichment e ON e.ioc_id=i.id
 WHERE i.ioc_type IN ('ip','domain','url','md5','sha1','sha256')
   AND (e.vt_last_analysis IS NULL OR e.enriched_at < now() - interval '7 days')
 ORDER BY i.risk_score DESC, i.last_seen DESC LIMIT %s""", (BATCH,))
rows = cur.fetchall()

for index, (ioc_id, kind, value) in enumerate(rows, 1):
    path = TYPE_PATH.get(kind)
    identifier = value
    if kind == "url":
        path = "urls"
        identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    response = requests.get(f"https://www.virustotal.com/api/v3/{path}/{identifier}",
                            headers={"x-apikey": KEY}, timeout=30)
    if response.status_code == 200:
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        timestamp = attributes.get("last_analysis_date")
        cur.execute("""INSERT INTO ioc_enrichment (ioc_id, vt_malicious, vt_suspicious, vt_reputation, vt_last_analysis, vt_link, enriched_at)
          VALUES (%s,%s,%s,%s,to_timestamp(%s),%s,now())
          ON CONFLICT (ioc_id) DO UPDATE SET vt_malicious=EXCLUDED.vt_malicious, vt_suspicious=EXCLUDED.vt_suspicious,
          vt_reputation=EXCLUDED.vt_reputation, vt_last_analysis=EXCLUDED.vt_last_analysis, vt_link=EXCLUDED.vt_link, enriched_at=now()""",
          (ioc_id, stats.get("malicious", 0), stats.get("suspicious", 0), attributes.get("reputation"), timestamp,
           f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else kind}/{identifier}"))
        print(f"[{index}/{len(rows)}] {value}: VT data stored")
    else:
        print(f"[{index}/{len(rows)}] {value}: VirusTotal HTTP {response.status_code}")
    conn.commit()
    if index < len(rows): time.sleep(16)
cur.close(); conn.close()
