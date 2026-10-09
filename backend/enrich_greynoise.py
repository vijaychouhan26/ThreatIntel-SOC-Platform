"""GreyNoise Community API enrichment for IP indicators."""
import os
import time

import psycopg2
import requests
from dotenv import load_dotenv

load_dotenv()
KEY = os.getenv("GREYNOISE_API_KEY")
BATCH = min(int(os.getenv("GREYNOISE_BATCH", "20")), 50)
if not KEY:
    raise SystemExit("GREYNOISE_API_KEY is not configured")

conn = psycopg2.connect(host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"), dbname=os.getenv("DB_NAME"),
                        user=os.getenv("DB_USER"), password=os.getenv("DB_PASSWORD"))
cur = conn.cursor()
cur.execute("""SELECT i.id, i.value FROM iocs i LEFT JOIN ioc_enrichment e ON e.ioc_id=i.id
 WHERE i.ioc_type='ip' AND (e.greynoise_last_seen IS NULL OR e.enriched_at < now() - interval '7 days')
 ORDER BY i.risk_score DESC, i.last_seen DESC LIMIT %s""", (BATCH,))
rows = cur.fetchall()
for index, (ioc_id, ip) in enumerate(rows, 1):
    response = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": KEY}, timeout=30)
    if response.status_code in (200, 404):
        data = response.json()
        cur.execute("""INSERT INTO ioc_enrichment (ioc_id, greynoise_noise, greynoise_riot, greynoise_classification, greynoise_name, greynoise_last_seen, greynoise_link, enriched_at)
          VALUES (%s,%s,%s,%s,%s,%s,%s,now())
          ON CONFLICT (ioc_id) DO UPDATE SET greynoise_noise=EXCLUDED.greynoise_noise, greynoise_riot=EXCLUDED.greynoise_riot,
          greynoise_classification=EXCLUDED.greynoise_classification, greynoise_name=EXCLUDED.greynoise_name,
          greynoise_last_seen=EXCLUDED.greynoise_last_seen, greynoise_link=EXCLUDED.greynoise_link, enriched_at=now()""",
          (ioc_id, data.get("noise"), data.get("riot"), data.get("classification"), data.get("name"), data.get("last_seen"), data.get("link")))
        print(f"[{index}/{len(rows)}] {ip}: GreyNoise data stored")
    else:
        print(f"[{index}/{len(rows)}] {ip}: GreyNoise HTTP {response.status_code}")
    conn.commit()
    if index < len(rows): time.sleep(1)
cur.close(); conn.close()
