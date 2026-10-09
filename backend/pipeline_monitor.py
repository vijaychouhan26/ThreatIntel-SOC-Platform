"""Small CLI used by the pipeline to expose refresh history in the dashboard."""
import os
import sys
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
                        dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
                        password=os.getenv("DB_PASSWORD"))
cur = conn.cursor()

if len(sys.argv) < 2:
    raise SystemExit("Usage: pipeline_monitor.py start|finish|get|set ...")
if sys.argv[1] == "start":
    cur.execute("INSERT INTO pipeline_runs (log_path) VALUES (%s) RETURNING id", (sys.argv[2],))
    print(cur.fetchone()[0])
elif sys.argv[1] == "finish":
    cur.execute("UPDATE pipeline_runs SET completed_at=now(), status=%s WHERE id=%s", (sys.argv[3], sys.argv[2]))
elif sys.argv[1] == "get":
    cur.execute("SELECT bool_value FROM app_settings WHERE key=%s", (sys.argv[2],))
    row = cur.fetchone()
    print("true" if row is None or row[0] else "false")
elif sys.argv[1] == "set":
    value = sys.argv[3].lower() in {"1", "true", "yes", "on"}
    cur.execute("""INSERT INTO app_settings (key, bool_value, updated_at) VALUES (%s,%s,now())
      ON CONFLICT (key) DO UPDATE SET bool_value=EXCLUDED.bool_value, updated_at=now()""", (sys.argv[2], value))
else:
    raise SystemExit("Unknown action")
conn.commit()
cur.close(); conn.close()
