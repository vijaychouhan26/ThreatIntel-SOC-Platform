import os
import re
import json
import ipaddress
import requests
import psycopg2
from dotenv import load_dotenv
from threat_actors import ACTORS, catalog_matches, lookup_actor, mitre

load_dotenv()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
ARTICLE_BATCH = int(os.getenv("ARTICLE_BATCH", "25"))

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()

RE_CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_ACTOR = re.compile(r'\b(APT|UNC|TA)[ -]?(\d{1,5})\b', re.IGNORECASE)
RE_DOMAIN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|in|info|biz|xyz|top|live|app)\b', re.IGNORECASE)

SKIP_DOMAINS = {
    "thehackernews.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "therecord.media", "securityweek.com", "microsoft.com", "cisa.gov",
    "paloaltonetworks.com", "google.com", "youtube.com", "twitter.com",
    "linkedin.com", "github.com", "wikipedia.org", "cloudflare.com",
}


def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_unspecified or ip.is_link_local)
    except ValueError:
        return False


def regex_iocs(text):
    ips = [ip for ip in set(RE_IP.findall(text or "")) if valid_ip(ip)]
    domains = []
    for d in set(RE_DOMAIN.findall(text or "")):
        dl = d.lower()
        if dl not in SKIP_DOMAINS and not any(dl.endswith("." + s) for s in SKIP_DOMAINS):
            domains.append(dl)
    return {
        "cve": sorted({c.upper() for c in RE_CVE.findall(text or "")}),
        "ip": sorted(ips),
        "sha256": sorted(set(RE_SHA256.findall(text or ""))),
        "sha1": sorted(set(RE_SHA1.findall(text or ""))),
        "md5": sorted(set(RE_MD5.findall(text or ""))),
    }


def regex_apt_groups(text):
    groups = set()
    for prefix, number in RE_ACTOR.findall(text or ""):
        prefix = prefix.upper()
        groups.add(f"UNC-{number}" if prefix == "UNC" else f"{prefix}{number}")
    return sorted(groups)


def excerpt_around(text, needle, radius=280):
    if not text or not needle:
        return ""
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return (text or "")[:500]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    chunk = text[start:end].strip()
    return ("…" if start else "") + chunk + ("…" if end < len(text) else "")


def seed_catalog():
    for actor in ACTORS:
        url = mitre(actor["mitre_id"]) if actor.get("mitre_id") else None
        cur.execute("""
            INSERT INTO apt_groups (name, description, aliases, target_sectors, origin_country, mitre_id, mitre_url, times_seen)
            VALUES (%s,%s,%s,%s,%s,%s,%s,0)
            ON CONFLICT (name) DO UPDATE SET
                description = COALESCE(NULLIF(apt_groups.description, ''), EXCLUDED.description),
                aliases = COALESCE(apt_groups.aliases, EXCLUDED.aliases),
                target_sectors = COALESCE(apt_groups.target_sectors, EXCLUDED.target_sectors),
                origin_country = COALESCE(apt_groups.origin_country, EXCLUDED.origin_country),
                mitre_id = COALESCE(apt_groups.mitre_id, EXCLUDED.mitre_id),
                mitre_url = COALESCE(apt_groups.mitre_url, EXCLUDED.mitre_url)
        """, (
            actor["name"], actor.get("description"), actor.get("aliases") or None,
            actor.get("target_sectors") or None, actor.get("origin_country"),
            actor.get("mitre_id") or None, url,
        ))
    conn.commit()


def upsert_ioc(ioc_type, value, source, reason):
    if not value:
        return
    t = ioc_type.lower()
    v = value.lower() if t in ("domain", "url", "md5", "sha1", "sha256") else value
    if t == "cve":
        cur.execute("""
            INSERT INTO cves (cve_id, description, kev_listed)
            VALUES (%s, %s, false)
            ON CONFLICT (cve_id) DO UPDATE SET last_seen = now()
        """, (v.upper() if v.upper().startswith("CVE-") else value.upper(),
              reason or "Mentioned in threat reporting"))
        return
    cur.execute("""
        INSERT INTO iocs (ioc_type, value, reason, threat_type, confidence)
        VALUES (%s,%s,%s,'article',60)
        ON CONFLICT (ioc_type, value) DO UPDATE SET
            reason = COALESCE(iocs.reason, EXCLUDED.reason)
        RETURNING id
    """, (t, v, reason))
    ioc_id = cur.fetchone()[0]
    cur.execute("""SELECT 1 FROM ioc_sightings
                   WHERE ioc_id=%s AND source=%s AND seen_at::date=now()::date LIMIT 1""",
                (ioc_id, source))
    if cur.fetchone() is None:
        cur.execute("INSERT INTO ioc_sightings (ioc_id, source) VALUES (%s,%s)", (ioc_id, source))
        cur.execute("""UPDATE iocs SET times_seen=(SELECT COUNT(*) FROM ioc_sightings WHERE ioc_id=%s),
                       last_seen=now(), is_active=true WHERE id=%s""", (ioc_id, ioc_id))


def upsert_apt(name, article_title, article_link, text):
    if not name or name.lower() in ("unknown", ""):
        return
    catalog = lookup_actor(name)
    desc = None
    aliases = sectors = origin = mitre_id = mitre_url = None
    if catalog:
        name = catalog["name"]
        desc = catalog.get("description")
        aliases = catalog.get("aliases") or None
        sectors = catalog.get("target_sectors") or None
        origin = catalog.get("origin_country")
        mitre_id = catalog.get("mitre_id") or None
        mitre_url = mitre(mitre_id) if mitre_id else None
    else:
        desc = excerpt_around(text, name) or f"Threat actor mentioned in reporting: {article_title}"

    cur.execute("""
        INSERT INTO apt_groups (
            name, description, aliases, target_sectors, origin_country,
            mitre_id, mitre_url, main_article_link, main_article_title, times_seen
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0)
        ON CONFLICT (name) DO UPDATE SET
            last_seen = now(),
            description = COALESCE(NULLIF(EXCLUDED.description, ''), apt_groups.description),
            aliases = COALESCE(EXCLUDED.aliases, apt_groups.aliases),
            target_sectors = COALESCE(EXCLUDED.target_sectors, apt_groups.target_sectors),
            origin_country = COALESCE(EXCLUDED.origin_country, apt_groups.origin_country),
            mitre_id = COALESCE(EXCLUDED.mitre_id, apt_groups.mitre_id),
            mitre_url = COALESCE(EXCLUDED.mitre_url, apt_groups.mitre_url),
            main_article_link = COALESCE(apt_groups.main_article_link, EXCLUDED.main_article_link),
            main_article_title = COALESCE(apt_groups.main_article_title, EXCLUDED.main_article_title)
    """, (name, desc, aliases, sectors, origin, mitre_id, mitre_url, article_link, article_title))


PROMPT = """You are a cyber threat intelligence analyst. Read the article and extract structured intel.
Return ONLY valid JSON with this exact shape:
{{
  "apt_groups": [
    {{
      "name": "APT name",
      "description": "2-4 sentences: who they are, attribution if any, what they did in this article",
      "aliases": ["other names"],
      "target_sectors": ["sectors"],
      "origin_country": "country of origin if mentioned"
    }}
  ],
  "malware": ["family names"],
  "summary": "3-4 sentence threat summary covering impact, victims, and recommended attention",
  "ioc_reasons": {{"indicator_value": "one line why malicious"}}
}}
Rules: use [] if nothing found (never "Unknown"). Only real threat-actor/malware names.

Regex-found indicators (give reason for each): {iocs}

ARTICLE:
{article}
"""


def ask_llm(article_text, iocs):
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/generate", json={
            "model": MODEL,
            "prompt": PROMPT.format(iocs=json.dumps(iocs), article=article_text[:5000]),
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 500},
        }, timeout=180)
        if resp.status_code != 200:
            print(f"    LLM HTTP {resp.status_code}")
            return None
        return json.loads(resp.json()["response"])
    except Exception as e:
        print(f"    LLM error: {e}")
        return None


def fallback_summary(title, text):
    body = re.sub(r"\s+", " ", text or "").strip()
    if not body:
        return title
    return f"{title}. {body[:420]}{'…' if len(body) > 420 else ''}"


print("Seeding threat-actor catalog…")
seed_catalog()

cur.execute("""
    SELECT id, source, data->>'title', data->>'link', data->>'published', data->>'text'
    FROM raw_items
    WHERE kind='article'
    ORDER BY fetched_at DESC, id DESC
    LIMIT %s
""", (max(ARTICLE_BATCH, 80),))
articles = cur.fetchall()
print(f"Processing {len(articles)} articles (deterministic + optional LLM)…\n")

done = 0
for raw_id, source, title, link, published, text in articles:
    text = text or ""
    source = source or "news"
    iocs = regex_iocs(text)
    intel = ask_llm(text, iocs) if text and done < ARTICLE_BATCH else None

    llm_apts = []
    malwares = []
    summary = fallback_summary(title, text)
    reasons = {}
    if intel:
        raw_apts = intel.get("apt_groups") or []
        if raw_apts and isinstance(raw_apts[0], str):
            raw_apts = [{"name": n} for n in raw_apts]
        llm_apts = raw_apts
        malwares = [m for m in (intel.get("malware") or []) if isinstance(m, str)]
        if intel.get("summary"):
            summary = intel["summary"]
        reasons = intel.get("ioc_reasons") or {}

    catalog_apts = catalog_matches(f"{title}\n{text}")
    regex_apts = [{"name": n} for n in regex_apt_groups(text)]
    merged = {}
    for a in regex_apts + [{"name": a["name"], **a} for a in catalog_apts] + llm_apts:
        n = a.get("name")
        if not n:
            continue
        canon = (lookup_actor(n) or {}).get("name") or n
        prev = merged.get(canon) or {}
        prev.update({k: v for k, v in a.items() if v})
        prev["name"] = canon
        merged[canon] = prev
    all_apt_data = list(merged.values())
    apt_names = list(merged.keys())

    excerpt = (text[:600] + "…") if len(text) > 600 else text

    cur.execute("""
        INSERT INTO articles (title, link, published, summary, apt_groups, malware, source, excerpt)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (link) DO UPDATE SET
            summary = COALESCE(NULLIF(EXCLUDED.summary, ''), articles.summary),
            apt_groups = EXCLUDED.apt_groups,
            malware = EXCLUDED.malware,
            source = COALESCE(EXCLUDED.source, articles.source),
            excerpt = COALESCE(NULLIF(EXCLUDED.excerpt, ''), articles.excerpt)
    """, (title, link, published, summary,
          apt_names or None, malwares or None, source, excerpt))

    for a in all_apt_data:
        if a.get("name"):
            upsert_apt(a["name"], title, link, a.get("description") or text)

    for ioc_type, vals in iocs.items():
        for v in vals:
            reason = reasons.get(v) or reasons.get(v.upper()) or f"Extracted from article: {title[:80]}"
            upsert_ioc(ioc_type, v, source, reason)

    cur.execute("UPDATE raw_items SET processed=true WHERE id=%s", (raw_id,))
    conn.commit()
    done += 1
    print(f"  [{done}/{len(articles)}] {title[:52]} | APT:{len(apt_names)} MAL:{len(malwares)} IOC:{sum(len(v) for v in iocs.values())}")

cur.execute("""
    UPDATE apt_groups g SET times_seen = COALESCE((
        SELECT COUNT(*) FROM articles a WHERE g.name = ANY(a.apt_groups)
    ), 0)
""")
conn.commit()

cur.execute("SELECT COUNT(*) FROM articles")
print(f"\nArticles: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM apt_groups")
print(f"APT groups: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM iocs WHERE threat_type='article'")
print(f"Article IOCs: {cur.fetchone()[0]}")
cur.close()
conn.close()
