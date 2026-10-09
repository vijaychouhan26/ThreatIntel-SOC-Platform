import os
import json
import time
import hashlib
import requests
import feedparser
import psycopg2
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

HEADERS = {"User-Agent": "Mozilla/5.0 (threat-intel-collector)"}

FEEDS = [
    ("hackernews", "https://feeds.feedburner.com/TheHackersNews"),
    ("bleepingcomputer", "https://www.bleepingcomputer.com/feed/"),
    ("krebsonsecurity", "https://krebsonsecurity.com/feed/"),
    ("the-record", "https://therecord.media/feed"),
    ("securityweek", "https://www.securityweek.com/feed/"),
    ("unit42", "https://unit42.paloaltonetworks.com/feed/"),
    ("msrc-blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("cisa-alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("google-tag", "https://blog.google/threat-analysis-group/rss/"),
]

BODY_SELECTORS = [
    "div.articlebody", "div.post-body", "div.articleBody", "article",
    "div.entry-content", "div.post-content", "div.c-article__body",
    "div#content", "div.blog-post-content",
]

conn = psycopg2.connect(
    host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
    dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
)
cur = conn.cursor()


def insert_raw(source, kind, payload):
    raw = json.dumps(payload, sort_keys=True)
    h = hashlib.sha256(raw.encode()).hexdigest()
    cur.execute(
        """INSERT INTO raw_items (source, kind, data, content_hash)
           VALUES (%s,%s,%s,%s) ON CONFLICT (content_hash) DO NOTHING""",
        (source, kind, json.dumps(payload), h),
    )
    return cur.rowcount == 1


def fetch_full_article(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=25)
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "lxml")
        for sel in BODY_SELECTORS:
            body = soup.select_one(sel)
            if body:
                for tag in body(["script", "style", "nav", "aside", "form"]):
                    tag.decompose()
                text = body.get_text(separator=" ", strip=True)
                if len(text) > 400:
                    return text
        return None
    except Exception as e:
        print(f"    fetch error: {e}")
        return None


def ingest_feed(source, url):
    print(f"Fetching feed: {source} ({url})")
    try:
        feed = feedparser.parse(url)
        entries = feed.entries or []
    except Exception as e:
        print(f"  Failed to parse feed: {e}")
        return 0
    print(f"  Found {len(entries)} items")
    inserted = 0
    for i, entry in enumerate(entries[:40], 1):
        title = entry.get("title", "")
        link = entry.get("link", "")
        published = entry.get("published") or entry.get("updated") or ""
        full_text = fetch_full_article(link) if link else None
        if not full_text:
            full_text = BeautifulSoup(entry.get("summary", "") or entry.get("description", "") or "", "lxml").get_text(strip=True)
        article = {
            "title": title,
            "link": link,
            "published": published,
            "text": full_text,
            "source": source,
        }
        if insert_raw(source, "article", article):
            inserted += 1
        print(f"  [{i}/{min(len(entries), 40)}] {len(full_text or '')} chars | {title[:60]}")
        time.sleep(0.4)
    conn.commit()
    print(f"  New articles inserted: {inserted}\n")
    return inserted


total = 0
for source, url in FEEDS:
    try:
        total += ingest_feed(source, url)
    except Exception as e:
        print(f"  SKIP {source}: {e}\n")
        conn.rollback()

print(f"Done. Total new articles: {total}")
cur.close()
conn.close()
