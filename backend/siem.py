"""Normalize SIEM alerts and correlate exact observables with stored CTI."""

import hashlib
import ipaddress
import json
import re
from datetime import datetime

import psycopg2.extras


RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|in|info|biz|xyz|top|live|app|dev|cloud|site|online)\b",
    re.IGNORECASE,
)


def scalar_strings(value, path="event"):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from scalar_strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from scalar_strings(child, f"{path}[{index}]")
    elif isinstance(value, (str, int, float)):
        yield path, str(value)


def extract_observables(payload):
    """Return exact observable values and the first JSON path containing each."""
    found = {"ioc": {}, "cve": {}}
    for path, text in scalar_strings(payload):
        for cve in RE_CVE.findall(text):
            found["cve"].setdefault(cve.upper(), path)
        for value in RE_SHA256.findall(text):
            found["ioc"].setdefault(value.lower(), path)
        for value in RE_SHA1.findall(text):
            found["ioc"].setdefault(value.lower(), path)
        for value in RE_MD5.findall(text):
            found["ioc"].setdefault(value.lower(), path)
        for value in RE_URL.findall(text):
            found["ioc"].setdefault(value.rstrip(".,);]").lower(), path)
        for value in RE_IP.findall(text):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            found["ioc"].setdefault(value, path)
        for value in RE_DOMAIN.findall(text):
            found["ioc"].setdefault(value.lower(), path)
    return found


def first(payload, *paths, default=None):
    for path in paths:
        value = payload
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, ""):
            return value
    return default


def normalize_event(payload, source="wazuh"):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    fallback_id = hashlib.sha256(canonical.encode()).hexdigest()
    timestamp = first(payload, "timestamp", "@timestamp", "event.created")
    if isinstance(timestamp, str):
        timestamp = timestamp.replace("Z", "+00:00")
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            timestamp = None
    level = first(payload, "rule.level", "event.severity", "severity")
    try:
        level = int(level) if level is not None else None
    except (TypeError, ValueError):
        level = None
    return {
        "source": source,
        "external_id": str(first(payload, "id", "_id", "event.id", default=fallback_id)),
        "rule_id": str(first(payload, "rule.id", "rule_id", default="")) or None,
        "rule_level": level,
        "title": str(first(payload, "rule.description", "message", "event.action", default="SIEM event")),
        "agent_name": str(first(payload, "agent.name", "host.name", "agent", default="")) or None,
        "event_timestamp": timestamp,
    }


def ingest_event(conn, payload, source="wazuh", commit=True):
    if not isinstance(payload, dict):
        raise ValueError("SIEM event must be a JSON object")
    event = normalize_event(payload, source)
    observables = extract_observables(payload)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            INSERT INTO siem_events (
              source, external_id, rule_id, rule_level, title, agent_name,
              event_timestamp, raw_event
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (source, external_id) DO UPDATE SET
              rule_id=EXCLUDED.rule_id, rule_level=EXCLUDED.rule_level,
              title=EXCLUDED.title, agent_name=EXCLUDED.agent_name,
              event_timestamp=EXCLUDED.event_timestamp, raw_event=EXCLUDED.raw_event
            RETURNING id
        """, (
            event["source"], event["external_id"], event["rule_id"],
            event["rule_level"], event["title"], event["agent_name"],
            event["event_timestamp"], psycopg2.extras.Json(payload),
        ))
        event_id = cur.fetchone()["id"]
        cur.execute("DELETE FROM siem_matches WHERE event_id=%s", [event_id])

        matches = []
        ioc_values = list(observables["ioc"])
        if ioc_values:
            cur.execute("""
                SELECT id, value, risk_score, risk_level
                FROM iocs WHERE lower(value) = ANY(%s)
            """, [ioc_values])
            for row in cur.fetchall():
                matches.append({
                    "entity_type": "ioc", "entity_value": row["value"],
                    "ioc_id": row["id"], "cve_record_id": None,
                    "match_field": observables["ioc"].get(row["value"].lower()),
                    "risk_score": row["risk_score"], "risk_level": row["risk_level"],
                })

        cve_values = list(observables["cve"])
        if cve_values:
            cur.execute("""
                SELECT id, cve_id, cvss_score, severity
                FROM cves WHERE upper(cve_id) = ANY(%s)
            """, [cve_values])
            for row in cur.fetchall():
                score = int(float(row["cvss_score"]) * 10) if row["cvss_score"] is not None else None
                matches.append({
                    "entity_type": "cve", "entity_value": row["cve_id"],
                    "ioc_id": None, "cve_record_id": row["id"],
                    "match_field": observables["cve"].get(row["cve_id"].upper()),
                    "risk_score": score, "risk_level": row["severity"],
                })

        for match in matches:
            cur.execute("""
                INSERT INTO siem_matches (
                  event_id, entity_type, entity_value, ioc_id, cve_record_id,
                  match_field, risk_score, risk_level
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (event_id, entity_type, entity_value) DO NOTHING
            """, (
                event_id, match["entity_type"], match["entity_value"],
                match["ioc_id"], match["cve_record_id"], match["match_field"],
                match["risk_score"], match["risk_level"],
            ))
        cur.execute("UPDATE siem_events SET match_count=%s WHERE id=%s", [len(matches), event_id])
    if commit:
        conn.commit()
    return {"event_id": event_id, "external_id": event["external_id"], "matches": matches}
