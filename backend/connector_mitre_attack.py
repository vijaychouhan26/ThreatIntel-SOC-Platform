"""Synchronise ATT&CK Enterprise groups and group-to-technique mappings via TAXII 2.1."""
import os
from urllib.parse import urljoin

import psycopg2
import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

TAXII_ROOT = os.getenv("MITRE_TAXII_ROOT", "https://attack-taxii.mitre.org/taxii2/")
HEADERS = {"Accept": "application/taxii+json;version=2.1"}


def http_session():
    retry = Retry(
        total=4,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def external_id(obj):
    for ref in obj.get("external_references", []):
        value = ref.get("external_id", "")
        if value:
            return value
    return None


def external_url(obj, fallback):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return fallback


def fetch_objects():
    session = http_session()
    root_response = session.get(TAXII_ROOT, headers=HEADERS, timeout=30)
    root_response.raise_for_status()
    root = root_response.json()
    # TAXII advertises its default API root as an absolute path (for example
    # /api/v21); preserve that leading slash instead of nesting it below /taxii2.
    api_root = urljoin(TAXII_ROOT, root["default"].rstrip("/") + "/")
    collections_response = session.get(urljoin(api_root, "collections/"), headers=HEADERS, timeout=30)
    collections_response.raise_for_status()
    collections = collections_response.json()["collections"]
    enterprise = next(c for c in collections if c["title"] == "Enterprise ATT&CK")
    url = urljoin(api_root, f"collections/{enterprise['id']}/objects/")
    objects = []
    while url:
        response = session.get(url, headers=HEADERS, timeout=60)
        response.raise_for_status()
        payload = response.json()
        objects.extend(payload.get("objects", []))
        more = payload.get("more", False)
        token = payload.get("next")
        url = f"{url}?next={token}" if more and token else None
    return objects


def main():
    objects = fetch_objects()
    groups = {o["id"]: o for o in objects if o.get("type") == "intrusion-set" and not o.get("revoked")}
    techniques = {o["id"]: o for o in objects if o.get("type") == "attack-pattern" and not o.get("revoked")}
    software = {o["id"]: o for o in objects
                if o.get("type") in ("malware", "tool") and not o.get("revoked")
                and not o.get("x_mitre_deprecated")}
    relationships = [o for o in objects if o.get("type") == "relationship" and o.get("relationship_type") == "uses"]

    conn = psycopg2.connect(host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"), dbname=os.getenv("DB_NAME"),
                            user=os.getenv("DB_USER"), password=os.getenv("DB_PASSWORD"))
    cur = conn.cursor()
    by_stix = {}
    for stix_id, group in groups.items():
        group_id = external_id(group)
        if not group_id:
            continue
        name = group["name"]
        by_stix[stix_id] = (name, group_id)
        cur.execute("""
            INSERT INTO apt_groups (name, description, aliases, mitre_id, mitre_url, times_seen)
            VALUES (%s,%s,%s,%s,%s,0)
            ON CONFLICT (name) DO UPDATE SET
              description=EXCLUDED.description, aliases=EXCLUDED.aliases,
              mitre_id=EXCLUDED.mitre_id, mitre_url=EXCLUDED.mitre_url, last_seen=now()
        """, (name, group.get("description"), group.get("aliases") or None, group_id,
              f"https://attack.mitre.org/groups/{group_id}/"))

    by_software_stix = {}
    for stix_id, item in software.items():
        software_id = external_id(item)
        if not software_id:
            continue
        name = item["name"]
        by_software_stix[stix_id] = (name, software_id)
        fallback = f"https://attack.mitre.org/software/{software_id}/"
        cur.execute("""
            INSERT INTO attack_software (name, mitre_id, software_type, description, aliases, mitre_url)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (name) DO UPDATE SET
              mitre_id=EXCLUDED.mitre_id, software_type=EXCLUDED.software_type,
              description=EXCLUDED.description, aliases=EXCLUDED.aliases,
              mitre_url=EXCLUDED.mitre_url, updated_at=now()
        """, (name, software_id, item["type"], item.get("description"),
              item.get("x_mitre_aliases") or None, external_url(item, fallback)))

    mapped = 0
    software_mapped = 0
    for relation in relationships:
        if relation.get("source_ref") not in by_stix:
            continue
        name, group_id = by_stix[relation["source_ref"]]
        if relation.get("target_ref") in by_software_stix:
            software_name, software_id = by_software_stix[relation["target_ref"]]
            cur.execute("""
                INSERT INTO apt_software (group_name, software_name, mitre_group_id, mitre_software_id, source_url)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (group_name, software_name) DO UPDATE SET
                  mitre_group_id=EXCLUDED.mitre_group_id,
                  mitre_software_id=EXCLUDED.mitre_software_id,
                  source_url=EXCLUDED.source_url, updated_at=now()
            """, (name, software_name, group_id, software_id,
                  f"https://attack.mitre.org/software/{software_id}/"))
            software_mapped += 1
            continue
        if relation.get("target_ref") not in techniques:
            continue
        technique = techniques[relation["target_ref"]]
        technique_id = external_id(technique)
        if not technique_id:
            continue
        tactics = [phase.get("phase_name") for phase in technique.get("kill_chain_phases", [])
                   if phase.get("kill_chain_name") == "mitre-attack"]
        cur.execute("""
            INSERT INTO apt_techniques (group_name, mitre_group_id, technique_id, technique_name, tactics, source_url)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT (group_name, technique_id) DO UPDATE SET
              technique_name=EXCLUDED.technique_name, tactics=EXCLUDED.tactics,
              source_url=EXCLUDED.source_url, updated_at=now()
        """, (name, group_id, technique_id, technique["name"], tactics or None,
              f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"))
        mapped += 1
    conn.commit()
    cur.close(); conn.close()
    print(f"MITRE ATT&CK sync complete: {len(by_stix)} groups, {mapped} group-technique mappings, "
          f"{len(by_software_stix)} software entries, {software_mapped} group-software mappings")


if __name__ == "__main__":
    main()
