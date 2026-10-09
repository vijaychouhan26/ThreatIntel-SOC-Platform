"""Forward a Wazuh/Elastic JSON alert to the local CTI matching endpoint."""

import json
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv


load_dotenv()


def read_events(path):
    text = Path(path).read_text().strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python siem_forwarder.py <alert.json> [source]")
    token = os.getenv("SIEM_INGEST_TOKEN", "").strip()
    if not token or token.startswith("replace_"):
        raise SystemExit("SIEM_INGEST_TOKEN is not configured in backend/.env")
    endpoint = os.getenv("SIEM_API_URL", "http://127.0.0.1:8006/siem/ingest")
    source = sys.argv[2] if len(sys.argv) > 2 else "wazuh"
    sent = 0
    matches = 0
    for event in read_events(sys.argv[1]):
        response = requests.post(
            endpoint,
            json={"source": source, "event": event},
            headers={"X-SIEM-Token": token},
            timeout=15,
        )
        response.raise_for_status()
        result = response.json()
        sent += 1
        matches += result.get("match_count", 0)
    print(f"Forwarded {sent} event(s); {matches} CTI match(es)")


if __name__ == "__main__":
    main()
