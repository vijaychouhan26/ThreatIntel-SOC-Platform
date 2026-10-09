import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from siem import extract_observables, normalize_event  # noqa: E402


class ObservableExtractionTests(unittest.TestCase):
    def test_extracts_and_normalizes_supported_observables(self):
        payload = {
            "message": "CVE-2024-12345 from 8.8.8.8 contacted HTTPS://Evil.Example.COM/a.",
            "hash": "D41D8CD98F00B204E9800998ECF8427E",
        }
        result = extract_observables(payload)
        self.assertIn("CVE-2024-12345", result["cve"])
        self.assertIn("8.8.8.8", result["ioc"])
        self.assertIn("https://evil.example.com/a", result["ioc"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result["ioc"])

    def test_rejects_invalid_ipv4_candidate(self):
        result = extract_observables({"message": "not an address: 999.2.3.4"})
        self.assertNotIn("999.2.3.4", result["ioc"])


class EventNormalizationTests(unittest.TestCase):
    def test_normalizes_wazuh_fields(self):
        event = {
            "id": "abc-1",
            "timestamp": "2026-10-09T12:00:00Z",
            "rule": {"id": "5712", "level": "10", "description": "SSH brute force"},
            "agent": {"name": "Ubuntu"},
        }
        normalized = normalize_event(event)
        self.assertEqual(normalized["external_id"], "abc-1")
        self.assertEqual(normalized["rule_id"], "5712")
        self.assertEqual(normalized["rule_level"], 10)
        self.assertEqual(normalized["agent_name"], "Ubuntu")

    def test_fallback_id_is_deterministic(self):
        self.assertEqual(
            normalize_event({"message": "same"})["external_id"],
            normalize_event({"message": "same"})["external_id"],
        )


if __name__ == "__main__":
    unittest.main()
