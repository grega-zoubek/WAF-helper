import json
import tempfile
import unittest
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "discovery-worker"))

from app.signature_technology import build_signature_technology_context


class SignatureTechnologyContextTests(unittest.TestCase):
    def test_matches_application_and_server_context_without_promoting_evidence(self):
        catalog = {
            "catalogs": [{"catalog_fingerprint": "fingerprint-1"}],
            "rule_count": 3,
            "rules": [
                {"rule_id": "1001", "category": "web-wordpress", "technology_tags": ["wordpress"]},
                {"rule_id": "1002", "category": "web-php", "technology_tags": ["php"]},
                {"rule_id": "1003", "category": "web-iis", "technology_tags": ["iis"]},
            ],
        }
        technologies = [
            {"technology": "WordPress", "technology_key": "wordpress", "category": "cms"},
            {"technology": "PHP", "technology_key": "php", "category": "server-runtime"},
            {"technology": "Microsoft IIS", "technology_key": "microsoft-iis", "category": "web-server"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            result = build_signature_technology_context(technologies, index_path=str(path))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["catalog_fingerprint"], "fingerprint-1")
        self.assertEqual({item["surface"] for item in result["technology_matches"]}, {"web-application", "server"})
        self.assertTrue(all(item["is_detection_evidence"] is False for item in result["technology_matches"]))
        wordpress = next(item for item in result["technology_matches"] if item["technology"] == "WordPress")
        self.assertEqual(wordpress["signature_rule_count"], 1)
        self.assertEqual(wordpress["example_rule_ids"], ["1001"])

    def test_missing_index_is_explicit_and_non_blocking(self):
        result = build_signature_technology_context([], index_path="C:/missing/signature-index.json")
        self.assertEqual(result["status"], "configured-file-missing")
        self.assertFalse(result["is_detection_evidence"])


if __name__ == "__main__":
    unittest.main()
