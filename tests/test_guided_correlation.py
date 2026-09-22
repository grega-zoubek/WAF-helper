import sys
import unittest
from pathlib import Path

RUNTIME_INSPECTOR = Path(__file__).resolve().parents[1] / "services" / "runtime-inspector"
sys.path.insert(0, str(RUNTIME_INSPECTOR))

from app.main import correlate_focus_to_requests


class GuidedCorrelationTests(unittest.TestCase):
    def test_correlates_matching_query_key_without_values(self):
        requests = [{
            "id": "opaque-request-id",
            "method": "GET",
            "url": "https://example.test/api/search?q=REDACTED&take=REDACTED",
            "resource_type": "fetch",
            "started_at": 10.15,
            "status_code": 200,
        }]

        result = correlate_focus_to_requests({"name": "q", "id": "search-box"}, 10.0, requests, "example.test")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["matched_parameter_names"], ["q"])
        self.assertEqual(result[0]["confidence"], 0.7)
        self.assertEqual(result[0]["path_template"], "/api/search")
        self.assertNotIn("raw_value", result[0])
        self.assertNotIn("REDACTED", str(result[0]))

    def test_only_later_in_window_same_host_fetches_are_considered(self):
        requests = [
            {"id": "before", "method": "GET", "url": "https://example.test/api/search?q=REDACTED", "resource_type": "fetch", "started_at": 9.9},
            {"id": "late", "method": "GET", "url": "https://example.test/api/search?q=REDACTED", "resource_type": "xhr", "started_at": 12.1},
            {"id": "external", "method": "GET", "url": "https://other.test/api/search?q=REDACTED", "resource_type": "fetch", "started_at": 10.1},
            {"id": "document", "method": "GET", "url": "https://example.test/api/search?q=REDACTED", "resource_type": "document", "started_at": 10.1},
        ]

        result = correlate_focus_to_requests({"name": "q"}, 10.0, requests, "example.test")

        self.assertEqual(result, [])

    def test_temporal_only_match_is_explicitly_low_confidence(self):
        requests = [{"id": "r1", "method": "GET", "url": "https://example.test/api/suggestions", "resource_type": "xhr", "started_at": 10.3}]

        result = correlate_focus_to_requests({"name": "search"}, 10.0, requests, "example.test")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], 0.25)
        self.assertEqual(result[0]["matched_parameter_names"], [])
        self.assertIn("unconfirmed", result[0]["reason"])


if __name__ == "__main__":
    unittest.main()
