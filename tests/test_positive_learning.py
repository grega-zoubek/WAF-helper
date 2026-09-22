import json
import sys
import unittest
from pathlib import Path

CONTROL_API = Path(__file__).resolve().parents[1] / "services" / "control-api"
sys.path.insert(0, str(CONTROL_API))

from app.positive_learning import build_guided_candidate


class GuidedCandidateTests(unittest.TestCase):
    def test_builds_observe_only_model_from_redacted_metadata(self):
        source = {
            "session_id": "session-opaque-123",
            "hostname": "example.test",
            "requests": [
                {
                    "id": "req-1", "method": "GET", "path_template": "/products/{id:int}",
                    "scheme": "https", "cookie_header_present": True,
                    "query_names": ["page", "page"], "request_header_names": ["accept", "cookie"],
                    "response_header_names": ["content-type", "x-content-type-options"],
                    "response_content_type": "application/json", "observed_at": "2026-09-22T08:00:00+00:00",
                },
                {
                    "id": "req-2", "method": "GET", "path_template": "/products/{id:int}",
                    "scheme": "https", "cookie_header_present": True,
                    "query_names": ["page"], "request_header_names": ["accept"],
                    "response_header_names": ["content-type"], "response_content_type": "application/json",
                    "observed_at": "2026-09-22T08:00:01+00:00",
                },
                {"id": "req-post", "method": "POST", "path_template": "/login", "query_names": ["password"]},
            ],
            "selected_elements": [{"tag": "input", "type": "text", "name": "page", "id": "page"}],
            "interaction_events": [],
            "cookie_metadata": [{"name": "session_token", "domain": ".example.test", "path": "/", "secure": True, "http_only": True}],
            "privacy": {"raw_values_returned": False, "request_bodies_returned": False, "cookie_values_returned": False},
        }

        candidate = build_guided_candidate(source)
        document = candidate.model_dump(mode="json")
        self.assertEqual(candidate.lifecycle.value, "discovered")
        self.assertEqual(len(candidate.endpoints), 1)
        endpoint = candidate.endpoints[0]
        self.assertEqual(endpoint.method, "GET")
        self.assertEqual(endpoint.decision_mode.value, "observe")
        by_location_and_name = {(field.location.value, field.name): field for field in endpoint.fields}
        self.assertIn(("query", "page"), by_location_and_name)
        self.assertIn(("path", "id"), by_location_and_name)
        self.assertEqual(by_location_and_name[("request_cookie", "session_token")].sensitivity.value, "secret")
        self.assertIsNone(by_location_and_name[("query", "page")].proposed_constraints.max_length)
        self.assertNotIn("req-post", json.dumps(document))
        self.assertNotIn("cookie_value", json.dumps(document))

    def test_rejects_untrusted_raw_value_properties_without_echoing_them(self):
        source = {
            "session_id": "session-opaque-456", "hostname": "example.test",
            "requests": [{
                "method": "GET", "path_template": "/search", "query_names": ["q"],
                "raw_value": "DO-NOT-RETAIN-CANARY", "url": "https://example.test/search?q=DO-NOT-RETAIN-CANARY",
            }],
            "selected_elements": [], "cookie_metadata": [],
        }
        with self.assertRaises(ValueError) as raised:
            build_guided_candidate(source)
        self.assertNotIn("DO-NOT-RETAIN-CANARY", str(raised.exception))

    def test_repeated_path_parameters_have_unique_model_fields(self):
        source = {
            "session_id": "session-opaque-789", "hostname": "example.test",
            "requests": [{"method": "GET", "path_template": "/items/{id:int}/sub/{id:int}", "query_names": []}],
            "selected_elements": [], "cookie_metadata": [],
        }
        candidate = build_guided_candidate(source)
        path_names = [field.name for field in candidate.endpoints[0].fields if field.location.value == "path"]
        self.assertEqual(path_names, ["id", "id_2"])


if __name__ == "__main__":
    unittest.main()
