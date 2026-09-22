import json
import sys
import unittest
from pathlib import Path

CONTROL_API = Path(__file__).resolve().parents[1] / "services" / "control-api"
sys.path.insert(0, str(CONTROL_API))

from app.positive_learning import build_discovery_candidate, build_guided_candidate


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

    def test_authenticated_observations_are_role_specific_and_still_observe_only(self):
        candidate = build_guided_candidate({
            "session_id": "opaque-session", "hostname": "example.test",
            "auth_state": "role-specific", "identity_label": "qa-reader",
            "requests": [{"method": "GET", "path_template": "/account", "query_names": []}],
            "interaction_events": [], "cookie_metadata": [],
        })
        endpoint = candidate.endpoints[0]
        self.assertEqual(endpoint.authentication.value, "role_specific")
        self.assertEqual(endpoint.decision_mode.value, "observe")
        self.assertEqual(endpoint.method, "GET")

    def test_same_endpoint_observed_before_and_after_login_is_optional(self):
        candidate = build_guided_candidate({
            "session_id": "opaque-session", "hostname": "example.test",
            "auth_state": "role-specific",
            "requests": [
                {"method": "GET", "path_template": "/", "authentication": "anonymous"},
                {"method": "GET", "path_template": "/", "authentication": "role-specific"},
            ],
            "interaction_events": [], "cookie_metadata": [],
        })
        self.assertEqual(candidate.endpoints[0].authentication.value, "optional")

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

    def test_discovery_fusion_uses_observed_same_host_safe_methods_only(self):
        profile = {
            "technology_count": 1,
            "technologies": [{"technology": "WordPress", "confidence_score": 0.91}],
            "route_inventory": [
                {"evidence_type": "route", "request_method": "GET", "status_code": 200, "source_url": "https://example.test/search?q=private-value", "metadata": {"content_type": "text/html", "headers": {"content-type": "text/html"}}},
                {"evidence_type": "route", "request_method": "POST", "status_code": 200, "source_url": "https://example.test/login", "metadata": {}},
                {"evidence_type": "route", "request_method": "GET", "status_code": 200, "source_url": "https://other.test/admin", "metadata": {}},
                {"evidence_type": "route_discovered", "request_method": "GET", "status_code": None, "source_url": "https://example.test/unverified", "metadata": {"not_fetched": True}},
            ],
            "route_candidates": [{"source_url": "https://example.test/static-candidate"}],
            "auth_endpoint_candidates": [{"source_url": "https://example.test/auth-candidate"}],
            "auth_surfaces": [{"source_url": "https://example.test/login"}],
            "api_endpoints": [{"method": "GET", "status_code": 200, "url": "https://example.test/api/items?page=3", "content_type": "application/json"}, {"method": "POST", "status_code": 200, "url": "https://example.test/api/login"}],
        }
        analysis = {"generic_protection_intents": [{"intent_id": "session-and-authentication-protection", "applicability_score": 0.95, "applicability_confidence": "high"}]}
        model, summary = build_discovery_candidate("example.test", "job-123", profile, analysis, {"status": "matched", "matched_vserver": "lb_example"})
        endpoints = {(item.path_template, item.method) for item in model.endpoints}
        self.assertEqual(endpoints, {("/search", "GET"), ("/api/items", "GET")})
        self.assertTrue(all(item.decision_mode.value == "observe" for item in model.endpoints))
        self.assertEqual(model.lifecycle.value, "discovered")
        endpoint_evidence = {ref.source.value for endpoint in model.endpoints for ref in endpoint.evidence}
        self.assertEqual(endpoint_evidence, {"passive_crawl", "runtime_inspection"})
        self.assertEqual(summary["route_candidates_not_verified"], 2)
        self.assertEqual(summary["runtime_auth_surface_count"], 1)
        self.assertEqual(summary["adc_vserver"], "lb_example")
        serialized = json.dumps(model.model_dump(mode="json")) + json.dumps(summary)
        self.assertNotIn("private-value", serialized)
        self.assertNotIn("/unverified", serialized)
        self.assertNotIn("/login", serialized)


if __name__ == "__main__":
    unittest.main()
