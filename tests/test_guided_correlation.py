import sys
import unittest
from pathlib import Path

RUNTIME_INSPECTOR = Path(__file__).resolve().parents[1] / "services" / "runtime-inspector"
sys.path.insert(0, str(RUNTIME_INSPECTOR))

from app.main import InspectionRequest, correlate_focus_to_requests, guard_guided_route, redact_url


class GuidedCorrelationTests(unittest.TestCase):
    def test_redacts_query_and_fragment_values(self):
        value = "https://example.test/#/callback?access_token=PRIVATE&state=NONCE"
        result = redact_url(value)
        self.assertEqual(result, "https://example.test/#/callback?access_token=REDACTED&state=REDACTED")
        self.assertNotIn("PRIVATE", result)
        self.assertNotIn("NONCE", result)

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


class GuidedNetworkGuardTests(unittest.IsolatedAsyncioTestCase):
    class Route:
        def __init__(self, method, url):
            self.request = type("Request", (), {"method": method, "url": url})()
            self.action = None

        async def abort(self, reason):
            self.action = ("abort", reason)

        async def continue_(self):
            self.action = ("continue", None)

    async def test_allows_only_in_scope_get_and_head(self):
        scope = InspectionRequest(urls=["https://example.test/app"], hostname="example.test", allowed_paths=["/app"])
        for method in ("GET", "HEAD"):
            route = self.Route(method, "https://example.test/app/search")
            await guard_guided_route(route, scope)
            self.assertEqual(route.action[0], "continue")

    async def test_aborts_mutations_and_out_of_scope_requests(self):
        scope = InspectionRequest(urls=["https://example.test/app"], hostname="example.test", allowed_paths=["/app"])
        for method, url in (
            ("POST", "https://example.test/app/login"),
            ("GET", "https://example.test/private"),
            ("GET", "https://other.test/app/search"),
        ):
            route = self.Route(method, url)
            await guard_guided_route(route, scope)
            self.assertEqual(route.action, ("abort", "blockedbyclient"))


if __name__ == "__main__":
    unittest.main()
