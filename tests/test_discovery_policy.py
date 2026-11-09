import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "runtime-inspector"))

from app.coverage import build_coverage  # noqa: E402
from app.discovery_policy import (  # noqa: E402
    CATEGORIES, PRESETS, Budget, build_policy, classify_request, decide, describe_catalog, policy_fingerprint,
)
from app.live import apply_policy  # noqa: E402


def classify(method, path, ctype="", fmt="", rtype="xhr"):
    return classify_request(method, f"https://shop.test{path}", ctype, fmt, rtype)[0]


class ClassificationTests(unittest.TestCase):
    def test_reads_search_and_downloads(self):
        self.assertEqual(classify("GET", "/products"), "navigation_read")
        self.assertEqual(classify("GET", "/rest/products/search?q=apple"), "search_filter")
        self.assertEqual(classify("GET", "/list?page=2&sort=name"), "search_filter")
        self.assertEqual(classify("GET", "/files/report.pdf"), "file_transfer")
        self.assertEqual(classify("GET", "/logout"), "auth_session")

    def test_state_changing_requests(self):
        self.assertEqual(classify("POST", "/rest/user/login", "application/json"), "auth_session")
        self.assertEqual(classify("POST", "/api/Users/register"), "registration")
        self.assertEqual(classify("POST", "/profile/image/file", "multipart/form-data"), "file_transfer")
        self.assertEqual(classify("POST", "/api/BasketItems"), "checkout")
        self.assertEqual(classify("POST", "/api/Feedbacks"), "external_effect")
        self.assertEqual(classify("DELETE", "/api/Addresss/4"), "record_write")
        self.assertEqual(classify("PUT", "/api/Products/1"), "record_write")
        self.assertEqual(classify("POST", "/items/create"), "record_write")
        self.assertEqual(classify("POST", "/submit", "application/x-www-form-urlencoded", "form", "document"), "form_submit")

    def test_unrecognised_state_change_is_ambiguous(self):
        self.assertIsNone(classify("POST", "/api/widgets", "application/json", "json"))
        self.assertIsNone(classify("POST", "/graphql", "application/json", "json"))

    def test_search_post_without_write_verb(self):
        self.assertEqual(classify("POST", "/api/search"), "search_filter")


class PolicyTests(unittest.TestCase):
    def test_defaults_are_read_only_and_state_changes_off(self):
        policy = build_policy()
        self.assertEqual(set(policy["enabled"]), {"navigation_read", "search_filter"})
        for key, (_, changes_state) in CATEGORIES.items():
            if changes_state:
                self.assertNotIn(key, policy["enabled"], key)

    def test_operator_preset_allows_requests_but_never_probes(self):
        policy = build_policy("operator_free")
        self.assertIn("auth_session", policy["enabled"])
        self.assertNotIn("security_probe", policy["enabled"])
        self.assertNotIn("boundary_test", policy["enabled"])

    def test_validation(self):
        with self.assertRaises(ValueError):
            build_policy("nope")
        with self.assertRaises(ValueError):
            build_policy("read_only", {"enabled": ["navigation_read", "rm_rf"]})
        with self.assertRaises(ValueError):
            build_policy("read_only", {"ambiguous": "allow"})  # automated actors cannot allow ambiguity
        with self.assertRaises(ValueError):
            build_policy("read_only", {"budgets": {"max_everything": 1}})
        with self.assertRaises(ValueError):
            build_policy("read_only", {"route_scopes": {"bogus": ["/"]}})

    def test_budget_ceiling_and_scope_cleaning(self):
        policy = build_policy("read_only", {"budgets": {"max_requests": 10**9}, "route_scopes": {"record_write": ["/api", "../etc", "nope"]}})
        self.assertLessEqual(policy["budgets"]["max_requests"], 50_000)
        self.assertEqual(policy["route_scopes"]["record_write"], ["/api"])

    def test_fingerprint_is_stable_and_sensitive(self):
        a, b = build_policy("read_only"), build_policy("read_only")
        self.assertEqual(policy_fingerprint(a), policy_fingerprint(b))
        c = build_policy("read_only", {"enabled": ["navigation_read"]})
        self.assertNotEqual(policy_fingerprint(a), policy_fingerprint(c))

    def test_decide(self):
        policy = build_policy("automated_default", {"enabled": ["navigation_read", "record_write"], "route_scopes": {"record_write": ["/api/notes"]}})
        self.assertEqual(decide(policy, "navigation_read", "/")["action"], "allow")
        self.assertEqual(decide(policy, "auth_session", "/login")["action"], "deny")
        self.assertEqual(decide(policy, "record_write", "/api/notes/3")["action"], "allow")
        self.assertEqual(decide(policy, "record_write", "/api/users/3")["action"], "deny")
        self.assertEqual(decide(policy, None, "/x")["action"], "pause")
        self.assertEqual(decide(build_policy("operator_free"), None, "/x")["action"], "allow")

    def test_catalog_marks_defaults(self):
        catalog = {item["id"]: item for item in describe_catalog()}
        self.assertTrue(catalog["navigation_read"]["default_enabled"])
        self.assertFalse(catalog["checkout"]["default_enabled"])
        self.assertTrue(catalog["security_probe"]["tool_declared"])

    def test_budget(self):
        budget = Budget({"max_requests": 2, "max_actions": 1, "max_seconds": 10})
        self.assertTrue(budget.charge_request() and budget.charge_request())
        self.assertFalse(budget.charge_request())
        self.assertTrue(budget.charge_action())
        self.assertFalse(budget.charge_action())

    def test_presets_all_build(self):
        for name in PRESETS:
            build_policy(name)


def session(preset="read_only", overrides=None):
    policy = build_policy(preset, overrides)
    return {"hostname": "shop.test", "policy": policy, "budget": Budget(policy["budgets"]), "permission_counts": {}, "permission_events": [], "budget_exhausted": False}


class EnforcementTests(unittest.TestCase):
    def test_page_script_cannot_widen_permission(self):
        s = session("read_only")
        # a script-triggered POST is judged by the same policy as one the person clicked
        self.assertFalse(apply_policy(s, "POST", "https://shop.test/rest/user/login", "xhr", "application/json"))
        self.assertTrue(apply_policy(s, "GET", "https://shop.test/products", "document"))
        self.assertEqual(s["permission_events"][0]["category"], "auth_session")
        self.assertEqual(s["permission_events"][0]["action"], "deny")

    def test_ambiguous_is_paused_for_automated_runs(self):
        s = session("read_only")
        self.assertFalse(apply_policy(s, "POST", "https://shop.test/api/widgets", "xhr", "application/json"))
        self.assertEqual(s["permission_events"][0]["action"], "pause")

    def test_operator_session_allows_ambiguous(self):
        s = session("operator_free")
        self.assertTrue(apply_policy(s, "POST", "https://shop.test/api/widgets", "xhr", "application/json"))
        self.assertEqual(s["permission_events"], [])

    def test_budget_blocks_requests(self):
        s = session("read_only", {"budgets": {"max_requests": 2}})
        self.assertTrue(apply_policy(s, "GET", "https://shop.test/a", "xhr"))
        self.assertTrue(apply_policy(s, "GET", "https://shop.test/b", "xhr"))
        self.assertFalse(apply_policy(s, "GET", "https://shop.test/c", "xhr"))
        self.assertTrue(s["budget_exhausted"])

    def test_events_hold_no_query_values(self):
        s = session("read_only")
        apply_policy(s, "POST", "https://shop.test/rest/user/login?token=SECRET123", "xhr", "application/json")
        self.assertNotIn("SECRET123", str(s["permission_events"]))

    def test_cross_host_is_left_to_the_mode_guard(self):
        s = session("read_only")
        self.assertTrue(apply_policy(s, "GET", "https://cdn.test/lib.js", "script"))
        self.assertEqual(s["budget"].requests, 0)


class CoverageTests(unittest.TestCase):
    def doc(self, status=200):
        return {"method": "GET", "url": "https://shop.test/", "resource_type": "document", "status_code": status, "response_content_type": "text/html"}

    def test_clean_run_is_complete(self):
        report = build_coverage([self.doc(), {"method": "GET", "url": "https://shop.test/a.js", "resource_type": "script", "status_code": 200, "response_content_type": "application/javascript"}])
        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["explored"])

    def test_load_error_is_failed_not_explored(self):
        report = build_coverage([], load_error="net::ERR_CONNECTION_REFUSED")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["explored"])

    def test_adc_redirecting_assets_is_degraded(self):
        net = [self.doc()] + [{"method": "GET", "url": "https://shop.test/main.js", "resource_type": "script", "status_code": 302, "response_content_type": "text/html"}]
        report = build_coverage(net)
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["failure_counts"], {"asset_redirect": 1})

    def test_mime_mismatch_and_failed_asset_and_server_error(self):
        net = [
            self.doc(),
            {"method": "GET", "url": "https://shop.test/a.css", "resource_type": "stylesheet", "status_code": 200, "response_content_type": "text/html"},
            {"method": "GET", "url": "https://shop.test/f.woff", "resource_type": "font", "status_code": 404, "response_content_type": ""},
            {"method": "POST", "url": "https://shop.test/api", "resource_type": "xhr", "status_code": 500, "response_content_type": "application/json"},
        ]
        counts = build_coverage(net)["failure_counts"]
        self.assertEqual(counts, {"mime_mismatch": 1, "failed_asset": 1, "application_error": 1})

    def test_blank_page_without_a_document_fails(self):
        report = build_coverage([{"method": "GET", "url": "https://shop.test/x.js", "resource_type": "script", "status_code": 200, "response_content_type": "application/javascript"}])
        self.assertEqual(report["status"], "failed")

    def test_permission_events_surface_as_failures(self):
        events = [{"action": "pause", "method": "POST", "path": "/api/widgets", "reason": "ambiguous", "category": "ambiguous"},
                  {"action": "deny", "method": "POST", "path": "/login", "reason": "off", "category": "auth_session"}]
        counts = build_coverage([self.doc()], permission_events=events, budget_exhausted=True)["failure_counts"]
        self.assertEqual(counts, {"needs_classification": 1, "permission_denied": 1, "budget_exhausted": 1})


class ParityTests(unittest.TestCase):
    def test_control_api_copy_is_identical(self):
        self.assertEqual((ROOT / "services/runtime-inspector/app/discovery_policy.py").read_text(), (ROOT / "services/control-api/app/discovery_policy.py").read_text())


if __name__ == "__main__":
    unittest.main()
