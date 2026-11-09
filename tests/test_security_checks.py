import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "analysis-service"))

from app.security_checks import _regex_for, build_security_check_recommendations  # noqa: E402


def field(name, role, tag="input", kind="text"):
    return {"name": name, "id": "", "tag": tag, "role": role, "format": {"type": kind}, "injection_prone": role in {"search", "email", "free-text", "numeric"}}


SPA = {
    "route_inventory": [{"source_url": "http://x.test/"}, {"source_url": "http://x.test/#/login"}, {"source_url": "http://x.test/assets/a.css"}],
    "api_endpoints": [{"method": "GET", "url": "http://x.test/api/Products/12"}, {"method": "POST", "url": "http://x.test/rest/user/login"}],
    "form_endpoints": [{"method": "SCRIPT", "path_template": "/login", "fields": [{"name": "email", "role": "email", "type": "email"}, {"name": "password", "role": "password", "type": "password"}]}],
    "field_formats": [field("email", "email"), field("password", "password", kind="password"), field("q", "search")],
    "evidence": [],
}
SERVER = {
    "route_inventory": [{"source_url": "http://x.test/shop"}], "api_endpoints": [],
    "form_endpoints": [{"method": "POST", "path_template": "/checkout", "fields": [{"name": "card", "role": "card", "type": "text"}, {"name": "csrf", "role": "csrf-token", "type": "hidden"}]}],
    "field_formats": [field("card", "card"), field("csrf", "csrf-token", kind="hidden")],
    "evidence": [{"metadata": {"cookie_names": ["SESSIONID"]}}],
}


def by_id(result):
    return {c["check_id"]: c for c in result["checks"]}


class RecommenderTests(unittest.TestCase):
    def test_spa_gets_json_and_start_url_but_not_form_tracking(self):
        checks = by_id(build_security_check_recommendations(SPA, [{"endpoint": "SCRIPT /login", "fields": ["email"], "roles": ["email"]}]))
        self.assertEqual(checks["json_injection"]["applicability"], "recommended")
        self.assertEqual(checks["form_field_consistency"]["applicability"], "not-applicable")
        self.assertEqual(checks["csrf_form_tagging"]["applicability"], "not-applicable")
        self.assertEqual(checks["start_url"]["false_positive_risk"], "high")
        patterns = checks["start_url"]["proposed_objects"]["start_url_patterns"]
        self.assertIn("^/api/Products/[0-9]+$", patterns)
        self.assertFalse([p for p in patterns if "#" in p])
        fields = {(f["field"], f["suggested_type"]) for f in checks["field_formats"]["proposed_objects"]["fields"]}
        self.assertIn(("email", "email"), fields)
        self.assertNotIn("password", {f for f, _ in fields})

    def test_server_rendered_app_gets_form_checks_and_cookies(self):
        result = build_security_check_recommendations(SERVER, [])
        checks = by_id(result)
        self.assertEqual(checks["form_field_consistency"]["applicability"], "recommended")
        self.assertEqual(checks["csrf_form_tagging"]["applicability"], "recommended")
        self.assertTrue(any("anti-forgery" in n for n in checks["csrf_form_tagging"]["notes"]))
        self.assertEqual(checks["cookie_consistency"]["applicability"], "recommended")
        self.assertEqual(checks["credit_card"]["applicability"], "conditional")
        self.assertEqual(checks["json_injection"]["applicability"], "not-applicable")

    def test_everything_is_log_and_proposal_only(self):
        result = build_security_check_recommendations(SPA, [])
        self.assertTrue(result["changes_applied"] is False and result["default_action"] == "LOG")
        self.assertEqual({c["proposed_action"] for c in result["checks"]}, {"LOG"})

    def test_regex_for_templates(self):
        self.assertEqual(_regex_for("/p/{id:int}/x.js"), "^/p/[0-9]+/x\\.js$")


if __name__ == "__main__":
    unittest.main()
