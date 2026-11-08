import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app import operator_auth  # noqa: E402
from app.positive_learning import build_guided_candidate  # noqa: E402
from app.scan_scope import explicitly_allowlisted  # noqa: E402

HEADERS = {"origin": "https://192.168.11.90", "x-forwarded-proto": "https", "host": "192.168.11.90"}


class WebSocketAuthTests(unittest.TestCase):
    def check(self, headers=HEADERS, cookies=None, csrf="tok", session=None):
        session = {"sub": "operator", "csrf": "tok"} if session is None else session
        with patch.object(operator_auth, "verify_session", return_value=session or None):
            return operator_auth.authenticate_websocket(headers, cookies if cookies is not None else {operator_auth.COOKIE_NAME: "x"}, csrf)

    def test_valid_upgrade_is_accepted(self):
        self.assertEqual(self.check()["sub"], "operator")

    def test_missing_session_wrong_origin_or_csrf_are_rejected(self):
        self.assertIsNone(self.check(session={}))
        self.assertIsNone(self.check(headers={**HEADERS, "origin": "https://evil.test"}))
        self.assertIsNone(self.check(headers={**HEADERS, "x-forwarded-proto": "http"}))
        self.assertIsNone(self.check(csrf="wrong"))
        self.assertIsNone(self.check(csrf=""))


class LiveCandidateTests(unittest.TestCase):
    def source(self, **extra):
        request = {"id": "r1", "method": "POST", "path_template": "/rest/user/login", "query_names": [], "scheme": "https",
                   "body_format": "json", "body_fields": [{"name": "email", "value_class": "email-like", "length_bucket": "9-32"},
                                                          {"name": "password", "value_class": "short-text", "length_bucket": "9-32"}], **extra}
        return {"hostname": "shop.test", "session_id": "live-1", "requests": [request, {"id": "r2", "method": "GET", "path_template": "/", "query_names": []}], "evidence_source": "guided_browser"}

    def test_post_endpoint_with_body_fields_is_modelled(self):
        document = build_guided_candidate(self.source())
        endpoints = {(e.method, e.path_template): e for e in document.endpoints}
        login = endpoints[("POST", "/rest/user/login")]
        fields = {f.name: f for f in login.fields}
        self.assertEqual({"email", "password"}, {n for n in fields})
        self.assertEqual(fields["password"].location.value, "json")
        self.assertEqual(fields["password"].sensitivity.value, "credential")
        self.assertEqual(login.request_content_types, ["application/json"])
        self.assertEqual(login.decision_mode.value, "observe")

    def test_post_without_body_metadata_stays_excluded(self):
        source = self.source()
        source["requests"][0].pop("body_format")
        document = build_guided_candidate(source)
        self.assertNotIn("POST", {e.method for e in document.endpoints})


class AllowlistTests(unittest.TestCase):
    def test_only_listed_hosts_are_explicitly_allowlisted(self):
        with patch.dict(os.environ, {"SCAN_TARGET_ALLOWLIST": "192.168.11.0/24,app.example.test"}):
            self.assertTrue(explicitly_allowlisted("http://192.168.11.91/", resolve=False))
            self.assertTrue(explicitly_allowlisted("https://app.example.test/", resolve=False))
            self.assertFalse(explicitly_allowlisted("http://10.0.0.5/", resolve=False))
        with patch.dict(os.environ, {"SCAN_TARGET_ALLOWLIST": ""}):
            self.assertFalse(explicitly_allowlisted("http://192.168.11.91/", resolve=False))


if __name__ == "__main__":
    unittest.main()
