import sys
import unittest
from pathlib import Path


RUNTIME_APP = Path(__file__).resolve().parents[1] / "services" / "runtime-inspector" / "app"
sys.path.insert(0, str(RUNTIME_APP))

from auth_journey import guided_request_allowed, validated_login_target


class AuthJourneyPolicyTests(unittest.TestCase):
    def test_only_same_origin_https_post_within_scope_is_a_login_target(self):
        self.assertEqual(
            validated_login_target("https://shop.example/login", "POST", "https://shop.example/api/login", "shop.example", ["/api", "/login"]),
            ("https://shop.example", "/api/login"),
        )

    def test_rejects_http_cross_origin_out_of_scope_and_query_targets(self):
        cases = [
            ("http://shop.example/login", "POST", "http://shop.example/login"),
            ("https://shop.example/login", "GET", "https://shop.example/login"),
            ("https://shop.example/login", "POST", "https://other.example/api/login"),
            ("https://shop.example/login", "POST", "https://shop.example/outside/login"),
            ("https://shop.example/login", "POST", "https://shop.example/api/login?next=/home"),
        ]
        for page, method, action in cases:
            with self.subTest(action=action, method=method):
                with self.assertRaises(ValueError):
                    validated_login_target(page, method, action, "shop.example", ["/api", "/login"])

    def test_only_one_exact_login_post_is_permitted(self):
        session = {"auth_post_pending": True, "auth_post_used": False, "auth_post_target": {"origin": "https://shop.example", "path": "/api/login"}}
        self.assertTrue(guided_request_allowed("POST", "https://shop.example/api/login", "shop.example", ["/"], session))
        self.assertFalse(guided_request_allowed("POST", "https://shop.example/api/login", "shop.example", ["/"], session))
        self.assertFalse(guided_request_allowed("DELETE", "https://shop.example/api/items/1", "shop.example", ["/"], session))
        self.assertTrue(guided_request_allowed("GET", "https://shop.example/api/items", "shop.example", ["/"], session))
        self.assertFalse(guided_request_allowed("GET", "http://shop.example/api/items", "shop.example", ["/"], session))
        self.assertFalse(guided_request_allowed("GET", "https://shop.example:8443/api/items", "shop.example", ["/"], session))

    def test_out_of_scope_or_cross_host_post_is_never_allowed(self):
        session = {"auth_post_pending": True, "auth_post_used": False, "auth_post_target": {"origin": "https://shop.example", "path": "/api/login"}}
        self.assertFalse(guided_request_allowed("POST", "https://evil.example/api/login", "shop.example", ["/"], session))
        self.assertFalse(guided_request_allowed("POST", "https://shop.example/api/login", "shop.example", ["/public"], session))
        self.assertTrue(session["auth_post_pending"])


if __name__ == "__main__":
    unittest.main()
