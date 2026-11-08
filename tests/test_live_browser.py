import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "runtime-inspector"))

from app.live_policy import key_to_cdp, live_request_allowed, mouse_to_cdp, post_body_shape  # noqa: E402
from app.target_guard import scan_target_error as inspector_guard  # noqa: E402


def allowed(mode, method, url, rtype="xhr"):
    return live_request_allowed(mode, method, url, rtype, "shop.test", ["/"])


class PolicyTests(unittest.TestCase):
    def test_read_only_is_get_head_same_host(self):
        self.assertTrue(allowed("read_only", "GET", "https://shop.test/a"))
        self.assertFalse(allowed("read_only", "POST", "https://shop.test/login"))
        self.assertFalse(allowed("read_only", "GET", "https://cdn.test/a.js", "script"))

    def test_free_allows_same_host_writes_and_cross_host_subresources_only(self):
        self.assertTrue(allowed("free", "POST", "https://shop.test/rest/login"))
        self.assertTrue(allowed("free", "DELETE", "https://shop.test/api/x"))
        self.assertTrue(allowed("free", "GET", "https://cdn.test/lib.js", "script"))
        self.assertFalse(allowed("free", "POST", "https://tracker.test/collect"))
        self.assertFalse(allowed("free", "GET", "https://other.test/", "document"))

    def test_free_scopes_document_navigation_to_paths(self):
        self.assertFalse(live_request_allowed("free", "GET", "https://shop.test/admin", "document", "shop.test", ["/shop"]))
        self.assertTrue(live_request_allowed("free", "GET", "https://shop.test/rest/x", "xhr", "shop.test", ["/shop"]))

    def test_internal_and_odd_schemes_always_refused(self):
        for url in ("http://postgres:5432/", "http://169.254.169.254/", "http://127.0.0.1/", "file:///etc/passwd", "ftp://shop.test/"):
            self.assertFalse(allowed("free", "GET", url), url)
        self.assertFalse(allowed("bogus", "GET", "https://shop.test/"))

    def test_target_guard_parity_with_control_api(self):
        sys.path.insert(0, str(ROOT / "services" / "control-api"))
        import importlib.util
        spec = importlib.util.spec_from_file_location("cp_scope", ROOT / "services/control-api/app/scan_scope.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for url in ("http://postgres/", "http://10.1.2.3/", "https://example.test/", "http://127.0.0.1/", "ftp://x/", "http://a:b@x.test/"):
            self.assertEqual(inspector_guard(url, resolve=False), module.scan_target_error(url, resolve=False), url)


class BodyShapeTests(unittest.TestCase):
    SECRET = "S3cr3t-Passw0rd!"

    def test_form_body_keeps_names_and_classes_not_values(self):
        shape = post_body_shape("application/x-www-form-urlencoded", f"email=a%40b.com&password={self.SECRET}&age=42&empty=")
        self.assertEqual({f["name"]: f["value_class"] for f in shape["fields"]}, {"email": "email-like", "password": "short-text", "age": "number", "empty": "empty"})
        self.assertNotIn(self.SECRET, json.dumps(shape))
        self.assertNotIn("a@b.com", json.dumps(shape))

    def test_json_body_is_flattened_without_values(self):
        shape = post_body_shape("application/json", json.dumps({"user": {"email": "x@y.io", "pw": self.SECRET}, "remember": True, "tags": ["a"]}))
        names = {f["name"]: f["value_class"] for f in shape["fields"]}
        self.assertEqual(names, {"user.email": "email-like", "user.pw": "short-text", "remember": "boolean", "tags": "array"})
        self.assertNotIn(self.SECRET, json.dumps(shape))

    def test_bad_names_and_invalid_bodies_are_safe(self):
        shape = post_body_shape("application/x-www-form-urlencoded", "a%20b%3Cscript%3E=1")
        self.assertEqual(shape["fields"][0]["name"], "(invalid-name)")
        self.assertEqual(post_body_shape("application/json", "{not json")["format"], "json-invalid")
        self.assertEqual(post_body_shape("text/plain", "hello")["fields"], [])

    def test_multipart_returns_names_only(self):
        body = f'--b\r\nContent-Disposition: form-data; name="avatar"; filename="{self.SECRET}.png"\r\n\r\nBINARY\r\n--b--'
        shape = post_body_shape("multipart/form-data; boundary=b", body)
        self.assertEqual([f["name"] for f in shape["fields"]], ["avatar"])
        self.assertNotIn(self.SECRET, json.dumps(shape))


class InputMappingTests(unittest.TestCase):
    def test_mouse_mapping_clamps_and_validates(self):
        self.assertIsNone(mouse_to_cdp({"action": "teleport"}))
        params = mouse_to_cdp({"action": "down", "x": 99999, "y": -5, "button": 2})
        self.assertEqual((params["type"], params["x"], params["y"], params["button"]), ("mousePressed", 4096.0, 0.0, "right"))
        wheel = mouse_to_cdp({"action": "wheel", "x": 10, "y": 10, "delta_y": 100000})
        self.assertEqual(wheel["deltaY"], 5000.0)

    def test_key_mapping(self):
        down = key_to_cdp({"action": "down", "key": "a", "code": "KeyA", "key_code": 65})
        self.assertEqual((down["type"], down["text"]), ("keyDown", "a"))
        ctrl = key_to_cdp({"action": "down", "key": "a", "code": "KeyA", "modifiers": 2})
        self.assertNotIn("text", ctrl)
        self.assertEqual(key_to_cdp({"action": "down", "key": "Enter"})["text"], "\r")
        self.assertIsNone(key_to_cdp({"action": "press", "key": "a"}))


if __name__ == "__main__":
    unittest.main()
