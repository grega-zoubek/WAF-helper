import ast
import os
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "control-api"))

from app.scan_scope import scan_target_error  # noqa: E402


def load_destructive_helpers():
    """Pull the pure helpers out of discovery-worker/main.py without importing httpx/psycopg."""
    tree = ast.parse((ROOT / "services/discovery-worker/app/main.py").read_text(encoding="utf-8"))
    wanted = [n for n in tree.body if (isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "DESTRUCTIVE_PATH_RE" for t in n.targets))
              or (isinstance(n, ast.FunctionDef) and n.name == "is_destructive_url")]
    namespace = {"re": re, "urlparse": urlparse}
    exec(compile(ast.Module(wanted, []), "helpers", "exec"), namespace)
    return namespace["is_destructive_url"]


class ScanScopeTests(unittest.TestCase):
    def test_internal_and_reserved_targets_are_refused(self):
        for url in ("http://postgres:5432/", "http://netscaler-adapter:8092/api", "http://localhost/", "http://127.0.0.1/",
                    "http://169.254.169.254/latest", "http://0.0.0.0/", "ftp://example.test/", "http://user:pw@example.test/"):
            self.assertIsNotNone(scan_target_error(url, resolve=False), url)

    def test_lan_and_public_targets_are_allowed(self):
        for url in ("http://192.168.11.91/", "https://www.example.test/"):
            self.assertIsNone(scan_target_error(url, resolve=False), url)

    def test_allowlist_restricts_targets(self):
        os.environ["SCAN_TARGET_ALLOWLIST"] = "192.168.11.0/24,app.example.test"
        try:
            self.assertIsNone(scan_target_error("http://192.168.11.91/", resolve=False))
            self.assertIsNone(scan_target_error("https://app.example.test/", resolve=False))
            self.assertIsNotNone(scan_target_error("http://10.0.0.5/", resolve=False))
        finally:
            del os.environ["SCAN_TARGET_ALLOWLIST"]


class CrawlerDenyListTests(unittest.TestCase):
    def test_action_like_links_are_not_followed(self):
        is_destructive = load_destructive_helpers()
        for url in ("https://a.test/logout", "https://a.test/user/delete/5", "https://a.test/#/sign-out", "https://a.test/newsletter/unsubscribe?id=1"):
            self.assertTrue(is_destructive(url), url)
        for url in ("https://a.test/products", "https://a.test/undeleted-items", "https://a.test/forgot-password"):
            self.assertFalse(is_destructive(url), url)


if __name__ == "__main__":
    unittest.main()
