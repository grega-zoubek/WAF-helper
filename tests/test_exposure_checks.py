import ast
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "discovery-worker"))

from app.technology_detection import detect_technology_signals  # noqa: E402


def load_classifier():
    tree = ast.parse((ROOT / "services/discovery-worker/app/main.py").read_text(encoding="utf-8"))
    wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "classify_exposure"]
    namespace = {}
    exec(compile(ast.Module(wanted, []), "classifier", "exec"), namespace)
    return namespace["classify_exposure"]


class ExposureClassifierTests(unittest.TestCase):
    def setUp(self):
        self.classify = load_classifier()

    def test_spa_fallback_html_is_never_an_exposure(self):
        html = "<!doctype html><html><app-root></app-root></html>"
        for path in ("/robots.txt", "/sitemap.xml", "/metrics", "/swagger.json", "/health", "/.well-known/security.txt"):
            self.assertIsNone(self.classify(path, 200, "text/html; charset=UTF-8", html), path)

    def test_real_files_are_reported(self):
        cases = [
            ("/robots.txt", "text/plain", "User-agent: *\nDisallow: /admin", "robots-txt"),
            ("/sitemap.xml", "application/xml", "<?xml version='1.0'?><urlset>", "sitemap"),
            ("/.well-known/security.txt", "text/plain", "Contact: mailto:a@b.c", "security-txt"),
            ("/metrics", "text/plain; version=0.0.4", "# HELP process_cpu_seconds_total x", "prometheus-metrics"),
            ("/swagger.json", "application/json", '{"swagger": "2.0"}', "api-schema"),
            ("/api-docs", "text/html", "<title>Swagger UI</title>", "api-docs"),
            ("/api-docs/", "text/html", "<title>Swagger UI</title>", "api-docs"),
            ("/health", "application/json", '{"status":"UP"}', "health-endpoint"),
        ]
        for path, media, body, kind in cases:
            self.assertEqual(self.classify(path, 200, media, body)["kind"], kind, path)

    def test_non_200_is_ignored(self):
        self.assertIsNone(self.classify("/metrics", 404, "text/plain", "# HELP x"))


class UploadDetectionTests(unittest.TestCase):
    def names(self, **kw):
        return {s["technology"] for s in detect_technology_signals(url="https://x.test/", **kw)}

    def test_file_input_without_multipart_form_is_an_upload_surface(self):
        self.assertIn("File upload surface", self.names(controls=[{"tag": "input", "type": "file", "accept": ".pdf,.zip"}]))

    def test_other_inputs_are_not(self):
        self.assertNotIn("File upload surface", self.names(controls=[{"tag": "input", "type": "text"}]))


if __name__ == "__main__":
    unittest.main()
