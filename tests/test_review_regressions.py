"""Regression tests for the 2026-11-08 code review (findings H1-H4)."""
import ast
import json
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path


WORKER = Path(__file__).parents[1] / "services" / "discovery-worker"
sys.path.insert(0, str(WORKER))

from app.signature_technology import build_signature_technology_context  # noqa: E402
from app.technology_detection import detect_technology_signals  # noqa: E402


def names(**kwargs):
    return {item["technology"] for item in detect_technology_signals(**kwargs)}


def load_surface_parser():
    """Load SurfaceParser without importing httpx/psycopg/fastapi."""
    tree = ast.parse((WORKER / "app" / "main.py").read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "SurfaceParser")
    namespace = {"HTMLParser": HTMLParser, "Any": object}
    exec(compile(ast.Module([cls], []), "surface_parser", "exec"), namespace)
    return namespace["SurfaceParser"]


class DetectorRegressionTests(unittest.TestCase):
    def test_generic_session_cookies_are_not_drupal(self):  # H1
        self.assertNotIn("Drupal", names(url="https://x.test/", cookies=["session", "sessionid", "sess_id"]))

    def test_real_drupal_session_cookie_is_detected(self):  # H1
        cookie = "SESS" + "a1" * 16
        self.assertIn("Drupal", names(url="https://x.test/", cookies=[cookie]))

    def test_soap_word_in_css_or_html_is_not_xml_service(self):  # H3
        self.assertNotIn("XML or SOAP", names(url="https://x.test/a.css", headers={"content-type": "text/css"}, body=".soap-dish{}"))
        self.assertNotIn("XML or SOAP", names(url="https://x.test/", headers={"content-type": "text/html"}, body="<h1>Soap shop</h1>"))
        self.assertNotIn("XML or SOAP", names(url="https://x.test/", headers={"content-type": "application/xhtml+xml"}, body="<html/>"))

    def test_real_xml_and_soap_are_detected(self):  # H3
        self.assertIn("XML or SOAP", names(url="https://x.test/svc", headers={"content-type": "text/xml; charset=utf-8"}, body="<a/>"))
        envelope = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>'
        self.assertIn("XML or SOAP", names(url="https://x.test/svc", headers={"content-type": "text/html"}, body=envelope))

    def test_graphql_word_in_page_is_not_graphql(self):  # H3
        self.assertNotIn("GraphQL", names(url="https://x.test/", headers={"content-type": "text/html"}, body="<p>we love graphql</p>"))
        self.assertIn("GraphQL", names(url="https://x.test/graphql", headers={"content-type": "application/json"}))


class SelectionGateTests(unittest.TestCase):
    def _context(self, technologies):
        catalog = {"rules": [{"rule_id": "1", "category": "drupal", "technology_tags": ["drupal"]},
                             {"rule_id": "2", "category": "web-struts", "technology_tags": ["struts"]},
                             {"rule_id": "3", "category": "web-misc", "technology_tags": ["java"]}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            return build_signature_technology_context(technologies, index_path=str(path))

    def test_low_confidence_technology_does_not_select_rules(self):  # H2
        result = self._context([{"technology": "Drupal", "technology_key": "drupal", "category": "cms", "confidence_score": 0.30}])
        self.assertEqual(result["technology_matches"], [])
        self.assertEqual(result["below_threshold_technologies"][0]["technology_key"], "drupal")

    def test_confident_technology_still_matches(self):  # H2
        result = self._context([{"technology": "Drupal", "technology_key": "drupal", "category": "cms", "confidence_score": 0.93}])
        self.assertEqual(result["technology_matches"][0]["example_rule_ids"], ["1"])

    def test_java_runtime_does_not_pull_struts(self):  # H2
        result = self._context([{"technology": "Java", "technology_key": "java", "category": "server-runtime", "confidence_score": 0.90}])
        self.assertEqual(result["technology_matches"][0]["matched_signature_tags"], ["java"])


class CrawlerParserTests(unittest.TestCase):
    def test_inline_script_text_is_captured(self):  # H4
        parser = load_surface_parser()()
        parser.feed('<script src="/a.js"></script><script>router.navigate("/inline/route")</script><p>x</p>')
        self.assertIn("/inline/route", "".join(parser.inline_script_parts))
        self.assertEqual(parser.assets, ["/a.js"])


if __name__ == "__main__":
    unittest.main()
