import ast
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "discovery-worker"))

from app.field_roles import classify_field, template_path  # noqa: E402


def role(**control):
    verdict = classify_field(control)
    return verdict["role"] if verdict else None


def load_parser():
    tree = ast.parse((ROOT / "services/discovery-worker/app/main.py").read_text(encoding="utf-8"))
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SurfaceParser")
    ns = {"HTMLParser": HTMLParser, "Any": object}
    exec(compile(ast.Module([cls], []), "parser", "exec"), ns)
    return ns["SurfaceParser"]


class RoleTests(unittest.TestCase):
    def test_core_roles(self):
        cases = [
            (dict(tag="input", type="password", name="pw"), "password"),
            (dict(tag="input", type="text", name="userName"), "username"),
            (dict(tag="input", type="text", autocomplete="username"), "username"),
            (dict(tag="input", type="email", name="x"), "email"),
            (dict(tag="input", type="search", name="q"), "search"),
            (dict(tag="app-mat-search-bar", type="search-component"), "search"),
            (dict(tag="input", type="text", name="query"), "search"),
            (dict(tag="input", type="file", accept=".pdf"), "file"),
            (dict(tag="input", type="hidden", name="csrf_token"), "csrf-token"),
            (dict(tag="input", type="hidden", name="step"), "hidden"),
            (dict(tag="input", type="text", autocomplete="cc-number"), "card"),
            (dict(tag="input", type="text", autocomplete="one-time-code"), "otp"),
            (dict(tag="input", type="tel", name="p"), "phone"),
            (dict(tag="input", type="number", name="qty"), "numeric"),
            (dict(tag="input", type="text", name="productId"), "numeric"),
            (dict(tag="textarea", name="comment"), "free-text"),
            (dict(tag="input", type="text", name="captchaControl"), "captcha"),
            (dict(tag="input", type="checkbox", name="rememberMe"), "choice"),
        ]
        for control, expected in cases:
            self.assertEqual(role(**control), expected, control)

    def test_buttons_are_not_fields(self):
        for control in (dict(tag="button"), dict(tag="input", type="submit"), dict(tag="input", type="button")):
            self.assertIsNone(classify_field(control))

    def test_injection_prone_flag_and_sensitivity(self):
        self.assertTrue(classify_field(dict(tag="input", type="search"))["injection_prone"])
        self.assertTrue(classify_field(dict(tag="textarea"))["injection_prone"])
        password = classify_field(dict(tag="input", type="password"))
        self.assertFalse(password["injection_prone"])
        self.assertEqual(password["sensitivity"], "credential")
        self.assertTrue(classify_field(dict(tag="input", type="text", name="q"))["signals"])

    def test_path_templates(self):
        self.assertEqual(template_path("/product/42/reviews/7"), "/product/{id:int}/reviews/{id2:int}")
        self.assertEqual(template_path("/u/123e4567-e89b-12d3-a456-426614174000"), "/u/{id:uuid}")
        self.assertEqual(template_path("/about/us"), "/about/us")


class FormParsingTests(unittest.TestCase):
    def test_controls_know_their_form_and_label(self):
        parser = load_parser()()
        parser.feed('<form action="/login" method="post"><label for="e">Email address</label><input id="e" name="email">'
                    '<label>Password <input type="password" name="pw"></label><button>Go</button></form>'
                    '<form action="/search"><input type="search" name="q"></form><input name="outside">')
        parser.finalize()
        by_name = {c["name"]: c for c in parser.controls}
        self.assertEqual((by_name["email"]["form_index"], by_name["email"]["label"]), (0, "Email address"))
        self.assertEqual((by_name["pw"]["form_index"], by_name["pw"]["label"]), (0, "Password"))
        self.assertEqual(by_name["q"]["form_index"], 1)
        self.assertEqual(by_name["outside"]["form_index"], -1)


class LabelClassificationTests(unittest.TestCase):
    def test_label_alone_can_decide_the_role(self):
        self.assertEqual(role(tag="input", type="text", name="mat-input-1", label="Search for products"), "search")
        self.assertEqual(role(tag="input", type="text", name="mat-input-2", label="Email address"), "email")


class InspectorCopyParity(unittest.TestCase):
    def test_copies_are_identical(self):
        original = (ROOT / "services/discovery-worker/app/field_roles.py").read_text()
        for service in ("runtime-inspector", "control-api", "analysis-service"):
            self.assertEqual((ROOT / f"services/{service}/app/field_roles.py").read_text(), original, service)


if __name__ == "__main__":
    unittest.main()
