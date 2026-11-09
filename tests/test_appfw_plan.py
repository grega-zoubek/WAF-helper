import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "services" / "control-api"))

from app.appfw_plan import build_plan_preview, default_profile_name  # noqa: E402
from app.openapi_export import openapi_from_model  # noqa: E402

REC = {"checks": [
    {"check_id": "start_url", "name": "Start URL", "applicability": "recommended", "profile_settings": ["startURLAction"], "proposed_objects": {"start_url_patterns": ["^/a$"]}},
    {"check_id": "csrf_form_tagging", "name": "CSRF", "applicability": "not-applicable", "profile_settings": ["CSRFtagAction"]},
    {"check_id": "buffer_overflow", "name": "Buffer overflow", "applicability": "recommended", "profile_settings": ["bufferOverflowAction"]},
]}


class PlanTests(unittest.TestCase):
    def test_only_recommended_checks_become_log_commands_and_nothing_blocks(self):
        plan = build_plan_preview(REC, "waf-chk-x")
        commands = [c["command"] for c in plan["commands"]]
        self.assertEqual(commands, ["set appfw profile waf-chk-x -startURLAction log stats learn", "set appfw profile waf-chk-x -bufferOverflowAction log stats"])
        self.assertFalse(any("block" in c.lower() for c in commands))
        self.assertTrue(plan["executed"] is False and plan["changes_applied"] is False)
        self.assertEqual(plan["relaxations"][0]["syntax"], "unverified")

    def test_unsafe_profile_names_are_rejected(self):
        for bad in ("x y", "-force", "a;b", ""):
            with self.assertRaises(ValueError):
                build_plan_preview(REC, bad)
        self.assertRegex(default_profile_name("Juice Shop.Example.COM"), r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}$")


class OpenApiTests(unittest.TestCase):
    def test_json_endpoint_exports_names_and_types_only(self):
        model = {"hostname": "x.test", "endpoints": [
            {"path_template": "/rest/user/{id:int}", "method": "POST", "response_content_types": ["application/json"], "request_content_types": ["application/json"], "authentication": "public",
             "fields": [{"name": "email", "location": "json", "proposed_constraints": {"value_type": "string", "format_hint": "email"}},
                        {"name": "age", "location": "json", "proposed_constraints": {"value_type": "number"}},
                        {"name": "q", "location": "query", "proposed_constraints": {"value_type": "string"}}]},
            {"path_template": "/index.html", "method": "GET", "response_content_types": ["text/html"], "fields": []}]}
        doc = openapi_from_model(model)
        self.assertEqual(list(doc["paths"]), ["/rest/user/{id}"])
        op = doc["paths"]["/rest/user/{id}"]["post"]
        self.assertEqual(op["parameters"][0], {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}})
        props = op["requestBody"]["content"]["application/json"]["schema"]["properties"]
        self.assertEqual(props["email"], {"type": "string", "format": "email"})
        self.assertEqual(props["age"]["type"], "number")


if __name__ == "__main__":
    unittest.main()
