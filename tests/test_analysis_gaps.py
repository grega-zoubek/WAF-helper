import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "analysis-service"))

from app.generic_protection import build_generic_protection_intents, input_fields  # noqa: E402
from app.main import AnalysisRequest, analyze  # noqa: E402


def control(tag, kind, name="", accept=""):
    return {"tag": tag, "name": name, "id": "", "format": {"type": kind, "accept": accept}}


class FieldCountTests(unittest.TestCase):
    def test_buttons_are_not_fields_and_duplicates_collapse(self):
        profile = {"field_formats": [control("button", "")] * 500 + [control("button", "submit")] * 20
                   + [control("input", "text", "q")] * 5 + [control("input", "password", "pw")] * 5 + [control("app-mat-search-bar", "search-component")]}
        self.assertEqual(len(input_fields(profile)), 3)

    def test_legacy_items_without_tag_still_count(self):
        self.assertEqual(len(input_fields({"field_formats": [{"name": "username"}]})), 1)

    def test_buttons_alone_do_not_trigger_injection_intent(self):
        intents = {i["intent_id"] for i in build_generic_protection_intents({"field_formats": [control("button", "")] * 30, "route_inventory": []})}
        self.assertNotIn("injection-and-input-signatures", intents)


class UploadIntentTests(unittest.TestCase):
    def test_file_input_in_spa_adds_upload_intent(self):
        intents = {i["intent_id"] for i in build_generic_protection_intents({"field_formats": [control("input", "file", "file", ".pdf,.zip")]})}
        self.assertIn("file-upload-protection", intents)


class HeaderAndExposureTests(unittest.TestCase):
    def result(self, headers, evidence=()):
        obs = [{"observation": {"response": {"headers": headers, "cookies": []}, "body_retained": False}}]
        return analyze(AnalysisRequest(run_id="r", profile={"technologies": [], "evidence": list(evidence)}, observations=obs))

    def test_feature_policy_counts_as_legacy_permissions_policy(self):
        out = self.result({"feature-policy": "payment 'self'"})
        item = next(h for h in out["security_headers"] if h["header"] == "Permissions-Policy")
        self.assertTrue(item["observed"])
        self.assertNotIn("Permissions-Policy was not observed in the sampled responses", out["evidence_gaps"])

    def test_cors_wildcard_and_exposed_endpoints_are_reported(self):
        evidence = [{"evidence_type": "exposure_check", "metadata": {"kind": "prometheus-metrics", "path": "/metrics", "detail": "readable"}}]
        out = self.result({"access-control-allow-origin": "*"}, evidence)
        kinds = {f["kind"] for f in out["exposure_findings"]}
        self.assertEqual(kinds, {"prometheus-metrics", "cors-wildcard"})


if __name__ == "__main__":
    unittest.main()
