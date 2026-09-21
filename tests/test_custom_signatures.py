import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.custom_signatures import LOCAL_RULE_ID_MAX, LOCAL_RULE_ID_MIN, build_custom_signature_spec, validate_draft_input


BASE_REQUEST = {
    "signature_object_name": "WAF_Local_Test",
    "rule_name": "Known test marker",
    "category": "web-misc",
    "log_string": "WAF Intelligence test marker",
    "comment": "Offline validation only",
    "pattern_type": "literal",
    "pattern": "WAF-INTELLIGENCE-TEST",
    "match_location": "BODY",
    "action": "LOG",
    "enabled": False,
    "harm_score": 3,
    "severity": "Low",
    "violation_type": "Warning",
    "positive_test_cases": ["prefix WAF-INTELLIGENCE-TEST suffix"],
    "negative_test_cases": ["prefix WAF-INTELLIGENCE suffix"],
    "evidence_refs": ["technology:Angular", "route:/login"],
}


class CustomSignatureTests(unittest.TestCase):
    def test_builds_disabled_local_rule_spec_with_detection_context(self):
        spec = build_custom_signature_spec(
            request=BASE_REQUEST,
            job={"id": "job-1", "status": "completed", "scope": {"seed_url": "http://example.test/"}},
            profile={
                "technology_detector_version": "1.1.0",
                "technologies": [{"technology": "Angular", "confidence": "high", "confidence_score": 0.94, "evidence_count": 3}],
                "signature_technology_context": {"status": "no-technology-tag-match"},
                "route_inventory": [{"path": "/login"}],
                "field_formats": [{"name": "username"}],
                "evidence": [{"id": 1}],
            },
        )
        self.assertEqual(spec["status"], "draft-needs-review")
        self.assertTrue(LOCAL_RULE_ID_MIN <= spec["rule"]["rule_id"] <= LOCAL_RULE_ID_MAX)
        self.assertFalse(spec["rule"]["enabled"])
        self.assertEqual(spec["rule"]["actions"], ["LOG"])
        self.assertEqual(spec["detection_context"]["technologies"][0]["technology"], "Angular")
        self.assertIsNone(spec["provider_artifact"]["native_xml"])

    def test_rejects_enabled_rule_and_missing_offline_tests(self):
        request = {**BASE_REQUEST, "enabled": True, "positive_test_cases": [], "negative_test_cases": []}
        errors = validate_draft_input(request)
        self.assertIn("new custom rules must start disabled and be promoted only after review", errors)
        self.assertIn("at least one positive and one negative offline test case are required", errors)

    def test_rejects_invalid_pcre(self):
        request = {**BASE_REQUEST, "pattern_type": "pcre", "pattern": "([a-z"}
        errors = validate_draft_input(request)
        self.assertTrue(any("pcre pattern is not locally compilable" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
