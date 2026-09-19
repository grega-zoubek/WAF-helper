import unittest

from app.analysis.applicability import version_matches
from app.assessment import run
from app.models import Component, Signature, SignatureState, Vulnerability


class AssessmentTests(unittest.TestCase):
    def test_version_range(self):
        self.assertTrue(version_matches("2.4.7", ">=2.4.0,<2.5.0"))
        self.assertFalse(version_matches("2.5.0", ">=2.4.0,<2.5.0"))

    def test_confirmed_vulnerability_generates_read_only_monitor_recommendation(self):
        result = run(
            "shop.example.com",
            [Component("WordPress", "6.9.4", evidence_type="SBOM", evidence_source="CycloneDX", confidence=1.0)],
            [Vulnerability("CVE-2026-63030", "WordPress", ">=6.0.0,<7.0.0", severity=9.8, kev=True)],
            [Signature(998105, ("CVE-2026-63030",), "WordPress", performance_warning=True)],
            [SignatureState(998105, True, False)],
        )
        self.assertEqual(result.applicable[0]["applicability"], "CONFIRMED")
        self.assertEqual(result.coverage[0]["status"], "SIGNATURE_AVAILABLE_NOT_ENABLED")
        self.assertTrue(result.recommendations[0]["read_only"])
        self.assertFalse(result.recommendations[0]["desired_state"]["block"])

    def test_missing_signature_is_a_gap_without_mutation_recommendation(self):
        result = run(
            "portal.example.com",
            [Component("Django", "5.1.2", evidence_type="SBOM", evidence_source="CycloneDX", confidence=1.0)],
            [Vulnerability("CVE-1", "Django", "==5.1.2")],
            [],
            [],
        )
        self.assertEqual(result.coverage[0]["status"], "NO_NETSCALER_SIGNATURE")
        self.assertEqual(result.recommendations, [])


if __name__ == "__main__":
    unittest.main()
