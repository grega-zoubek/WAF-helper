import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "discovery-worker"))

from app.signature_technology import STRONG_SCORE, build_signature_technology_context  # noqa: E402
from app.technology_detection import detect_technology_signals  # noqa: E402

CASES = json.loads((Path(__file__).parent / "fixtures" / "detector_cases.json").read_text(encoding="utf-8"))


class DetectorFixtureTests(unittest.TestCase):
    def test_fixtures(self):
        for name, case in CASES.items():
            with self.subTest(name):
                signals = detect_technology_signals(**case["input"])
                found = {item["technology"] for item in signals}
                for expected in case["expect"]:
                    self.assertIn(expected, found)
                for forbidden in case["forbid"]:
                    self.assertNotIn(forbidden, found)
                for weak in case.get("weak_only", []):
                    scores = [item["score"] for item in signals if item["technology"] == weak]
                    self.assertTrue(scores and max(scores) < 0.70, f"{weak} should only be a weak signal")

    def test_selection_gate_needs_strong_score_or_two_families(self):
        index = {"rules": [{"rule_id": "1", "category": "web-struts", "technology_tags": ["struts"]}]}
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "i.json"
            path.write_text(json.dumps(index), encoding="utf-8")
            base = {"technology": "Apache Struts", "technology_key": "apache-struts", "category": "framework"}
            weak = build_signature_technology_context([{**base, "confidence_score": 0.80, "signal_families": ["asset"]}], index_path=str(path))
            two = build_signature_technology_context([{**base, "confidence_score": 0.80, "signal_families": ["asset", "url"]}], index_path=str(path))
            strong = build_signature_technology_context([{**base, "confidence_score": STRONG_SCORE, "signal_families": ["asset"]}], index_path=str(path))
        self.assertEqual(weak["technology_matches"], [])
        self.assertEqual(len(two["technology_matches"]), 1)
        self.assertEqual(len(strong["technology_matches"]), 1)


if __name__ == "__main__":
    unittest.main()
