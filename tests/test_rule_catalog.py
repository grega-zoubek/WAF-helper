import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.rule_catalog import resolve_rule_catalog


class RuleCatalogTests(unittest.TestCase):
    def test_missing_rule_level_catalog_fails_closed(self):
        result = resolve_rule_catalog([
            {"intent_id": "generic-web-attack-signatures", "decision": "include"},
        ], [])
        self.assertEqual(result["status"], "blocked-missing-rule-level-catalog")
        self.assertFalse(result["automatic_apply_allowed"])
        self.assertEqual(result["selected_rules"], [])

    def test_predefined_mapping_selects_only_matching_rules(self):
        result = resolve_rule_catalog([
            {"intent_id": "generic-web-attack-signatures", "decision": "include"},
            {"intent_id": "technology-specific-signatures", "decision": "conditional"},
        ], [
            {"rule_id": 1001, "category": "misc", "attack_class": "cross-site-scripting", "description": "XSS"},
            {"rule_id": 1002, "category": "php", "attack_class": "php-specific", "description": "PHP"},
        ])
        self.assertEqual(result["status"], "resolved")
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["1001"])
        self.assertEqual(result["conditional_intents"], ["technology-specific-signatures"])
        self.assertFalse(result["automatic_apply_allowed"])


if __name__ == "__main__":
    unittest.main()
