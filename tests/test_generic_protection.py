import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "analysis-service"))

from app.generic_protection import automation_policy, build_generic_protection_intents


class GenericProtectionTests(unittest.TestCase):
    def test_juice_shop_uses_generic_intents_not_product_specific_catalogs(self):
        intents = build_generic_protection_intents({
            "technologies": [{"technology": "Angular", "technology_key": "angular", "category": "framework"}],
            "route_inventory": [{"source_url": "/"}, {"source_url": "/api"}],
            "field_formats": [],
            "evidence": [],
        })
        by_id = {item["intent_id"]: item for item in intents}
        self.assertEqual(by_id["generic-web-attack-signatures"]["decision"], "include")
        self.assertEqual(by_id["cross-site-scripting-signatures"]["decision"], "include")
        self.assertEqual(by_id["technology-specific-signatures"]["decision"], "conditional")
        self.assertNotIn("wordpress", {item["intent_id"] for item in intents})

    def test_forms_and_authentication_add_generic_input_intents(self):
        intents = build_generic_protection_intents({
            "technologies": [],
            "route_inventory": [],
            "field_formats": [{"name": "search"}],
            "evidence": [
                {"technology": "Authentication boundary", "metadata": {"cookie_names": ["session"]}},
            ],
        })
        ids = {item["intent_id"] for item in intents}
        self.assertIn("injection-and-input-signatures", ids)
        self.assertIn("session-and-authentication-protection", ids)

    def test_automation_is_fail_closed_and_ai_advisory_only(self):
        policy = automation_policy()
        self.assertEqual(policy["mode"], "proposal-only")
        self.assertFalse(policy["automatic_apply"]["enabled"])
        self.assertFalse(policy["ai_advisor"]["enabled"])
        self.assertTrue(policy["ai_advisor"]["cannot_apply_changes"])


if __name__ == "__main__":
    unittest.main()
