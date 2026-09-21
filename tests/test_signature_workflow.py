import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.signature_workflow import cli_import_commands, default_object_name, select_rules_for_detection


class SignatureWorkflowTests(unittest.TestCase):
    def test_default_name_contains_hostname_and_is_netscaler_safe(self):
        name = default_object_name("www.ess.gov.si", "bdac3c4c-32c9-4f09-aaf0-8bb65ea2ebd0")
        self.assertTrue(name.startswith("waf-www-ess-gov-si-"))
        self.assertLessEqual(len(name), 31)

    def test_selection_combines_generic_and_detected_technology_rules(self):
        profile = {
            "signature_technology_context": {"technology_matches": [{"matched_signature_tags": ["wordpress"]}]},
            "technologies": [],
        }
        analysis = {"generic_protection_intents": [{"intent_id": "cross-site-scripting-signatures", "decision": "include"}]}
        catalog = {"status": "ready", "rules": [
            {"rule_id": "1", "category": "web-client", "attack_classes": ["cross-site-scripting"], "technology_tags": []},
            {"rule_id": "2", "category": "web-wordpress", "attack_classes": [], "technology_tags": ["wordpress"]},
            {"rule_id": "3", "category": "web-misc", "attack_classes": [], "technology_tags": ["iis"]},
        ]}
        result = select_rules_for_detection(profile, analysis, catalog)
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["1", "2"])
        self.assertEqual(result["missing_requested_rule_ids"], [])

    def test_requested_ids_are_exact_and_missing_ids_are_reported(self):
        result = select_rules_for_detection(
            {"signature_technology_context": {}, "technologies": []},
            {"generic_protection_intents": []},
            {"status": "ready", "rules": [{"rule_id": "42", "category": "web-misc"}]},
            ["42", "99"],
        )
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["42"])
        self.assertEqual(result["missing_requested_rule_ids"], ["99"])

    def test_explicit_technology_filters_replace_detected_tags(self):
        profile = {
            "signature_technology_context": {"technology_matches": [{"matched_signature_tags": ["wordpress"]}]},
            "technologies": [],
        }
        result = select_rules_for_detection(
            profile,
            {"generic_protection_intents": []},
            {"status": "ready", "rules": [
                {"rule_id": "10", "technology_tags": ["wordpress"]},
                {"rule_id": "11", "technology_tags": ["perl"]},
                {"rule_id": "12", "technology_tags": ["iis"]},
            ]},
            selected_technology_tags=["perl"],
        )
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["11"])
        self.assertEqual(result["technology_tags"], ["perl"])
        self.assertEqual(result["technology_selection_mode"], "explicit")

    def test_explicit_technology_filters_can_exclude_generic_rules(self):
        result = select_rules_for_detection(
            {"signature_technology_context": {}, "technologies": []},
            {"generic_protection_intents": [{"intent_id": "cross-site-scripting-signatures", "decision": "include"}]},
            {"status": "ready", "rules": [
                {"rule_id": "20", "attack_classes": ["cross-site-scripting"]},
                {"rule_id": "21", "technology_tags": ["perl"]},
            ]},
            selected_technology_tags=["perl"],
            include_generic_signatures=False,
        )
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["21"])
        self.assertFalse(result["include_generic_signatures"])

    def test_product_filter_selects_only_rules_in_product_index(self):
        result = select_rules_for_detection(
            {"signature_technology_context": {}, "technologies": []},
            {"generic_protection_intents": []},
            {"status": "ready", "rules": [
                {"rule_id": "30", "technology_tags": ["ibm"]},
                {"rule_id": "31", "technology_tags": ["wordpress"]},
            ], "product_index": {"products": [
                {"key": "ibm/lotus-notes", "rule_ids": ["30"]},
            ]}},
            selected_technology_filters=["product:ibm/lotus-notes"],
            include_generic_signatures=False,
        )
        self.assertEqual([item["rule_id"] for item in result["selected_rules"]], ["30"])
        self.assertEqual(result["selected_product_rule_count"], 1)

    def test_commands_are_chunked_and_save_config_is_last(self):
        commands = cli_import_commands("waf-test", [str(value) for value in range(101)], "BLOCK", chunk_size=50)
        self.assertEqual(len(commands), 4)
        self.assertTrue(commands[-1].startswith("save ns config"))
        self.assertIn("-Action BLOCK", commands[0])


if __name__ == "__main__":
    unittest.main()
