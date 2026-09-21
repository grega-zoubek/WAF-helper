import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.rule_catalog import resolve_rule_catalog

_adapter_spec = importlib.util.spec_from_file_location(
    "adapter_rule_catalog",
    Path(__file__).parents[1] / "services" / "netscaler-adapter" / "app" / "rule_catalog.py",
)
_adapter_module = importlib.util.module_from_spec(_adapter_spec)
assert _adapter_spec.loader is not None
_adapter_spec.loader.exec_module(_adapter_module)
load_rule_catalog = _adapter_module.load_rule_catalog
extract_vendor_products = _adapter_module.extract_vendor_products
build_product_index = _adapter_module.build_product_index


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

    def test_adapter_catalog_file_is_fail_closed_when_not_configured(self):
        result = load_rule_catalog("")
        self.assertEqual(result["status"], "not-configured")
        self.assertEqual(result["rules"], [])

    def test_adapter_parses_netscaler_signature_rule_metadata(self):
        xml = """<?xml version=\"1.0\"?>
        <SignaturesFile schema_version=\"6\">
          <Signatures>
            <SignatureRule id=\"1001\" enabled=\"ON\" actions=\"log,block\" category=\"sql\" source=\"Snort\" version=\"2\">
              <PatternList><RequestPatterns><Pattern>
                <Location area=\"HTTP_POST_BODY\"/>
                <Match type=\"SQLInjection\">select</Match>
              </Pattern></RequestPatterns></PatternList>
              <LogString>SQL injection test</LogString>
              <Reference>cve,2024-0001</Reference>
            </SignatureRule>
            <SignatureRule id=\"1002\" enabled=\"OFF\" actions=\"log\" category=\"xss\" source=\"Snort\" version=\"1\">
              <PatternList><RequestPatterns><Pattern>
                <Location area=\"HTTP_URL\"/>
                <Match type=\"CrossSiteScripting\">script</Match>
              </Pattern></RequestPatterns></PatternList>
              <LogString>Cross-site scripting test</LogString>
            </SignatureRule>
          </Signatures>
        </SignaturesFile>"""
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "default_signatures.xml"
            source.write_text(xml, encoding="utf-8")
            result = load_rule_catalog(str(source))
        self.assertEqual(result["status"], "enumerated")
        self.assertEqual(result["rule_count"], 2)
        self.assertEqual(result["rules"][0]["rule_id"], "1001")
        self.assertIn("sql-injection", result["rules"][0]["attack_classes"])
        self.assertEqual(result["rules"][0]["locations"], ["http_post_body"])
        self.assertEqual(result["rules"][0]["reference_count"], 1)
        self.assertFalse(result["rules"][1]["enabled"])

    def test_product_index_groups_vendor_and_product_from_log_string(self):
        entities = extract_vendor_products("VMware vCenter Server path traversal and IBM Lotus Notes access")
        keys = {item["key"] for item in entities}
        self.assertIn("vmware/vcenter", keys)
        self.assertIn("ibm/lotus-notes", keys)
        index = build_product_index([
            {"rule_id": "1", "vendor_products": entities},
            {"rule_id": "2", "vendor_products": extract_vendor_products("VMware ESXi overflow")},
        ])
        vmware = next(item for item in index["vendors"] if item["vendor"] == "VMware")
        self.assertEqual(vmware["product_count"], 2)
        self.assertEqual(index["product_count"], 3)


if __name__ == "__main__":
    unittest.main()
