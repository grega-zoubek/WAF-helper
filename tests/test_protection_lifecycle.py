import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))
sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "netscaler-adapter"))

from app.protection_lifecycle import build_exception_selection, build_promote_selection, summarize_protection_status
from app.cli_inventory import build_protection_status, parse_appfw_stats
from app.positive_compile import compile_observe_only_preview, structured_endpoint_editor_payload


class ProtectionLifecycleTests(unittest.TestCase):
    def test_promote_to_block_keeps_subset(self):
        record = {
            "custom_signature_set_id": "set-1",
            "signature_object_name": "waf-app",
            "action": "LOG",
            "selected_rules": [{"rule_id": "10"}, {"rule_id": "20"}, {"rule_id": "30"}],
        }
        result = build_promote_selection(record, ["20", "30"])
        self.assertEqual(result["action"], "BLOCK")
        self.assertEqual(result["selected_rule_ids"], ["20", "30"])
        self.assertTrue(result["signature_object_name"].endswith("blk") or "blk" in result["signature_object_name"])

    def test_exception_removes_noisy_rules(self):
        record = {
            "custom_signature_set_id": "set-1",
            "signature_object_name": "waf-app",
            "action": "LOG",
            "selected_rules": [{"rule_id": "10"}, {"rule_id": "20"}],
        }
        result = build_exception_selection(record, ["10"])
        self.assertEqual(result["selected_rule_ids"], ["20"])
        self.assertEqual(result["disabled_rule_ids"], ["10"])
        self.assertEqual(result["action"], "LOG")

    def test_parse_appfw_stats_key_value_and_rows(self):
        text = "Name: policy-a\nHits: 7\nLast Hit: yesterday\n\npolicy-b 3 UP\n"
        rows = parse_appfw_stats(text)
        names = {item["name"]: item["hits"] for item in rows}
        self.assertEqual(names["policy-a"], 7)
        self.assertEqual(names["policy-b"], 3)

    def test_build_protection_status_filters_signature_object(self):
        outputs = {
            "show ns feature": "18) Application Firewall AppFw ON\n",
            "show appfw profile": "1) Name: demo-profile\n\tSignatures: waf-demo\n",
            "show appfw policy": "Done\n",
            "show appfw signatures": (
                "1) Url: a.xml Name: \"waf-demo\"\n\tBase Version: \"1\" Size: 1 bytes Encrypted Version: \"1\"\n"
                "2) Url: b.xml Name: \"other\"\n\tBase Version: \"1\" Size: 1 bytes Encrypted Version: \"1\"\n"
                "Total signatures Size: 0 bytes\n"
            ),
            "show appfw settings": "",
            "stat appfw": "Name: demo-profile\nHits: 9\n",
        }
        result = build_protection_status(outputs, signature_object_name="waf-demo")
        self.assertEqual([item["name"] for item in result["signatures"]], ["waf-demo"])
        self.assertTrue(result["hits_available"])
        self.assertEqual(result["profiles"][0]["hits"], 9)

    def test_summarize_protection_status_prefers_exported_set(self):
        summary = summarize_protection_status(
            {"status": "enumerated", "bound_vservers": ["lb1"], "profiles": [], "policies": [], "hit_counters": [], "hits_available": False, "signature_object_name": "waf-demo"},
            [{"custom_signature_set_id": "a", "status": "draft", "action": "LOG"}, {"custom_signature_set_id": "b", "status": "exported", "action": "LOG", "signature_object_name": "waf-demo"}],
        )
        self.assertEqual(summary["binding_state"], "bound")
        self.assertEqual(summary["custom_signature_set_id"], "b")

    def test_positive_compile_observe_only(self):
        preview = compile_observe_only_preview({
            "hostname": "app.test",
            "model_id": "m1",
            "endpoints": [{"method": "GET", "path_template": "/products/{id}", "fields": [{"name": "id", "location": "path", "proposed_constraints": {"requiredness": "required", "value_type": "integer"}}]}],
        }, candidate_id="c1", status="accepted")
        self.assertEqual(preview["enforcement_mode"], "observe")
        self.assertFalse(preview["positive_model_enabled"])
        self.assertEqual(preview["endpoint_count"], 1)
        rows = structured_endpoint_editor_payload({"endpoints": preview["endpoints"]})
        self.assertEqual(rows[0]["path_template"], "/products/{id}")


if __name__ == "__main__":
    unittest.main()
