import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "netscaler-adapter"))

from app.cli_inventory import build_waf_inventory, parse_profiles, parse_signatures


class CliInventoryTests(unittest.TestCase):
    def test_enabled_inventory_parses_profiles_and_signatures(self):
        outputs = {
            "show ns feature": "18) Application Firewall           AppFw                ON\n",
            "show appfw profile": (
                "1)\tName: APPFW_BYPASS      LogEveryPolicyHit:  OFF\n"
                "5)\tName: ns-web-default-appfw-profile\n"
                "\tType: HTML XML JSON\n"
                "\tSignatures: \" \"\n"
            ),
            "show appfw policy": "show appfw policy\nDone\n",
            "show appfw policylabel": "show appfw policylabel\nDone\n",
            "show appfw signatures": (
                "1) Url: default_signatures.xml Name: \"*Default Signatures\"\n"
                "\tBase Version: \"175\" Size: 2879756 bytes Encrypted Version: \"20\"\n"
                "Total signatures Size: 0 bytes\n"
            ),
            "show appfw settings": "DefaultProfile: APPFW_BYPASS UndefAction: APPFW_BLOCK\nSignatureAutoUpdate: OFF\n",
        }
        result = build_waf_inventory(outputs)
        self.assertEqual(result["status"], "enumerated")
        self.assertEqual(result["feature"]["enabled"], True)
        self.assertEqual([item["name"] for item in result["profiles"]["records"]], ["APPFW_BYPASS", "ns-web-default-appfw-profile"])
        self.assertEqual(result["signatures"]["record_count"], 1)
        self.assertFalse(result["automatic_apply_allowed"])

    def test_disabled_feature_is_not_an_empty_inventory(self):
        result = build_waf_inventory({"show ns feature": "18) Application Firewall AppFw OFF\n"})
        self.assertEqual(result["status"], "feature-disabled")
        self.assertFalse(result["feature"]["enabled"])
        self.assertEqual(result["policies"]["status"], "feature-disabled")

    def test_profile_name_parser_removes_inline_display_fields(self):
        records = parse_profiles("1) Name: APPFW_BLOCK      UseHTMLErrorObject: OFF\n")
        self.assertEqual(records[0]["name"], "APPFW_BLOCK")

    def test_signature_parser_normalizes_metadata(self):
        records = parse_signatures("1) Url: default.xml Name: \"Default\"\n\tBase Version: \"1\" Size: 12 bytes Encrypted Version: \"2\"\nTotal signatures Size: 0 bytes\n")
        self.assertEqual(records[0]["base_version"], "1")
        self.assertEqual(records[0]["size_bytes"], 12)


if __name__ == "__main__":
    unittest.main()
