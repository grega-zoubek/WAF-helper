import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.classic_correlation import correlate_scope_to_classic


class ClassicCorrelationTests(unittest.TestCase):
    def test_exact_vserver_match_returns_proposal_only(self):
        result = correlate_scope_to_classic(
            {"hostname": "192.168.11.91", "seed_url": "http://192.168.11.91/"},
            {
                "classic": {
                    "vservers": {"records": [{
                        "name": "lb_vs_juice_shop", "host": "192.168.11.91", "port": 80,
                        "bound_services": [{"name": "juice", "host": "192.168.11.90", "port": 3000, "protocol": "HTTP"}],
                    }]},
                    "services": {"records": []},
                },
                "waf": {
                    "feature": {"enabled": True},
                    "profiles": {"records": [{"name": "ns-web-default-appfw-profile"}]},
                    "policies": {"records": []},
                    "signatures": {"records": [{"name": "*Default Signatures"}]},
                },
            },
        )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["protection_status"], "feature-enabled-no-policy-binding-evidenced")
        self.assertEqual(result["proposal"]["status"], "proposal-only")
        self.assertFalse(result["automatic_apply_allowed"])

    def test_empty_classic_inventory_blocks(self):
        result = correlate_scope_to_classic({"hostname": "192.168.11.91", "seed_url": "http://192.168.11.91/"}, {"classic": {"vservers": {"records": []}, "services": {"records": []}}})
        self.assertEqual(result["status"], "empty-inventory")
        self.assertFalse(result["automatic_apply_allowed"])


if __name__ == "__main__":
    unittest.main()
