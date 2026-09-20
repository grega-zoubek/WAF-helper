import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.nextgen_correlation import correlate_scope_to_nextgen


class NextGenCorrelationTests(unittest.TestCase):
    def test_empty_inventory_is_blocked(self):
        result = correlate_scope_to_nextgen({"hostname": "192.168.11.91"}, {"applications": []})
        self.assertEqual(result["status"], "empty-inventory")
        self.assertFalse(result["automatic_apply_allowed"])

    def test_exact_virtual_ip_match(self):
        result = correlate_scope_to_nextgen(
            {"hostname": "192.168.11.91"},
            {"applications": [{"name": "juice-shop", "virtual_ip": "192.168.11.91", "port": 80, "protocol": "HTTP"}]},
        )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["matches"][0]["name"], "juice-shop")


if __name__ == "__main__":
    unittest.main()
