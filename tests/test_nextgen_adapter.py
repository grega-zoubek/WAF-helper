import importlib.util
import sys
import unittest
from pathlib import Path


adapter_root = Path(__file__).parents[1] / "services" / "netscaler-adapter"
sys.path.insert(0, str(adapter_root))

spec = importlib.util.spec_from_file_location(
    "adapter_nextgen",
    adapter_root / "app" / "nextgen.py",
)
assert spec is not None and spec.loader is not None
nextgen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nextgen)


class NextGenAdapterTests(unittest.TestCase):
    def test_base_url_uses_nextgen_contract(self):
        previous = dict(nextgen.os.environ)
        try:
            nextgen.os.environ.pop("NETSCALER_NEXTGEN_BASE_URL", None)
            nextgen.os.environ["NETSCALER_NEXTGEN_SCHEME"] = "https"
            self.assertEqual(
                nextgen.base_url("192.0.2.10"),
                "https://192.0.2.10/mgmt/api/nextgen/v1",
            )
        finally:
            nextgen.os.environ.clear()
            nextgen.os.environ.update(previous)

    def test_topology_normalization_is_provider_neutral(self):
        payload = {
            "applications": [
                {
                    "name": "juice-shop",
                    "virtual_ip": "192.0.2.20",
                    "port": 80,
                    "protocol": "HTTP",
                    "servers_port": 3000,
                    "servers": ["192.0.2.30"],
                }
            ]
        }
        topology = nextgen.topology_payload(payload)
        self.assertEqual(topology["provider"], "netscaler-nextgen")
        self.assertEqual(topology["lbvserver"][0]["ipv46"], "192.0.2.20")
        self.assertEqual(topology["service"][0]["port"], 3000)

    def test_appfw_is_explicitly_unsupported(self):
        result = nextgen.unsupported_appfw("appfwprofile")
        self.assertEqual(result["status"], "unsupported-by-oas")
        self.assertFalse(result["automatic_apply_allowed"])


if __name__ == "__main__":
    unittest.main()
