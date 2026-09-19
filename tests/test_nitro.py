import unittest
from unittest import mock

from app.netscaler.nitro import NitroClient, NitroError
from app.netscaler.mcp import NetScalerMcpClient


class NitroTests(unittest.TestCase):
    def test_arbitrary_resource_is_rejected(self):
        client = object.__new__(NitroClient)
        with self.assertRaises(ValueError):
            client.get("systemuser")

    def test_missing_credentials_are_rejected(self):
        with mock.patch.dict("os.environ", {"NS_LOGIN": "", "NS_PASSWORD": ""}, clear=False):
            with self.assertRaises(NitroError):
                NitroClient()

    def test_mcp_client_rejects_mutating_or_arbitrary_tools(self):
        client = NetScalerMcpClient()
        with self.assertRaises(ValueError):
            client.call_tool("netscaler_apply_change")

    def test_mcp_client_has_14_1_scope_guard(self):
        self.assertTrue(hasattr(NetScalerMcpClient, "connect_14_1"))


if __name__ == "__main__":
    unittest.main()
