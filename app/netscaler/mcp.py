import json
import os
from urllib.request import Request, urlopen


READ_ONLY_TOOLS = frozenset({
    "netscaler_system_info", "netscaler_inventory_summary", "netscaler_feature_matrix", "netscaler_cs_topology",
    "netscaler_get_resource", "netscaler_application_discovery", "netscaler_waf_discovery_report",
})


class McpError(RuntimeError):
    pass


class NetScalerMcpClient:
    """Minimal streamable-HTTP MCP client for the existing read-only server."""

    def __init__(self, endpoint: str | None = None):
        self.endpoint = endpoint or os.environ.get("NETSCALER_MCP_ENDPOINT", "http://192.168.11.90:8000/mcp")
        self.session_id = None
        self._next_id = 1

    def _post(self, message: dict, expect_response: bool = True) -> dict | None:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = Request(self.endpoint, data=json.dumps(message).encode(), headers=headers, method="POST")
        try:
            with urlopen(request, timeout=20) as response:
                self.session_id = response.headers.get("Mcp-Session-Id", self.session_id)
                if not expect_response:
                    return None
                body = response.read().decode("utf-8", "replace")
        except Exception as exc:
            raise McpError(f"MCP request failed: {exc}") from exc
        for line in body.splitlines():
            if line.startswith("data: "):
                result = json.loads(line[6:])
                if "error" in result:
                    raise McpError(result["error"].get("message", "MCP error"))
                return result.get("result", result)
        raise McpError("MCP response did not contain a JSON result")

    def initialize(self) -> None:
        self._post({"jsonrpc": "2.0", "id": self._next_id, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "waf-intelligence", "version": "0.1"}}})
        self._next_id += 1
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, expect_response=False)

    def connect_14_1(self) -> dict:
        """Initialize MCP and enforce the product scope required by the WAF plan."""
        self.initialize()
        system_info = self.call_tool("netscaler_system_info")
        version = system_info.get("nsversion", {}).get("version", "")
        if not version.startswith("NetScaler NS14.1:"):
            raise McpError(f"Unsupported NetScaler release: {version or 'unknown'}; only 14.1 is supported")
        return system_info

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        if name not in READ_ONLY_TOOLS:
            raise ValueError(f"Tool is not in the WAF Scanner read-only allow-list: {name}")
        result = self._post({"jsonrpc": "2.0", "id": self._next_id, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}})
        self._next_id += 1
        if result and result.get("isError"):
            detail = next((item.get("text") for item in result.get("content", []) if item.get("type") == "text"), "MCP tool returned an error")
            raise McpError(detail)
        structured = result.get("structuredContent") if isinstance(result, dict) else None
        if structured is not None:
            return structured
        content = result.get("content", []) if isinstance(result, dict) else []
        for item in content:
            if item.get("type") == "text":
                return json.loads(item["text"])
        return result
