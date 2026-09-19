import json

from app.netscaler.mcp import NetScalerMcpClient


def main() -> None:
    client = NetScalerMcpClient()
    system_info = client.connect_14_1()
    result = {
        "system_info": system_info,
        "inventory": client.call_tool("netscaler_inventory_summary"),
        "application_discovery": client.call_tool("netscaler_application_discovery"),
    }
    try:
        result["waf_discovery_report"] = client.call_tool("netscaler_waf_discovery_report")
    except Exception as exc:
        result["waf_discovery_report"] = {"status": "unavailable", "reason": str(exc), "read_only": True}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
