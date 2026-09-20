from __future__ import annotations

from typing import Any


def _application_items(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    values = payload.get("applications")
    if not isinstance(values, list):
        return []
    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        item = value.get("application") if isinstance(value.get("application"), dict) else value
        result.append(item)
    return result


def correlate_scope_to_nextgen(scope: dict[str, Any], payload: Any) -> dict[str, Any]:
    hostname = str(scope.get("hostname") or "").strip().lower()
    applications = _application_items(payload)
    matches: list[dict[str, Any]] = []
    for application in applications:
        candidates = {
            str(application.get("name") or "").strip().lower(),
            str(application.get("virtual_ip") or "").strip().lower(),
        }
        if hostname and hostname in candidates:
            matches.append({
                "name": application.get("name"),
                "virtual_ip": application.get("virtual_ip"),
                "port": application.get("port"),
                "protocol": application.get("protocol"),
                "configured_state": application.get("configured_state"),
                "match_reason": "exact-name-or-virtual-ip",
            })
    if matches:
        status = "matched"
        blocking_conditions: list[str] = []
    elif not applications:
        status = "empty-inventory"
        blocking_conditions = ["Next-Gen application inventory is empty"]
    else:
        status = "no-match"
        blocking_conditions = ["Discovery hostname did not exactly match a Next-Gen application name or virtual IP"]
    return {
        "provider": "netscaler-nextgen",
        "status": status,
        "target_hostname": hostname,
        "application_count": len(applications),
        "matches": matches,
        "blocking_conditions": blocking_conditions,
        "automatic_apply_allowed": False,
    }
