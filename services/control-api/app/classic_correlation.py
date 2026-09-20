from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


def _target(scope: dict[str, Any]) -> tuple[str, int | None]:
    hostname = str(scope.get("hostname") or "").strip().lower().strip("[]")
    port = scope.get("port")
    if not port and scope.get("seed_url"):
        parsed = urlparse(str(scope["seed_url"]))
        hostname = (parsed.hostname or hostname).lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        normalized_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        normalized_port = None
    return hostname, normalized_port


def _records(payload: Any, section: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    value = payload.get(section, {})
    if not isinstance(value, dict):
        return []
    rows = value.get("records", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _proposal(vserver: dict[str, Any], waf: dict[str, Any], profile: dict[str, Any] | None, signatures: list[dict[str, Any]]) -> dict[str, Any]:
    source_name = str((profile or {}).get("name") or "")
    if not source_name:
        source_name = "ns-web-default-appfw-profile" if any(item.get("name") == "ns-web-default-appfw-profile" for item in _records(waf, "profiles")) else "administrator-selected-web-profile"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(vserver.get("name") or "target")).strip("-")[:72] or "target"
    proposed_name = f"waf-scan-{safe_name}-lab"[:120]
    return {
        "status": "proposal-only",
        "automatic_apply_allowed": False,
        "target_vserver": vserver.get("name"),
        "source_profile": source_name,
        "proposed_custom_profile": proposed_name,
        "signature_catalog_candidates": [item.get("name") for item in signatures if item.get("name")],
        "initial_enforcement_mode": "log-first",
        "recommended_sequence": [
            "clone a suitable built-in web profile into a custom profile; never modify a built-in profile",
            "select a current default signature catalog and keep the first validation pass in log mode",
            "create and bind a policy only after approval, preflight, and a fresh topology fingerprint",
            "exercise benign and negative test traffic, then promote individual protections to block",
        ],
        "blocking_conditions": [
            "No automatic ADC write is permitted by this proposal",
            "Exact profile settings and policy expression still require an approved change plan",
        ],
    }


def correlate_scope_to_classic(scope: dict[str, Any], payload: Any) -> dict[str, Any]:
    hostname, port = _target(scope)
    classic = payload.get("classic", payload) if isinstance(payload, dict) else {}
    if not isinstance(classic, dict):
        classic = {}
    vservers = _records(classic, "vservers")
    services = _records(classic, "services")
    waf = payload.get("waf", {}) if isinstance(payload, dict) and isinstance(payload.get("waf"), dict) else {}
    matches: list[dict[str, Any]] = []
    for vserver in vservers:
        if str(vserver.get("host") or "").strip().lower() == hostname and (port is None or int(vserver.get("port", -1)) == port):
            matches.append({
                "vserver": vserver,
                "match_reason": "exact-vserver-address",
            })
        for service in vserver.get("bound_services", []) if isinstance(vserver.get("bound_services"), list) else []:
            if str(service.get("host") or "").strip().lower() == hostname and (port is None or int(service.get("port", -1)) == port):
                matches.append({
                    "vserver": vserver,
                    "match_reason": "exact-bound-service-address",
                    "matched_service": service,
                })
    if not matches:
        service_names = {str(item.get("name")) for item in services}
        if service_names:
            # A service can be enumerated even when the vserver detail query
            # was incomplete. Report it as a backend-only match, never as a
            # complete protected application path.
            for service in services:
                if str(service.get("host") or "").strip().lower() == hostname and (port is None or int(service.get("port", -1)) == port):
                    matches.append({"vserver": None, "matched_service": service, "match_reason": "exact-service-address"})
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (str((match.get("vserver") or {}).get("name") or ""), str(match.get("match_reason")))
        if key not in seen:
            seen.add(key)
            unique.append(match)
    if not vservers and not services:
        status = "empty-inventory"
        blocking = ["Classic ADC load-balancing inventory is empty"]
    elif len(unique) == 1 and unique[0].get("vserver"):
        status = "matched"
        blocking = []
    elif len(unique) > 1:
        status = "ambiguous"
        blocking = ["Target matched more than one classic ADC path"]
    elif unique:
        status = "backend-only-match"
        blocking = ["Only a backend service matched; the frontend vserver ownership is not proven"]
    else:
        status = "no-match"
        blocking = ["Discovery target did not exactly match a classic ADC vserver or service"]
    profile_records = _records(waf, "profiles")
    signature_records = _records(waf, "signatures")
    policies = _records(waf, "policies")
    vserver = unique[0].get("vserver") if len(unique) == 1 else None
    selected_profile = next((item for item in profile_records if item.get("name") == "ns-web-default-appfw-profile"), None)
    protection_status = "no-policy-binding-evidenced"
    if vserver and vserver.get("appfw_profile"):
        protection_status = "vserver-profile-binding-evidenced"
    elif policies:
        protection_status = "policies-exist-binding-not-correlated"
    elif isinstance(waf.get("feature"), dict) and waf["feature"].get("enabled") is True:
        protection_status = "feature-enabled-no-policy-binding-evidenced"
    proposal = _proposal(vserver, waf, selected_profile, signature_records) if status == "matched" and vserver else {
        "status": "blocked",
        "automatic_apply_allowed": False,
        "blocking_conditions": blocking or ["Target ownership is not proven"],
    }
    return {
        "provider": "netscaler-cli-over-ssh",
        "status": status,
        "target": {"hostname": hostname, "port": port},
        "classic_vserver_count": len(vservers),
        "classic_service_count": len(services),
        "matches": unique,
        "protection_status": protection_status,
        "appfw_policy_count": len(policies),
        "proposal": proposal,
        "blocking_conditions": blocking,
        "automatic_apply_allowed": False,
    }
