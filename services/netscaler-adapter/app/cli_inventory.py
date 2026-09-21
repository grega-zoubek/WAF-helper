"""Sanitized parsers for the read-only NetScaler AppFW CLI inventory."""

from __future__ import annotations

import re
from typing import Any


PROFILE_ACTION_FIELDS = (
    "StartURLAction",
    "DenyURLAction",
    "CookieConsistencyAction",
    "CSRFtagAction",
    "FieldConsistencyAction",
    "FileUploadTypesAction",
    "CmdInjectionAction",
    "CrossSiteScriptingAction",
    "SQLInjectionAction",
    "BufferOverflowAction",
    "JSONDoSAction",
    "JSONSQLInjectionAction",
    "JSONXSSAction",
    "XMLDoSAction",
    "XMLValidationAction",
    "REST Action",
    "gRPC Action",
    "PostBodyLimitAction",
)


ENDPOINT_HEADER = re.compile(
    r"^\s*(?:(?P<index>\d+)\)\s*)?(?P<name>[A-Za-z0-9_.-]+)\s+"
    r"\((?P<host>[^():\s]+):\s*(?P<port>\d+)\)\s+-\s*(?P<protocol>[A-Za-z0-9_-]+)"
)


def _value(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    value = match.group(1).strip().strip('"')
    return value or None


def parse_feature(text: str) -> dict[str, Any]:
    match = re.search(r"(?im)^\s*\d+\)\s*Application Firewall\s+AppFw\s+(ON|OFF)\s*$", text)
    if not match:
        return {
            "status": "not-reported",
            "enabled": None,
            "reason": "The CLI feature output did not contain an AppFw state line.",
        }
    enabled = match.group(1).upper() == "ON"
    return {
        "status": "enabled" if enabled else "disabled",
        "enabled": enabled,
        "reason": "AppFw feature is enabled." if enabled else "AppFw feature is disabled on the ADC.",
    }


def _profile_blocks(text: str) -> list[str]:
    matches = list(re.finditer(r"(?m)^\s*\d+\)\s*Name:\s*.*$", text))
    return [text[matches[index].start() : matches[index + 1].start() if index + 1 < len(matches) else len(text)] for index in range(len(matches))]


def parse_profiles(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for block in _profile_blocks(text):
        name_line = next((line for line in block.splitlines() if re.search(r"Name:", line, re.IGNORECASE)), "")
        name = re.sub(r"^.*?Name:\s*", "", name_line, flags=re.IGNORECASE).strip()
        name = re.split(r"\s{2,}(?:LogEveryPolicyHit|UseHTMLErrorObject):", name, maxsplit=1, flags=re.IGNORECASE)[0].strip().strip('"')
        if not name or name in seen:
            continue
        seen.add(name)
        actions: dict[str, str] = {}
        for field in PROFILE_ACTION_FIELDS:
            value = _value(block, rf"^\s*{re.escape(field)}:\s*(.+)$")
            if value is not None:
                actions[field] = value
        records.append({
            "name": name[:200],
            "type": _value(block, r"^\s*Type:\s*(.+)$"),
            "state": _value(block, r"^\s*State:\s*(.+)$"),
            "signatures": _value(block, r"^\s*Signatures:\s*(.+)$"),
            "builtin": name.upper() in {"APPFW_BYPASS", "APPFW_RESET", "APPFW_DROP", "APPFW_BLOCK"} or name.startswith("ns-"),
            "actions": actions,
        })
    return records


def parse_signatures(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    pattern = re.compile(
        r"(?ms)^\s*\d+\)\s*Url:\s*(?P<url>\S+)\s+Name:\s*\"(?P<name>[^\"]+)\"(?P<body>.*?)(?=^\s*\d+\)\s*Url:|^\s*Total signatures Size:)"
    )
    for match in pattern.finditer(text):
        body = match.group("body")
        records.append({
            "url": match.group("url")[:300],
            "name": match.group("name")[:200],
            "creation_date": _value(body, r"^\s*Creation Date:\s*(.+)$"),
            "base_version": _value(body, r"^\s*Base Version:\s*\"?([^\"\s]+)"),
            "size_bytes": int(size.group(1)) if (size := re.search(r"\bSize:\s*(\d+)\s+bytes", body)) else None,
            "encrypted_version": _value(body, r"\bEncrypted Version:\s*\"?([^\"\s]+)"),
        })
    return records


def parse_policies(text: str, feature_enabled: bool | None) -> list[dict[str, Any]]:
    if feature_enabled is not True or "Feature(s) not enabled [AppFw]" in text:
        return []
    records: list[dict[str, Any]] = []
    blocks = _profile_blocks(text)
    if not blocks and re.search(r"(?m)^\s*Name:\s*", text):
        blocks = [text]
    for block in blocks:
        name = _value(block, r"^\s*Name:\s*(.+)$")
        if name:
            records.append({
                "name": name[:200],
                "rule": _value(block, r"^\s*Rule:\s*(.+)$"),
                "profilename": _value(block, r"^\s*(?:ProfileName|Profile):\s*(.+)$"),
                "logaction": _value(block, r"^\s*LogAction:\s*(.+)$"),
                "bound_vservers": re.findall(r"Bound to:\s+(?:REQ|RESP)\s+VSERVER\s+([A-Za-z0-9_.-]+)", block, flags=re.IGNORECASE),
                "priority": _value(block, r"^\s*Priority:\s*(\d+)$"),
            })
    return records


def parse_settings(text: str) -> dict[str, Any]:
    return {
        "default_profile": _value(text, r"DefaultProfile:\s*([^\s]+)"),
        "undef_action": _value(text, r"UndefAction:\s*([^\s]+)"),
        "signature_auto_update": _value(text, r"SignatureAutoUpdate:\s*([^\s]+)"),
        "malformed_request_action": _value(text, r"MalformedReqAction:\s*(.+?)\s+Learning:"),
        "learning": _value(text, r"Learning:\s*([^\s]+)"),
        "centralized_learning": _value(text, r"CentralizedLearning:\s*([^\s]+)"),
    }


def _endpoint_record(match: re.Match[str]) -> dict[str, Any]:
    return {
        "name": match.group("name"),
        "host": match.group("host"),
        "port": int(match.group("port")),
        "protocol": match.group("protocol").upper(),
    }


SENSITIVE_PARAMETER_TERMS = ("password", "secret", "token", "private key", "certificate key")


def _parameter_map(text: str) -> dict[str, str]:
    parameters: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*(?P<key>[^:\r\n]{1,96}):\s*(?P<value>.*?)\s*$", line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group("key")).strip()
        value = match.group("value").strip().strip('"')
        normalized = key.lower()
        if (
            not key
            or not value
            or re.match(r"^\d+\)", key)
            or "(" in key
            or ")" in key
            or " - " in key
            or "was at" in normalized
            or any(term in normalized for term in SENSITIVE_PARAMETER_TERMS)
        ):
            continue
        parameters[key[:96]] = value[:300]
    return parameters


def parse_virtual_servers(text: str, vserver_type: str = "lb") -> list[dict[str, Any]]:
    """Parse a typed ``show * vserver`` summary into searchable metadata."""
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = ENDPOINT_HEADER.match(line)
        if match and match.group("index") is not None:
            record = _endpoint_record(match)
            current = {
                **record,
                "vserver_type": vserver_type,
                "state": None,
                "effective_state": None,
                "bound_service_count": None,
                "parameters": {},
            }
            records.append(current)
            continue
        if current is None:
            continue
        current["parameters"].update(_parameter_map(line))
        state = re.search(r"^\s*State:\s*(\S+)", line, re.IGNORECASE)
        if state:
            current["state"] = state.group(1).strip()
        effective = re.search(r"^\s*Effective State:\s*(\S+)", line, re.IGNORECASE)
        if effective:
            current["effective_state"] = effective.group(1).strip()
        bound = re.search(r"No\. of Bound Services:\s*(\d+)\s*\(Total\).*?(\d+)\s*\(Active\)", line, re.IGNORECASE)
        if bound:
            current["bound_service_count"] = {"total": int(bound.group(1)), "active": int(bound.group(2))}
    return records


def parse_lb_vservers(text: str) -> list[dict[str, Any]]:
    return parse_virtual_servers(text, "lb")


def parse_virtual_server_detail(text: str, vserver_type: str = "lb") -> dict[str, Any] | None:
    """Parse one vserver detail response without retaining raw CLI text."""
    matches = [match for match in (ENDPOINT_HEADER.match(line) for line in text.splitlines()) if match]
    if not matches:
        return None
    vserver = {**_endpoint_record(matches[0]), "vserver_type": vserver_type, "parameters": _parameter_map(text)}
    bindings = [_endpoint_record(match) for match in matches[1:]]
    appfw_profile = _value(text, r"^\s*(?:AppFW|AppFw|AppFW Profile|AppFw Profile)\s*(?:Profile)?\s*:\s*(.+)$")
    state = _value(text, r"^\s*State:\s*(\S+)")
    effective_state = _value(text, r"^\s*Effective State:\s*(\S+)")
    return {
        "vserver": {**vserver, "state": state, "effective_state": effective_state},
        "bound_services": bindings,
        "appfw_profile": appfw_profile,
    }


def parse_lb_vserver_detail(text: str) -> dict[str, Any] | None:
    return parse_virtual_server_detail(text, "lb")


def parse_services(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = ENDPOINT_HEADER.match(line)
        if not match or match.group("index") is None:
            continue
        record = _endpoint_record(match)
        records.append({**record, "state": _value(line, r"State:\s*(.+)$"), "server_name": None})
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = ENDPOINT_HEADER.match(line)
        if match and match.group("index") is not None:
            current = next((item for item in reversed(records) if item["name"] == match.group("name")), None)
            continue
        if current is not None:
            state = re.search(r"^\s*State:\s*(.+?)\s*$", line, re.IGNORECASE)
            if state:
                current["state"] = state.group(1).strip()
            server = re.search(r"^\s*Server Name:\s*(.+?)\s*$", line, re.IGNORECASE)
            if server:
                current["server_name"] = server.group(1).strip()
    return records


def parse_servicegroups(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    pattern = re.compile(r"^\s*(?P<index>\d+)\)\s*(?P<name>[A-Za-z0-9_.-]+)\s+-\s*(?P<protocol>[A-Za-z0-9_-]+)")
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            current = {
                "name": match.group("name"),
                "protocol": match.group("protocol").upper(),
                "state": None,
                "effective_state": None,
                "members": [],
            }
            records.append(current)
            continue
        if current is None:
            continue
        state = re.search(r"^\s*State:\s*(\S+)(?:\s+Effective State:\s*(\S+))?", line, re.IGNORECASE)
        if state:
            current["state"] = state.group(1)
            current["effective_state"] = state.group(2)
        member = re.search(r"^\s*\d+\)\s+(?P<host>[^:\s]+):(?P<port>\d+)\s+State:\s*(?P<state>\S+).*?Server Name:\s*(?P<server>\S+)", line, re.IGNORECASE)
        if member:
            current["members"].append({
                "host": member.group("host"),
                "port": int(member.group("port")),
                "state": member.group("state"),
                "server_name": member.group("server"),
            })
    return records


def build_classic_inventory(outputs: dict[str, str]) -> dict[str, Any]:
    source_specs = {
        "lb": ("show lb vserver", "show lb vserver"),
        "cs": ("show cs vserver", "show cs vserver"),
        "gw": ("show vpn vserver", "show vpn vserver"),
    }
    typed_vservers: dict[str, list[dict[str, Any]]] = {key: parse_virtual_servers(outputs.get(summary, ""), key) for key, (summary, _) in source_specs.items()}
    details: dict[str, Any] = {}
    for key, text in outputs.items():
        for vserver_type, (_, prefix) in source_specs.items():
            if key.startswith(prefix + " "):
                parsed = parse_virtual_server_detail(text, vserver_type)
                if parsed:
                    details[f"{vserver_type}:{parsed['vserver']['name']}"] = parsed
    for vserver_type, records in typed_vservers.items():
        for vserver in records:
            detail = details.get(f"{vserver_type}:{vserver['name']}")
            if detail:
                vserver["bound_services"] = detail["bound_services"]
                vserver["appfw_profile"] = detail["appfw_profile"]
                vserver["state"] = detail["vserver"].get("state") or vserver.get("state")
                vserver["effective_state"] = detail["vserver"].get("effective_state") or vserver.get("effective_state")
                vserver["parameters"].update(detail["vserver"].get("parameters", {}))
            else:
                vserver["bound_services"] = []
                vserver["appfw_profile"] = None
    vservers = [item for group in typed_vservers.values() for item in group]
    services = parse_services(outputs.get("show service", ""))
    servicegroups = parse_servicegroups(outputs.get("show servicegroup", ""))
    status = "enumerated" if vservers or services or servicegroups else "empty"
    bindings = [{"vserver": item["name"], "vserver_type": item.get("vserver_type", "lb"), "service": service["name"], "service_host": service["host"], "service_port": service["port"], "service_protocol": service["protocol"], "appfw_profile": item.get("appfw_profile")} for item in vservers for service in item.get("bound_services", [])]
    return {
        "provider": "netscaler-cli-over-ssh",
        "status": status,
        "vservers": {"status": status, "record_count": len(vservers), "records": vservers},
        "vservers_by_type": {key: {"status": status, "record_count": len(records), "records": records} for key, records in typed_vservers.items()} | {"global": {"status": status, "record_count": len(vservers), "records": vservers}},
        "services": {"status": status, "record_count": len(services), "records": services},
        "servicegroups": {"status": status, "record_count": len(servicegroups), "records": servicegroups},
        "bindings": {"status": status, "record_count": len(bindings), "records": bindings},
        "automatic_apply_allowed": False,
    }


def build_waf_inventory(outputs: dict[str, str]) -> dict[str, Any]:
    feature = parse_feature(outputs.get("show ns feature", ""))
    feature_enabled = feature.get("enabled") is True
    profiles = parse_profiles(outputs.get("show appfw profile", ""))
    policies = parse_policies(outputs.get("show appfw policy", ""), feature.get("enabled"))
    for policy in policies:
        name = str(policy.get("name", ""))
        detail = parse_policies(outputs.get(f"show appfw policy {name}", ""), feature.get("enabled"))
        if detail:
            policy.update(detail[0])
    policy_labels = parse_policies(outputs.get("show appfw policylabel", ""), feature.get("enabled"))
    signatures = parse_signatures(outputs.get("show appfw signatures", ""))
    status = "enumerated" if feature_enabled else "feature-disabled" if feature.get("enabled") is False else "not-reported"
    return {
        "provider": "netscaler-cli-over-ssh",
        "status": status,
        "feature": feature,
        "profiles": {"status": status, "record_count": len(profiles), "records": profiles},
        "policies": {"status": status, "record_count": len(policies), "records": policies},
        "policy_labels": {"status": status, "record_count": len(policy_labels), "records": policy_labels},
        "signatures": {"status": status, "record_count": len(signatures), "records": signatures},
        "settings": parse_settings(outputs.get("show appfw settings", "")),
        "classic": build_classic_inventory(outputs),
        "automatic_apply_allowed": False,
        "writes": {"enabled": False, "reason": "CLI inventory integration is read-only; WAF writes remain separately guarded."},
    }
