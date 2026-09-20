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
    for block in _profile_blocks(text):
        name = _value(block, r"^\s*Name:\s*(.+)$")
        if name:
            records.append({
                "name": name[:200],
                "rule": _value(block, r"^\s*Rule:\s*(.+)$"),
                "profilename": _value(block, r"^\s*ProfileName:\s*(.+)$"),
                "logaction": _value(block, r"^\s*LogAction:\s*(.+)$"),
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


def build_waf_inventory(outputs: dict[str, str]) -> dict[str, Any]:
    feature = parse_feature(outputs.get("show ns feature", ""))
    feature_enabled = feature.get("enabled") is True
    profiles = parse_profiles(outputs.get("show appfw profile", ""))
    policies = parse_policies(outputs.get("show appfw policy", ""), feature.get("enabled"))
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
        "automatic_apply_allowed": False,
        "writes": {"enabled": False, "reason": "CLI inventory integration is read-only; WAF writes remain separately guarded."},
    }
