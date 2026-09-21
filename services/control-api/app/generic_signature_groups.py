from __future__ import annotations

import re
from typing import Any


"""Provider-neutral grouping for the first signature-only protection phase.

The groups deliberately operate on normalized catalog metadata.  They do not
infer a positive model, create allowlists, or select product-specific rules.
Technology-tagged rules are left to the technology/product selection path.
"""


GENERIC_SIGNATURE_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "group_id": "http-protocol-compliance",
        "name": "HTTP protocol compliance",
        "priority": "P0",
        "rationale": "Malformed or ambiguous HTTP requests are a generic WAF boundary concern.",
    },
    {
        "group_id": "canonicalization-evasion",
        "name": "Canonicalization and evasion",
        "priority": "P0",
        "rationale": "Encoded, obfuscated, and normalization-sensitive input must be evaluated before attack matching.",
    },
    {
        "group_id": "injection",
        "name": "Injection attacks",
        "priority": "P0",
        "rationale": "Generic injection signatures cover SQL, command, LDAP, NoSQL, and related input attack classes.",
    },
    {
        "group_id": "xss",
        "name": "Cross-site scripting",
        "priority": "P0",
        "rationale": "XSS signatures protect reflected and stored input paths across server and client-rendered applications.",
    },
    {
        "group_id": "path-file",
        "name": "Path and file attacks",
        "priority": "P0",
        "rationale": "Traversal, file access, inclusion, and upload signatures protect filesystem-facing request paths.",
    },
)

GROUP_IDS = tuple(item["group_id"] for item in GENERIC_SIGNATURE_GROUPS)

_INJECTION_CLASSES = {
    "sql-injection",
    "command-injection",
    "os-command-injection",
    "ldap-injection",
    "nosql-injection",
    "xpath-injection",
    "template-injection",
    "code-injection",
}
_PATH_CLASSES = {"path-traversal", "file-upload", "local-file-inclusion", "remote-file-inclusion"}
_PROTOCOL_RE = re.compile(
    r"\b(?:http\s+(?:header|request|method)|request\s+(?:method|smuggl|splitt)|"
    r"chunked(?:[- ]encoding)?|content[- ]length|transfer[- ]encoding|malformed|"
    r"invalid\s+method|http\.sys|header\s+(?:injection|overflow)|protocol)\b",
    re.IGNORECASE,
)
_EVASION_RE = re.compile(
    r"\b(?:evasion|obfuscat|encod(?:ed|ing)|unicode|double\s+(?:url\s+)?encod|"
    r"url\s+encod|percent(?:[- ]encod)?|null\s+byte|canonical|mixed\s+case|"
    r"normaliz(?:e|ation))\b",
    re.IGNORECASE,
)
_PATH_RE = re.compile(
    r"\b(?:directory\s+(?:listing|traversal)|path\s+traversal|file\s+(?:upload|inclusion|access)|"
    r"local\s+file|remote\s+file|arbitrary\s+file|include|upload)\b",
    re.IGNORECASE,
)


def _surface_facts(profile: dict[str, Any]) -> dict[str, Any]:
    evidence = profile.get("evidence") or []
    technologies = profile.get("technologies") or []
    return {
        "reachable": bool(profile.get("route_inventory") or profile.get("route_candidates") or evidence or technologies),
        "has_upload": any(
            isinstance(item, dict) and str(item.get("technology") or "").casefold() == "file upload surface"
            for item in evidence
        ),
    }


def _rule_text(rule: dict[str, Any]) -> str:
    return " ".join(
        str(rule.get(field) or "")
        for field in ("category", "description", "source")
    ).casefold()


def match_rule_to_group(group_id: str, rule: dict[str, Any], profile: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return whether an untagged catalog rule belongs to a generic group."""
    if rule.get("technology_tags"):
        return False, []
    classes = {str(value).casefold() for value in (rule.get("attack_classes") or [])}
    text = _rule_text(rule)
    facts = _surface_facts(profile)
    if group_id == "http-protocol-compliance":
        matched = bool(_PROTOCOL_RE.search(text))
        return matched, ["structured HTTP/protocol description"] if matched else []
    if group_id == "canonicalization-evasion":
        matched = bool(_EVASION_RE.search(text))
        # Transfer/chunked encoding is protocol handling, not payload
        # canonicalization. Keep it in the protocol group unless the same
        # description also carries an explicit normalization/evasion cue.
        if matched and re.search(r"\bchunked(?:[- ]encoding)?\b|\btransfer[- ]encoding\b", text, re.IGNORECASE):
            matched = bool(re.search(r"double|url\s+encod|null\s+byte|unicode|obfuscat|canonical|normaliz", text, re.IGNORECASE))
        return matched, ["encoding or normalization description"] if matched else []
    if group_id == "injection":
        matched = bool(classes & _INJECTION_CLASSES)
        return matched, [f"attack class: {value}" for value in sorted(classes & _INJECTION_CLASSES)] if matched else []
    if group_id == "xss":
        matched = "cross-site-scripting" in classes or bool(re.search(r"\bcross[- ]site scripting\b|\bxss\b", text, re.IGNORECASE))
        return matched, ["cross-site scripting attack class"] if matched else []
    if group_id == "path-file":
        class_match = classes & _PATH_CLASSES
        if "file-upload" in class_match and not facts["has_upload"]:
            class_match = class_match - {"file-upload"}
        text_match = bool(_PATH_RE.search(text))
        if "file upload" in text.casefold() and not facts["has_upload"] and not (class_match - {"file-upload"}):
            text_match = False
        matched = bool(class_match or text_match)
        reasons = [f"attack class: {value}" for value in sorted(class_match)]
        if text_match:
            reasons.append("path/file attack description")
        return matched, reasons
    return False, []


def select_generic_signature_groups(
    rules: list[dict[str, Any]],
    profile: dict[str, Any],
    requested_group_ids: list[str] | None = None,
) -> dict[str, Any]:
    requested = {str(value).strip().casefold() for value in requested_group_ids or GROUP_IDS if str(value).strip()}
    requested &= set(GROUP_IDS)
    facts = _surface_facts(profile)
    groups: list[dict[str, Any]] = []
    rule_sources: dict[str, set[str]] = {}
    for definition in GENERIC_SIGNATURE_GROUPS:
        group_id = str(definition["group_id"])
        if group_id not in requested:
            continue
        matches: list[dict[str, Any]] = []
        for rule in rules:
            matched, reasons = match_rule_to_group(group_id, rule, profile)
            if matched:
                rule_id = str(rule.get("rule_id"))
                matches.append({"rule_id": rule_id, "reasons": reasons})
                rule_sources.setdefault(rule_id, set()).add(f"generic:{group_id}")
        confidence = "high" if facts["reachable"] and matches else "low"
        groups.append({
            **definition,
            "decision": "include" if facts["reachable"] else "conditional",
            "applicability_confidence": confidence,
            "evidence": ["reachable application evidence"] if facts["reachable"] else ["reachability evidence required"],
            "rule_count": len(matches),
            "selected_rule_count": len(matches) if facts["reachable"] else 0,
            "rule_ids": [item["rule_id"] for item in matches],
            "rule_matches": matches,
            "provider_mapping": "normalized NetScaler signature catalog",
            "proposal_only": True,
        })
    return {
        "groups": groups,
        "requested_group_ids": sorted(requested),
        "rule_sources": {rule_id: sorted(sources) for rule_id, sources in rule_sources.items()},
        "selected_rule_ids": sorted(rule_sources),
        "selected_rule_count": len(rule_sources),
        "unresolved_group_ids": [item["group_id"] for item in groups if not item["rule_count"]],
        "signature_only": True,
        "positive_model": {"enabled": False, "reason": "deferred to a later phase"},
    }


def _display_label(value: str) -> str:
    return str(value or "other").replace("-", " ").replace("_", " ").title()


def subgroup_for_rule(group_id: str, rule: dict[str, Any]) -> tuple[str, str]:
    """Return a stable, useful expandable subgroup for a generic rule."""
    classes = {str(value).casefold() for value in (rule.get("attack_classes") or [])}
    if group_id == "injection":
        priorities = (
            ("sql-injection", "SQL injection"),
            ("command-injection", "Command injection"),
            ("os-command-injection", "OS command injection"),
            ("ldap-injection", "LDAP injection"),
            ("nosql-injection", "NoSQL injection"),
            ("xpath-injection", "XPath injection"),
            ("template-injection", "Template injection"),
            ("code-injection", "Code injection"),
        )
        for attack_class, label in priorities:
            if attack_class in classes:
                return attack_class, label
        return "other-injection", "Other injection"
    if group_id == "xss":
        category = str(rule.get("category") or "other").casefold()
        return f"catalog:{category}", f"{_display_label(category)} XSS rules"
    if group_id == "path-file":
        priorities = (
            ("path-traversal", "Path traversal"),
            ("file-upload", "File upload"),
            ("local-file-inclusion", "Local file inclusion"),
            ("remote-file-inclusion", "Remote file inclusion"),
        )
        for attack_class, label in priorities:
            if attack_class in classes:
                return attack_class, label
        return "file-access", "File and directory access"
    if group_id == "canonicalization-evasion":
        description = str(rule.get("description") or "").casefold()
        if "null byte" in description:
            return "null-byte", "Null-byte and terminator evasion"
        if "unicode" in description:
            return "unicode", "Unicode normalization evasion"
        if "double" in description or "url encoding" in description:
            return "url-encoding", "URL and double-encoding evasion"
        return "other-evasion", "Other canonicalization/evasion"
    category = str(rule.get("category") or "other").casefold()
    return f"catalog:{category}", _display_label(category)


def build_generic_group_subgroups(
    groups: list[dict[str, Any]],
    rules_by_id: dict[str, dict[str, Any]],
    selected_rule_ids: set[str],
) -> list[dict[str, Any]]:
    """Attach compact subgroup/rule details while preserving deselected rules."""
    for group in groups:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        candidate_ids = [str(value) for value in (group.get("rule_ids") or [])]
        match_reasons = {
            str(item.get("rule_id")): list(item.get("reasons") or [])
            for item in (group.get("rule_matches") or [])
            if isinstance(item, dict)
        }
        for rule_id in candidate_ids:
            rule = rules_by_id.get(rule_id)
            if not rule:
                continue
            subgroup_id, subgroup_label = subgroup_for_rule(str(group.get("group_id")), rule)
            grouped.setdefault((subgroup_id, subgroup_label), []).append({
                "rule_id": rule_id,
                "description": rule.get("description"),
                "category": rule.get("category"),
                "attack_classes": rule.get("attack_classes", []),
                "technology_tags": rule.get("technology_tags", []),
                "locations": rule.get("locations", []),
                "match_types": rule.get("match_types", []),
                "severity": rule.get("severity"),
                "pattern_count": rule.get("pattern_count", 0),
                "selected": rule_id in selected_rule_ids,
                "match_reasons": match_reasons.get(rule_id, []),
            })
        subgroups = []
        for (subgroup_id, subgroup_label), subgroup_rules in sorted(grouped.items(), key=lambda item: item[0][1].casefold()):
            subgroup_rules.sort(key=lambda item: (str(item.get("category") or ""), str(item.get("rule_id") or "")))
            subgroups.append({
                "subgroup_id": subgroup_id,
                "name": subgroup_label,
                "rule_count": len(subgroup_rules),
                "selected_rule_count": sum(1 for item in subgroup_rules if item["selected"]),
                "rules": subgroup_rules,
            })
        group["candidate_rule_count"] = len(candidate_ids)
        group["selected_rule_count"] = sum(1 for rule_id in candidate_ids if rule_id in selected_rule_ids)
        group["selected_rule_ids"] = [rule_id for rule_id in candidate_ids if rule_id in selected_rule_ids]
        group["subgroups"] = subgroups
    return groups
