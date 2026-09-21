from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _normalize_rules(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("rules", value.get("entries", []))
    if not isinstance(value, list):
        return []
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id", item.get("ruleid", item.get("id")))
        if rule_id is None:
            continue
        key = str(rule_id).strip()
        if not key or key in seen:
            continue
        attack_classes = item.get("attack_classes", item.get("attack_class", []))
        technology_tags = item.get("technology_tags", item.get("technologies", []))
        if isinstance(attack_classes, str):
            attack_classes = [attack_classes]
        if isinstance(technology_tags, str):
            technology_tags = [technology_tags]
        rules.append({
            "rule_id": key,
            "category": str(item.get("category") or "").strip().casefold() or None,
            "attack_classes": sorted({str(v).strip().casefold() for v in attack_classes if v}),
            "technology_tags": sorted({str(v).strip().casefold() for v in technology_tags if v}),
            "description": str(item.get("description") or item.get("name") or "")[:500],
            "action": str(item.get("action") or "LOG").upper(),
            "enabled": bool(item.get("enabled", True)),
            "version": str(item.get("version") or "").strip() or None,
            "severity": str(item.get("severity") or "").strip().casefold() or None,
            "source": str(item.get("source") or "").strip() or None,
            "source_catalog": str(item.get("source_catalog") or "").strip() or None,
            "reference_count": int(item.get("reference_count") or 0),
            "pattern_count": int(item.get("pattern_count") or 0),
            "match_types": sorted({str(v).strip().casefold() for v in (item.get("match_types") or []) if v}),
            "locations": sorted({str(v).strip().casefold() for v in (item.get("locations") or []) if v}),
        })
        seen.add(key)
    return rules


def _split_tokens(value: str) -> list[str]:
    return [token.strip().casefold() for token in re.split(r"[,;|\s]+", value or "") if token.strip()]


def _infer_attack_classes(category: str, description: str, match_types: list[str], locations: list[str]) -> list[str]:
    haystack = " ".join([category, description, " ".join(match_types), " ".join(locations)]).casefold()
    result = set(_split_tokens(category))
    mappings = {
        "sql-injection": ("sql", "sql injection"),
        "cross-site-scripting": ("xss", "cross-site scripting", "crosssitescripting"),
        "xpath-injection": ("xpath",),
        "ldap-injection": ("ldap",),
        "nosql-injection": ("nosql", "mongo", "mongodb"),
        "command-injection": ("command injection", "command-injection", "os command", "os-command"),
        "buffer-overflow": ("buffer overflow", "buffer-overflow"),
        "file-upload": ("file upload", "file-upload", "unrestricted upload"),
        "path-traversal": ("path traversal", "directory traversal", "path-traversal"),
        "xml": ("xml", "soap"),
    }
    for attack_class, needles in mappings.items():
        if any(needle in haystack for needle in needles):
            result.add(attack_class)
    return sorted(result)


def _infer_technology_tags(category: str, description: str) -> list[str]:
    haystack = f"{category} {description}".casefold()
    technologies = (
        "apache", "asp", "asp.net", "coldfusion", "drupal", "exchange", "express", "iis",
        "java", "joomla", "laravel", "microsoft", "nginx", "node", "php", "postgres",
        "tomcat", "wordpress", "owa", "mysql", "oracle", "mongodb", "struts",
    )
    return [technology for technology in technologies if technology in haystack]


def _xml_rules(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rules: list[dict[str, Any]] = []
    for element in root.iter():
        attrs = {str(k).casefold().split("}")[-1]: str(v) for k, v in element.attrib.items()}
        rule_id = attrs.get("ruleid") or attrs.get("rule_id") or attrs.get("id")
        tag = str(element.tag).casefold().split("}")[-1]
        if not rule_id or ("rule" not in tag and "signature" not in tag):
            continue
        def child_text(name: str) -> str:
            for child in element.iter():
                child_tag = str(child.tag).casefold().split("}")[-1]
                if child_tag == name.casefold() and child.text:
                    return " ".join(child.text.split())
            return ""

        description = attrs.get("logstring") or attrs.get("description") or attrs.get("name") or child_text("logstring")
        category = attrs.get("category") or attrs.get("sigcategory") or ""
        matches: list[str] = []
        locations: list[str] = []
        for child in element.iter():
            child_tag = str(child.tag).casefold().split("}")[-1]
            child_attrs = {str(k).casefold().split("}")[-1]: str(v) for k, v in child.attrib.items()}
            if child_tag == "match" and child_attrs.get("type"):
                matches.append(child_attrs["type"])
            if child_tag == "location" and child_attrs.get("area"):
                locations.append(child_attrs["area"])
        references = [
            " ".join(child.text.split())
            for child in element.iter()
            if str(child.tag).casefold().split("}")[-1] == "reference" and child.text and child.text.strip()
        ]
        actions = attrs.get("actions") or attrs.get("action") or "LOG"
        enabled_value = attrs.get("enabled", "true").casefold()
        enabled = enabled_value not in {"false", "off", "0"}
        attack_classes = _infer_attack_classes(category, description, matches, locations)
        technology_tags = _infer_technology_tags(category, description)
        rules.append({
            "rule_id": rule_id,
            "category": category,
            "attack_classes": attack_classes,
            "technology_tags": technology_tags,
            "description": description,
            "action": actions.split(",")[0].strip() or "LOG",
            "enabled": enabled,
            "version": attrs.get("version"),
            "severity": attrs.get("severity"),
            "source": attrs.get("source") or attrs.get("vendor"),
            "reference_count": len(references),
            "pattern_count": len(matches) + len(locations),
            "match_types": matches,
            "locations": locations,
        })
    return _normalize_rules(rules)


def load_rule_catalog(path_value: str) -> dict[str, Any]:
    path_value = path_value.strip()
    if not path_value:
        return {"status": "not-configured", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    path = Path(path_value)
    if not path.is_file():
        return {"status": "configured-file-missing", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    if path.stat().st_size > 64 * 1024 * 1024:
        return {"status": "file-too-large", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    text = path.read_text(encoding="utf-8")
    source_payload: dict[str, Any] = {}
    try:
        source_payload = json.loads(text)
        rules = _normalize_rules(source_payload)
    except json.JSONDecodeError:
        rules = _xml_rules(text)
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), default=str).encode()
    category_counts: dict[str, int] = {}
    attack_class_counts: dict[str, int] = {}
    source_catalog_counts: dict[str, int] = {}
    for rule in rules:
        category = rule.get("category")
        if category:
            category_counts[str(category)] = category_counts.get(str(category), 0) + 1
        for attack_class in rule.get("attack_classes", []):
            attack_class_counts[str(attack_class)] = attack_class_counts.get(str(attack_class), 0) + 1
        source_catalog = rule.get("source_catalog")
        if source_catalog:
            source_catalog_counts[str(source_catalog)] = source_catalog_counts.get(str(source_catalog), 0) + 1
    return {
        "status": "enumerated" if rules else "no-rule-metadata",
        "provider": "netscaler",
        "schema_version": str(source_payload.get("schema_version") or "1.1.0") if isinstance(source_payload, dict) else "1.1.0",
        "catalogs": source_payload.get("catalogs", []) if isinstance(source_payload, dict) else [],
        "rules": rules,
        "rule_count": len(rules),
        "category_counts": dict(sorted(category_counts.items())),
        "attack_class_counts": dict(sorted(attack_class_counts.items())),
        "source_catalog_counts": dict(sorted(source_catalog_counts.items())),
        "catalog_fingerprint": hashlib.sha256(canonical).hexdigest() if rules else None,
        "raw_payload_retained": False,
    }
