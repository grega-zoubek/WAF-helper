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
        })
        seen.add(key)
    return rules


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
        attack_value = attrs.get("attackclass") or attrs.get("attack_class") or attrs.get("type") or ""
        rules.append({
            "rule_id": rule_id,
            "category": attrs.get("category") or attrs.get("sigcategory"),
            "attack_classes": [value for value in re.split(r"[,;| ]+", attack_value) if value],
            "technology_tags": [value for value in re.split(r"[,;| ]+", attrs.get("technology") or attrs.get("technologytag") or "") if value],
            "description": attrs.get("name") or attrs.get("description") or "",
            "action": attrs.get("action", "LOG"),
            "enabled": attrs.get("enabled", "true").casefold() not in {"false", "off", "0"},
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
    try:
        rules = _normalize_rules(json.loads(text))
    except json.JSONDecodeError:
        rules = _xml_rules(text)
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), default=str).encode()
    return {
        "status": "enumerated" if rules else "no-rule-metadata",
        "provider": "netscaler",
        "rules": rules,
        "rule_count": len(rules),
        "catalog_fingerprint": hashlib.sha256(canonical).hexdigest() if rules else None,
        "raw_payload_retained": False,
    }
