from __future__ import annotations

import hashlib
import json
from typing import Any


RULE_CATALOG_SCHEMA_VERSION = "1.1.0"


INTENT_ATTACK_CLASSES: dict[str, set[str]] = {
    "generic-web-attack-signatures": {"buffer-overflow", "command-injection", "cross-site-scripting", "sql-injection"},
    "injection-and-input-signatures": {"command-injection", "ldap-injection", "nosql-injection", "os-command-injection", "sql-injection"},
    "cross-site-scripting-signatures": {"cross-site-scripting"},
    "file-upload-protection": {"file-upload", "web-misc"},
    "xml-service-protection": {"xml", "xml-dos", "xpath-injection"},
}


def catalog_fingerprint(rules: list[dict[str, Any]]) -> str:
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def normalize_rule_catalog(catalog: Any) -> list[dict[str, Any]]:
    """Normalize provider-exported rule metadata without retaining raw payloads."""
    if isinstance(catalog, dict):
        catalog = catalog.get("rules", catalog.get("entries", []))
    if not isinstance(catalog, list):
        return []
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in catalog:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id", item.get("ruleid", item.get("id")))
        if rule_id is None:
            continue
        key = str(rule_id).strip()
        if not key or key in seen:
            continue
        attack_classes = item.get("attack_classes", item.get("attack_class", []))
        if isinstance(attack_classes, str):
            attack_classes = [attack_classes]
        technology_tags = item.get("technology_tags", item.get("technologies", []))
        if isinstance(technology_tags, str):
            technology_tags = [technology_tags]
        locations = item.get("locations", item.get("location", []))
        if isinstance(locations, str):
            locations = [locations]
        normalized.append({
            "rule_id": key,
            "category": str(item.get("category") or "").strip().casefold() or None,
            "attack_classes": sorted({str(value).strip().casefold() for value in attack_classes if value}),
            "technology_tags": sorted({str(value).strip().casefold() for value in technology_tags if value}),
            "description": str(item.get("description") or item.get("name") or "")[:500],
            "action": str(item.get("action") or "LOG").upper(),
            "enabled": bool(item.get("enabled", True)),
            "locations": sorted({str(value).strip().casefold() for value in locations if value}),
            "severity": str(item.get("severity") or "").strip().casefold() or None,
            "version": str(item.get("version") or "").strip() or None,
            "released_year": str(item.get("released_year", item.get("year")) or "").strip() or None,
            "source": str(item.get("source") or "").strip() or None,
            "match_types": sorted({str(value).strip().casefold() for value in (item.get("match_types") or [])} if isinstance(item.get("match_types"), list) else {value.strip().casefold() for value in str(item.get("match_types") or "").split() if value.strip()}),
            "reference_count": int(item.get("reference_count") or 0),
            "pattern_count": int(item.get("pattern_count") or 0),
        })
        seen.add(key)
    return normalized


def resolve_rule_catalog(intents: list[dict[str, Any]], catalog: Any, *, provider: str = "netscaler") -> dict[str, Any]:
    rules = normalize_rule_catalog(catalog)
    included = [item for item in intents if item.get("decision") == "include"]
    if not rules:
        return {
            "status": "blocked-missing-rule-level-catalog",
            "provider": provider,
            "schema_version": RULE_CATALOG_SCHEMA_VERSION,
            "catalog_fingerprint": None,
            "selected_rules": [],
            "unresolved_intents": [str(item.get("intent_id")) for item in included],
            "conditional_intents": [str(item.get("intent_id")) for item in intents if item.get("decision") == "conditional"],
            "automatic_apply_allowed": False,
            "reason": "The provider returned catalog files but no normalized rule-level metadata.",
        }

    selected: list[dict[str, Any]] = []
    resolved: set[str] = set()
    for intent in included:
        intent_id = str(intent.get("intent_id") or "")
        attack_classes = INTENT_ATTACK_CLASSES.get(intent_id, set())
        matches = [
            rule for rule in rules
            if attack_classes & set(rule.get("attack_classes", []))
            or intent_id in set(rule.get("technology_tags", []))
        ]
        for rule in matches:
            selected.append({"rule_id": rule["rule_id"], "intent_id": intent_id, "category": rule.get("category"), "description": rule.get("description"), "action": "LOG", "source": "predefined-policy"})
        if matches:
            resolved.add(intent_id)

    unresolved = [str(item.get("intent_id")) for item in included if str(item.get("intent_id")) not in resolved]
    deduped: list[dict[str, Any]] = []
    seen_rules: set[tuple[str, str]] = set()
    for item in selected:
        key = (item["rule_id"], item["intent_id"])
        if key not in seen_rules:
            seen_rules.add(key)
            deduped.append(item)
    return {
        "status": "resolved" if not unresolved else "partial-resolution",
        "provider": provider,
        "schema_version": RULE_CATALOG_SCHEMA_VERSION,
        "catalog_fingerprint": catalog_fingerprint(rules),
        "rule_count": len(rules),
        "selected_rules": deduped,
        "unresolved_intents": unresolved,
        "conditional_intents": [str(item.get("intent_id")) for item in intents if item.get("decision") == "conditional"],
        "automatic_apply_allowed": False,
        "reason": "Rules are selected by predefined intent mappings; unresolved or conditional intents remain non-applicable until evidence is added.",
    }
