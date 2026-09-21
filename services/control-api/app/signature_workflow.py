from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from app.rule_catalog import catalog_fingerprint, normalize_rule_catalog, resolve_rule_catalog


DEFAULT_UPSTREAM_INDEX_FILE = "/run/upstream-signatures/latest.json"
OBJECT_NAME_RE = re.compile(r"[A-Za-z0-9_.# @=-]{1,31}")
ACTION_VALUES = {"LOG", "BLOCK"}


def default_object_name(hostname: str, job_id: str) -> str:
    value = re.sub(r"[^a-z0-9-]+", "-", str(hostname or "app").casefold()).strip("-") or "app"
    suffix = re.sub(r"[^a-z0-9]+", "", str(job_id or "job").casefold())[:8] or "job"
    return f"waf-{value}-{suffix}"[:31]


def load_upstream_catalog(path_value: str | None = None) -> dict[str, Any]:
    path = Path(path_value or os.getenv("SIGNATURE_UPSTREAM_INDEX_FILE", DEFAULT_UPSTREAM_INDEX_FILE))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "missing", "path": str(path), "rules": []}
    except (OSError, json.JSONDecodeError):
        return {"status": "invalid", "path": str(path), "rules": []}
    if not isinstance(value, dict) or not isinstance(value.get("rules"), list):
        return {"status": "invalid", "path": str(path), "rules": []}
    return {**value, "status": "ready", "path": str(path)}


def _technology_tags(profile: dict[str, Any]) -> set[str]:
    tags: set[str] = set()
    context = profile.get("signature_technology_context") or {}
    for match in context.get("technology_matches", []) if isinstance(context, dict) else []:
        if not isinstance(match, dict):
            continue
        tags.update(str(value).casefold() for value in (match.get("matched_signature_tags") or []) if value)
    return tags


def select_rules_for_detection(
    profile: dict[str, Any],
    analysis: dict[str, Any],
    catalog: dict[str, Any],
    requested_rule_ids: list[str] | None = None,
    selected_technology_tags: list[str] | None = None,
) -> dict[str, Any]:
    rules = normalize_rule_catalog(catalog)
    by_id = {str(item["rule_id"]): item for item in rules}
    intents = analysis.get("generic_protection_intents") or []
    generic = resolve_rule_catalog(intents, rules)
    technology_tags = (
        {str(value).strip().casefold() for value in selected_technology_tags if str(value).strip()}
        if selected_technology_tags is not None
        else _technology_tags(profile)
    )
    technology_matches: list[dict[str, Any]] = []
    excluded_unmatched_technology_rules: list[dict[str, Any]] = []
    selected_ids: set[str] = set()

    # Generic attack intents are intentionally broad, but a broad intent must
    # not pull in product-specific rules for technologies that were not
    # observed.  An explicit administrator selection remains an override.
    for item in generic.get("selected_rules", []):
        rule_id = str(item.get("rule_id"))
        rule = by_id.get(rule_id)
        if not rule:
            continue
        rule_tags = set(rule.get("technology_tags", []))
        matched_tags = sorted(technology_tags.intersection(rule_tags))
        if rule_tags and not matched_tags:
            excluded_unmatched_technology_rules.append({
                "rule_id": rule_id,
                "technology_tags": sorted(rule_tags),
                "reason": "technology tag was not evidenced by this discovery",
            })
            continue
        selected_ids.add(rule_id)
        if matched_tags:
            technology_matches.append({"rule_id": rule_id, "source": "detected-technology", "technology_tags": matched_tags})

    if technology_tags:
        for rule in rules:
            if technology_tags.intersection(set(rule.get("technology_tags", []))):
                selected_ids.add(str(rule["rule_id"]))
                if not any(item.get("rule_id") == str(rule["rule_id"]) for item in technology_matches):
                    technology_matches.append({"rule_id": str(rule["rule_id"]), "source": "detected-technology", "technology_tags": sorted(technology_tags.intersection(set(rule.get("technology_tags", []))))})
    if requested_rule_ids is not None:
        requested = {str(value) for value in requested_rule_ids}
        missing = sorted(requested - set(by_id))
        selected_ids = requested & set(by_id)
        excluded_unmatched_technology_rules = []
    else:
        missing = []
    selected_rules = []
    for rule_id in sorted(selected_ids, key=lambda value: int(value) if value.isdigit() else value):
        rule = by_id[rule_id]
        sources = sorted({str(item.get("intent_id")) for item in generic.get("selected_rules", []) if str(item.get("rule_id")) == rule_id} | ({"detected-technology"} if any(item.get("rule_id") == rule_id for item in technology_matches) else set()))
        selected_rules.append({**rule, "selection_sources": sources})
    filtered_generic = {
        **generic,
        "selected_rules": [item for item in generic.get("selected_rules", []) if str(item.get("rule_id")) in selected_ids],
        "excluded_unmatched_technology_rules": excluded_unmatched_technology_rules,
    }
    return {
        "catalog_status": catalog.get("status"),
        "catalog_path": catalog.get("path"),
        "catalog_fingerprint": catalog_fingerprint(rules) if rules else None,
        "catalog_rule_count": len(rules),
        "generic_resolution": filtered_generic,
        "technology_tags": sorted(technology_tags),
        "technology_selection_mode": "explicit" if selected_technology_tags is not None else "detected",
        "technology_rule_matches": technology_matches,
        "excluded_unmatched_technology_rules": excluded_unmatched_technology_rules,
        "excluded_unmatched_technology_rule_count": len(excluded_unmatched_technology_rules),
        "selected_rules": selected_rules,
        "missing_requested_rule_ids": missing,
    }


def workflow_fingerprint(plan: dict[str, Any]) -> str:
    # Fingerprint only the export-relevant state.  Runtime selection metadata
    # differs between an automatic proposal and its explicit revalidation, so
    # including that metadata would create false drift during preflight.
    payload = {
        "job_id": plan.get("job_id"),
        "hostname": plan.get("hostname"),
        "nsip": plan.get("nsip"),
        "signature_object_name": plan.get("signature_object_name"),
        "action": plan.get("action"),
        "catalog_fingerprint": plan.get("catalog_fingerprint"),
        "selected_rules": [
            {
                "rule_id": item.get("rule_id"),
                "category": item.get("category"),
                "attack_classes": item.get("attack_classes", []),
                "technology_tags": item.get("technology_tags", []),
                "locations": item.get("locations", []),
            }
            for item in (plan.get("selected_rules") or [])
            if isinstance(item, dict)
        ],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def cli_import_commands(signature_object_name: str, rule_ids: list[str], action: str, chunk_size: int = 50) -> list[str]:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", signature_object_name)[:31]
    remote_path = f"waf-scanner-{safe_name}.xml"
    return [
        f"import appfw signatures local:{remote_path} {signature_object_name} -autoEnableNewSignatures OFF",
        "save ns config",
    ]
