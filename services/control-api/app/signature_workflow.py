from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from app.rule_catalog import catalog_fingerprint, normalize_rule_catalog, resolve_rule_catalog
from app.generic_signature_groups import build_cve_signature_group, build_generic_group_subgroups, select_generic_signature_groups
from app.confidence import confidence_summary, rule_confidence, technology_detection_scores


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


def _product_rule_ids(catalog: dict[str, Any]) -> dict[str, set[str]]:
    product_index = catalog.get("product_index") if isinstance(catalog, dict) else None
    if not isinstance(product_index, dict):
        return {}
    result: dict[str, set[str]] = {}
    for item in product_index.get("products", []):
        if not isinstance(item, dict) or not item.get("key"):
            continue
        result[f"product:{str(item['key']).strip().casefold()}"] = {str(value) for value in (item.get("rule_ids") or []) if value is not None}
    return result


def _rule_year(rule: dict[str, Any]) -> int | None:
    value = rule.get("released_year", rule.get("year"))
    try:
        year = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return year if 1900 <= year <= 2100 else None


def _positive_model_recommendation(profile: dict[str, Any], explicit_filters: list[str] | None) -> dict[str, Any]:
    detected_technologies = [
        item for item in (profile.get("technologies") or [])
        if isinstance(item, dict) and str(item.get("technology") or "").strip()
    ]
    detected_tags = _technology_tags(profile)
    if explicit_filters is None and not detected_technologies and not detected_tags:
        return {
            "enabled": False,
            "recommended": True,
            "status": "recommended",
            "mode": "positive-model",
            "action": "build-positive-model",
            "reason": "No application technology or product was detected; a generic signature baseline is not sufficiently application-specific.",
            "next_step": "Build an allow-list model from observed routes, methods, parameters, cookies, and content types before BLOCK enforcement.",
            "automatic_apply_allowed": False,
        }
    return {
        "enabled": False,
        "recommended": False,
        "status": "not-required",
        "mode": "positive-model",
        "action": "deferred",
        "reason": "Application technology evidence is available or an explicit technology selection was provided.",
        "automatic_apply_allowed": False,
    }


def select_rules_for_detection(
    profile: dict[str, Any],
    analysis: dict[str, Any],
    catalog: dict[str, Any],
    requested_rule_ids: list[str] | None = None,
    selected_technology_tags: list[str] | None = None,
    include_generic_signatures: bool = True,
    selected_technology_filters: list[str] | None = None,
    selected_release_years: list[int] | None = None,
    selected_signature_groups: list[str] | None = None,
    cve_view_mode: str = "vendor",
    cve_search_mode: str = "description",
    cve_search_query: str = "",
) -> dict[str, Any]:
    rules = normalize_rule_catalog(catalog)
    by_id = {str(item["rule_id"]): item for item in rules}
    intents = (analysis.get("generic_protection_intents") or []) if include_generic_signatures else []
    generic = resolve_rule_catalog(intents, rules)
    generic_groups = select_generic_signature_groups(
        rules,
        profile,
        selected_signature_groups,
    ) if include_generic_signatures else {
        "groups": [],
        "requested_group_ids": [],
        "rule_sources": {},
        "selected_rule_ids": [],
        "selected_rule_count": 0,
        "unresolved_group_ids": [],
        "signature_only": True,
        "positive_model": {"enabled": False, "reason": "deferred to a later phase"},
    }
    explicit_filters = selected_technology_filters if selected_technology_filters is not None else selected_technology_tags
    positive_model = _positive_model_recommendation(profile, explicit_filters)
    product_rule_map = _product_rule_ids(catalog)
    product_rule_ids: set[str] = set()
    if explicit_filters is not None:
        filter_values = {str(value).strip().casefold() for value in explicit_filters if str(value).strip()}
        technology_tags = {value.removeprefix("tag:") for value in filter_values if not value.startswith("product:")}
        for value in filter_values:
            if value.startswith("product:"):
                product_rule_ids.update(product_rule_map.get(value, set()))
    else:
        technology_tags = _technology_tags(profile)
    technology_matches: list[dict[str, Any]] = []
    excluded_unmatched_technology_rules: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    generic_group_sources = {
        str(rule_id): set(sources)
        for rule_id, sources in (generic_groups.get("rule_sources") or {}).items()
    }

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

    # The first protection phase is signature-only and provider-neutral.  Add
    # exact untagged catalog rules from the five generic groups; technology-
    # tagged rules remain controlled by the technology/product selectors above.
    if include_generic_signatures:
        selected_ids.update(
            rule_id for rule_id in generic_group_sources
            if rule_id in by_id
        )

    if technology_tags:
        for rule in rules:
            if technology_tags.intersection(set(rule.get("technology_tags", []))):
                selected_ids.add(str(rule["rule_id"]))
                if not any(item.get("rule_id") == str(rule["rule_id"]) for item in technology_matches):
                    technology_matches.append({"rule_id": str(rule["rule_id"]), "source": "detected-technology", "technology_tags": sorted(technology_tags.intersection(set(rule.get("technology_tags", []))))})
    if product_rule_ids:
        for rule_id in product_rule_ids:
            if rule_id not in by_id:
                continue
            selected_ids.add(rule_id)
            if not any(item.get("rule_id") == rule_id for item in technology_matches):
                technology_matches.append({"rule_id": rule_id, "source": "selected-product"})
    release_years = {int(value) for value in (selected_release_years or []) if str(value).isdigit() and 1900 <= int(value) <= 2100} if selected_release_years is not None else None
    if release_years is not None:
        selected_ids = {rule_id for rule_id in selected_ids if _rule_year(by_id[rule_id]) in release_years}
        technology_matches = [item for item in technology_matches if str(item.get("rule_id")) in selected_ids]
    tag_rule_sets: dict[str, set[str]] = {}
    for tag in technology_tags:
        tag_rule_sets[tag] = {str(rule["rule_id"]) for rule in rules if tag in set(rule.get("technology_tags", []))}
    canonical_filters: list[str] = []
    for tag in sorted(technology_tags):
        tag_key = f"tag:{tag}"
        matching_products = [key for key, rule_ids in product_rule_map.items() if rule_ids and rule_ids == tag_rule_sets.get(tag, set())]
        canonical_filters.extend(sorted(matching_products) or [tag_key])
    if explicit_filters is not None:
        canonical_filters = sorted({
            value if value.startswith("product:") else f"tag:{value.removeprefix('tag:')}"
            for value in (explicit_filters or [])
            if str(value).strip()
        })
    if requested_rule_ids is not None:
        requested = {str(value) for value in requested_rule_ids}
        missing = sorted(requested - set(by_id))
        selected_ids = requested & set(by_id)
        excluded_unmatched_technology_rules = []
    else:
        missing = []
    # CVEs are a cross-list of technology-linked rules in the current
    # proposal, not a separate catalog browser.  Generic untagged attack
    # signatures can remain recommended, but their CVE references must not be
    # presented as application-specific recommendations without technology
    # evidence.
    technology_rule_match_ids = {
        str(item.get("rule_id"))
        for item in technology_matches
        if item.get("rule_id") is not None
    }
    cve_candidate_rule_ids = selected_ids.intersection(technology_rule_match_ids)
    technology_scores = technology_detection_scores(profile)
    selected_rules = []
    for rule_id in sorted(selected_ids, key=lambda value: int(value) if value.isdigit() else value):
        rule = by_id[rule_id]
        sources = sorted(
            {str(item.get("intent_id")) for item in generic.get("selected_rules", []) if str(item.get("rule_id")) == rule_id}
            | generic_group_sources.get(rule_id, set())
            | ({"detected-technology"} if any(item.get("rule_id") == rule_id for item in technology_matches) else set())
        )
        confidence = rule_confidence(
            rule,
            technology_tags=technology_tags,
            technology_scores=technology_scores,
            explicitly_selected_product=rule_id in product_rule_ids,
            explicitly_selected_technology=explicit_filters is not None,
            selection_sources=set(sources),
        )
        enriched_rule = {**rule, "selection_sources": sources, "confidence": confidence}
        by_id[rule_id] = enriched_rule
        selected_rules.append(enriched_rule)
    generic_groups["groups"] = build_generic_group_subgroups(
        generic_groups.get("groups", []),
        by_id,
        selected_ids,
        catalog.get("product_index") if isinstance(catalog, dict) else None,
    )
    cve_signature_group = build_cve_signature_group(
        cve_candidate_rule_ids,
        by_id,
        selected_ids,
        catalog.get("product_index") if isinstance(catalog, dict) else None,
        cve_view_mode,
        cve_search_mode,
        cve_search_query,
    )
    generic_group_rule_count = sum(int(group.get("selected_rule_count") or 0) for group in generic_groups.get("groups", []))
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
        "generic_signature_groups": generic_groups.get("groups", []),
        "cve_signature_group": cve_signature_group,
        "cve_rule_count": int(cve_signature_group.get("candidate_rule_count") or 0) if cve_signature_group else 0,
        "cve_count": int(cve_signature_group.get("cve_count") or 0) if cve_signature_group else 0,
        "cve_candidate_scope": "detected-or-selected-technology-rules",
        "confidence_summary": confidence_summary(selected_rules),
        "generic_signature_group_ids": generic_groups.get("requested_group_ids", []),
        "generic_signature_group_rule_count": generic_group_rule_count,
        "unresolved_generic_signature_groups": generic_groups.get("unresolved_group_ids", []),
        "signature_only": True,
        "positive_model": positive_model,
        "technology_tags": sorted(technology_tags),
        "technology_filters": canonical_filters,
        "technology_selection_mode": "explicit" if explicit_filters is not None else "detected",
        "selected_product_rule_count": len(product_rule_ids),
        "release_years": sorted(release_years) if release_years is not None else [],
        "release_year_selection_mode": "explicit" if release_years is not None else "none",
        "include_generic_signatures": bool(include_generic_signatures),
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
