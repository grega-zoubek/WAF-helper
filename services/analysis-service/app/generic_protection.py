from __future__ import annotations

from typing import Any


POLICY_VERSION = "1.1.0"


def _technology_keys(profile: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for item in profile.get("technologies", []):
        if not isinstance(item, dict):
            continue
        for field in ("technology", "technology_key", "category"):
            value = str(item.get(field) or "").strip().casefold()
            if value:
                keys.add(value)
    return keys


def _evidence_technologies(profile: dict[str, Any]) -> set[str]:
    return {
        str(item.get("technology") or "").strip().casefold()
        for item in profile.get("evidence", [])
        if isinstance(item, dict) and item.get("technology")
    }


def _surface_facts(profile: dict[str, Any]) -> dict[str, Any]:
    evidence = profile.get("evidence", []) or []
    evidence_technologies = _evidence_technologies(profile)
    static_candidates = [item for item in profile.get("auth_endpoint_candidates", []) or [] if isinstance(item, dict)]
    static_auth = [item for item in static_candidates if str((item.get("metadata") or {}).get("endpoint_class", "")) == "authentication"]
    static_api = [item for item in static_candidates if str((item.get("metadata") or {}).get("endpoint_class", "")) == "api"]
    route_count = len(profile.get("route_inventory", []) or [])
    field_count = len(profile.get("field_formats", []) or [])
    auth_surface_count = len(profile.get("auth_surfaces", []) or [])
    api_endpoint_count = len(profile.get("api_endpoints", []) or [])
    has_forms = bool(field_count or {"html forms", "state-changing form surface"} & evidence_technologies)
    has_auth = bool(auth_surface_count or static_auth or "authentication boundary" in evidence_technologies)
    has_upload = "file upload surface" in evidence_technologies
    has_api = bool(api_endpoint_count or static_api or {"rest or json api", "graphql", "xml or soap"} & (_technology_keys(profile) | evidence_technologies))
    has_client = bool({"angular", "react", "vue.js", "next.js", "nuxt", "spa"} & _technology_keys(profile))
    has_cookies = any(
        isinstance(item, dict)
        and isinstance(item.get("metadata"), dict)
        and item.get("metadata", {}).get("cookie_names")
        for item in evidence
    )
    return {
        "technology_count": len(profile.get("technologies", []) or []),
        "route_count": route_count,
        "field_count": field_count,
        "auth_surface_count": auth_surface_count,
        "api_endpoint_count": api_endpoint_count,
        "static_auth_endpoint_count": len(static_auth),
        "static_api_endpoint_count": len(static_api),
        "has_forms": has_forms,
        "has_auth": has_auth,
        "has_upload": has_upload,
        "has_api": has_api,
        "has_client": has_client,
        "has_cookies": has_cookies,
        "has_xml": "xml or soap" in (_technology_keys(profile) | evidence_technologies),
    }


def _applicability(intent_id: str, facts: dict[str, Any]) -> tuple[float, list[str]]:
    evidence: list[str] = []
    if intent_id == "generic-web-attack-signatures":
        score = 0.90 if facts["route_count"] or facts["technology_count"] else 0.70
        evidence.append("reachable HTTP application")
    elif intent_id == "injection-and-input-signatures":
        score = 0.92 if facts["field_count"] or facts["has_api"] else 0.35
        if facts["field_count"]:
            evidence.append(f"field_count={facts['field_count']}")
        if facts["has_api"]:
            evidence.append("API surface")
    elif intent_id == "cross-site-scripting-signatures":
        score = 0.90 if facts["has_client"] or facts["route_count"] or facts["has_forms"] else 0.35
        if facts["has_client"]:
            evidence.append("client-rendered surface")
        if facts["route_count"]:
            evidence.append(f"route_count={facts['route_count']}")
    elif intent_id == "session-and-authentication-protection":
        score = 0.95 if facts["has_auth"] else 0.78 if facts["has_cookies"] else 0.25
        if facts["auth_surface_count"]:
            evidence.append(f"runtime_auth_surfaces={facts['auth_surface_count']}")
        if facts["static_auth_endpoint_count"]:
            evidence.append(f"static_auth_candidates={facts['static_auth_endpoint_count']}")
        if facts["has_cookies"]:
            evidence.append("cookie metadata")
    elif intent_id == "file-upload-protection":
        score = 0.96 if facts["has_upload"] else 0.15
        if facts["has_upload"]:
            evidence.append("file upload surface")
    elif intent_id == "xml-service-protection":
        score = 0.94 if facts["has_xml"] else 0.20
        if facts["has_xml"]:
            evidence.append("XML or SOAP evidence")
    elif intent_id == "runtime-specific-signatures":
        score = 0.70 if facts["technology_count"] else 0.25
        evidence.append("runtime confirmation and provider mapping required")
    elif intent_id == "technology-specific-signatures":
        score = 0.72 if facts["technology_count"] else 0.20
        evidence.append("technology evidence and provider mapping required")
    else:
        score = 0.50
        evidence.append("no specialized scoring rule")
    return round(score, 2), evidence


def applicability_confidence(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.60:
        return "medium"
    return "low"


def _intent(
    intent_id: str,
    name: str,
    priority: str,
    decision: str,
    rationale: str,
    evidence: list[str],
    *,
    action: str = "LOG",
    provider_mapping: str = "catalog-resolution-required",
) -> dict[str, Any]:
    return {
        "intent_id": intent_id,
        "name": name,
        "priority": priority,
        "decision": decision,
        "proposed_action": action,
        "rationale": rationale,
        "evidence": sorted(set(evidence)),
        "provider_mapping": provider_mapping,
        "proposal_only": True,
    }


def build_generic_protection_intents(profile: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive provider-neutral protection intents from passive application evidence.

    This layer intentionally does not select ADC rule IDs. Provider adapters resolve
    these intents against the installed catalog and preserve a proposal-only guard.
    """
    technologies = _technology_keys(profile)
    evidence_technologies = _evidence_technologies(profile)
    evidence = profile.get("evidence", [])
    facts = _surface_facts(profile)
    route_count = facts["route_count"]
    field_count = facts["field_count"]
    has_forms = facts["has_forms"]
    has_auth = facts["has_auth"]
    has_upload = facts["has_upload"]
    has_api = facts["has_api"]
    has_client = facts["has_client"]
    has_cookies = facts["has_cookies"]

    intents: list[dict[str, Any]] = [
        _intent(
            "generic-web-attack-signatures",
            "Generic web attack signatures",
            "high",
            "include",
            "Every reachable HTTP application needs a provider-resolved baseline for common attack patterns.",
            ["reachable HTTP application"],
        )
    ]

    if has_forms or field_count or has_api:
        intents.append(_intent(
            "injection-and-input-signatures",
            "Injection and input attack signatures",
            "high",
            "include",
            "Input-bearing routes, fields, or API surfaces were observed.",
            ["forms or fields" if has_forms or field_count else "API/protocol evidence"],
        ))

    if has_forms or has_client or route_count:
        intents.append(_intent(
            "cross-site-scripting-signatures",
            "Cross-site scripting signatures",
            "high",
            "include",
            "HTML, client-rendered content, or application routes were observed; JavaScript-heavy applications require false-positive review.",
            ["HTML/client application surface", f"route_count={route_count}"],
        ))

    if has_auth or has_cookies:
        intents.append(_intent(
            "session-and-authentication-protection",
            "Session and authentication protection",
            "high",
            "include",
            "Authentication or session metadata was observed.",
            ["authentication boundary" if has_auth else "cookie metadata"],
        ))

    if has_upload:
        intents.append(_intent(
            "file-upload-protection",
            "File upload protection",
            "high",
            "include",
            "A file upload surface was observed.",
            ["file upload surface"],
        ))

    if "xml or soap" in technologies or "xml or soap" in evidence_technologies:
        intents.append(_intent(
            "xml-service-protection",
            "XML and SOAP protection",
            "medium",
            "include",
            "XML or SOAP protocol evidence was observed.",
            ["XML or SOAP evidence"],
        ))

    intents.extend([
        _intent(
            "runtime-specific-signatures",
            "Runtime-specific signatures",
            "medium",
            "conditional",
            "Runtime-specific signatures require explicit runtime evidence and an installed provider catalog mapping.",
            ["runtime confirmation required"],
            action="LOG",
        ),
        _intent(
            "technology-specific-signatures",
            "Technology-specific signatures",
            "low",
            "conditional",
            "Product fingerprints are optional enrichment and must not select unrelated technology rules.",
            ["product-specific evidence and catalog mapping required"],
            action="LOG",
        ),
    ])
    for item in intents:
        score, scoring_evidence = _applicability(str(item["intent_id"]), facts)
        item["applicability_score"] = score
        item["applicability_confidence"] = applicability_confidence(score)
        item["scoring_evidence"] = scoring_evidence
    return intents


def automation_policy() -> dict[str, Any]:
    return {
        "policy_version": POLICY_VERSION,
        "mode": "proposal-only",
        "predefined_rules": {"enabled": True, "source": "versioned provider catalog and generic policy rules"},
        "ai_advisor": {"enabled": False, "role": "advisory-only", "cannot_select_unavailable_rules": True, "cannot_apply_changes": True},
        "automatic_apply": {"enabled": False, "requires": ["explicit approval", "fresh ADC inventory", "successful preflight", "write-mode confirmation"]},
        "fail_closed_reasons": ["unknown target path", "missing rule-level catalog evidence", "catalog drift", "unresolved false-positive risk"],
    }
