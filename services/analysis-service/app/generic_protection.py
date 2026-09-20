from __future__ import annotations

from typing import Any


POLICY_VERSION = "1.0.0"


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
    route_count = len(profile.get("route_inventory", []) or [])
    field_count = len(profile.get("field_formats", []) or [])
    has_forms = bool(field_count or {"html forms", "state-changing form surface"} & evidence_technologies)
    has_auth = "authentication boundary" in evidence_technologies
    has_upload = "file upload surface" in evidence_technologies
    has_api = bool({"rest or json api", "graphql", "xml or soap"} & (technologies | evidence_technologies))
    has_client = bool({"angular", "react", "vue.js", "next.js", "nuxt", "spa"} & technologies)
    has_cookies = any(
        isinstance(item, dict)
        and isinstance(item.get("metadata"), dict)
        and item.get("metadata", {}).get("cookie_names")
        for item in evidence
    )

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
