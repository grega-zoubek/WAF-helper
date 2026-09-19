from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="WAF Intelligence Analysis Service", version="0.1.0")


class AnalysisRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=80)
    profile: dict[str, Any]
    observations: list[dict[str, Any]] = Field(default_factory=list)


def names(profile: dict[str, Any]) -> set[str]:
    return {str(item.get("technology", "")).lower() for item in profile.get("technologies", [])}


SIGNATURE_CATALOG: dict[str, dict[str, Any]] = {
    "web-baseline": {
        "name": "Generic web application baseline",
        "category": "baseline",
        "priority": "high",
        "reason": "Every HTTP application needs a generic baseline before technology-specific tuning.",
    },
    "spa-client": {
        "name": "Single-page application client surface",
        "category": "client-framework",
        "priority": "medium",
        "reason": "Client-rendered routes, forms, and JavaScript assets were observed.",
    },
    "json-api": {
        "name": "REST/JSON API surface",
        "category": "api",
        "priority": "high",
        "reason": "REST, JSON, or API route evidence was observed.",
    },
    "graphql-api": {
        "name": "GraphQL API surface",
        "category": "api",
        "priority": "high",
        "reason": "GraphQL technology or endpoint evidence was observed.",
    },
    "server-php": {
        "name": "PHP server runtime",
        "category": "server-runtime",
        "priority": "medium",
        "reason": "PHP runtime or a PHP-based framework was identified.",
    },
    "server-java": {
        "name": "Java server runtime",
        "category": "server-runtime",
        "priority": "medium",
        "reason": "Java runtime or Java framework evidence was identified.",
    },
    "server-dotnet": {
        "name": ".NET server runtime",
        "category": "server-runtime",
        "priority": "medium",
        "reason": ".NET/ASP.NET runtime evidence was identified.",
    },
    "server-node": {
        "name": "Node.js server runtime",
        "category": "server-runtime",
        "priority": "medium",
        "reason": "Node.js or Express runtime evidence was identified.",
    },
    "cms": {
        "name": "CMS application surface",
        "category": "application-platform",
        "priority": "medium",
        "reason": "A CMS or generated content platform was identified.",
    },
    "authentication": {
        "name": "Authentication and account surface",
        "category": "application-surface",
        "priority": "high",
        "reason": "Login, account, or authentication controls were observed.",
    },
    "file-upload": {
        "name": "File upload surface",
        "category": "application-surface",
        "priority": "high",
        "reason": "A file input or upload control was observed.",
    },
    "form-input": {
        "name": "Web form input surface",
        "category": "application-surface",
        "priority": "high",
        "reason": "HTML or runtime form controls were observed.",
    },
}


def _has_any(technology_names: set[str], values: set[str]) -> bool:
    return any(value in name or name in value for name in technology_names for value in values)


def _profile_score(item: dict[str, Any]) -> float:
    try:
        return float(item.get("confidence_score", 0.0))
    except (TypeError, ValueError):
        return 0.0


def _primary_technology(profile: dict[str, Any]) -> dict[str, Any]:
    technologies = [item for item in profile.get("technologies", []) if item.get("technology")]
    if not technologies:
        return {"technology": "Undetermined", "confidence": "low", "confidence_score": 0.0, "basis": "No technology evidence was observed"}
    item = max(technologies, key=_profile_score)
    return {
        "technology": item.get("technology", "Undetermined"),
        "confidence": item.get("confidence", "low"),
        "confidence_score": _profile_score(item),
        "basis": f"Highest-confidence technology signal from {item.get('evidence_count', 0)} evidence row(s)",
    }


def _source_urls(profile: dict[str, Any]) -> list[str]:
    urls = []
    for item in profile.get("evidence", []):
        source_url = str(item.get("source_url", ""))
        if source_url and source_url not in urls:
            urls.append(source_url)
    return urls


def build_protection_plan(profile: dict[str, Any]) -> dict[str, Any]:
    technology_names = names(profile)
    technologies = profile.get("technologies", [])
    evidence = profile.get("evidence", [])
    primary = _primary_technology(profile)
    selected: list[str] = ["web-baseline"]
    selection_reasons: list[str] = ["Generic web baseline is always selected as the starting point."]

    if _has_any(technology_names, {"angular", "react", "vue", "next", "nuxt", "javascript", "spa"}):
        selected.append("spa-client")
        selection_reasons.append("A client-rendered JavaScript application was detected.")
    if _has_any(technology_names, {"rest", "json", "api"}):
        selected.append("json-api")
        selection_reasons.append("REST/JSON or API evidence was detected.")
    if _has_any(technology_names, {"graphql"}):
        selected.append("graphql-api")
        selection_reasons.append("GraphQL evidence was detected.")
    if _has_any(technology_names, {"php", "laravel"}):
        selected.append("server-php")
    if _has_any(technology_names, {"java", "spring"}):
        selected.append("server-java")
    if _has_any(technology_names, {"asp.net", ".net", "dotnet"}):
        selected.append("server-dotnet")
    if _has_any(technology_names, {"node", "express"}):
        selected.append("server-node")
    if _has_any(technology_names, {"wordpress", "drupal", "cms", "generated platform"}):
        selected.append("cms")

    form_items = [
        item for item in evidence
        if item.get("evidence_type") == "technology"
        and item.get("technology") in {"HTML forms", "State-changing form surface", "Authentication boundary", "File upload surface"}
    ]
    if form_items or profile.get("field_formats"):
        selected.append("form-input")
        selection_reasons.append("Form controls or field format evidence was observed.")
    if any(item.get("technology") == "Authentication boundary" for item in form_items):
        selected.append("authentication")
        selection_reasons.append("An authentication boundary was observed.")
    if any(item.get("technology") == "File upload surface" for item in form_items):
        selected.append("file-upload")
        selection_reasons.append("A file upload surface was observed.")

    selected = list(dict.fromkeys(selected))
    signature_recommendations = []
    for catalog_key in selected:
        catalog_item = SIGNATURE_CATALOG[catalog_key]
        signature_recommendations.append({
            "catalog_key": catalog_key,
            "name": catalog_item["name"],
            "category": catalog_item["category"],
            "priority": catalog_item["priority"],
            "selection": "selected",
            "deployment_mode": "Log",
            "reason": catalog_item["reason"],
            "source": "deterministic technology/application catalog",
            "requires_adc_catalog_match": True,
            "status": "proposal-only",
        })

    route_paths: list[str] = []
    for item in profile.get("route_inventory", []):
        route = str(item.get("source_url", ""))
        parsed = urlparse(route)
        logical = parsed.fragment if parsed.fragment.startswith("/") else parsed.path or "/"
        if logical and logical not in route_paths:
            route_paths.append(logical[:200])
    field_names: list[str] = []
    for item in profile.get("field_formats", []):
        name = str(item.get("name") or item.get("id") or "")
        if name and name not in field_names:
            field_names.append(name[:100])

    custom_signature_proposals: list[dict[str, Any]] = []
    if route_paths:
        custom_signature_proposals.append({
            "proposal_id": "app-route-scope",
            "name": "Application route scope",
            "kind": "application-context",
            "match_location": "URL_PATH_OR_HASH_ROUTE",
            "observed_values": route_paths[:25],
            "suggested_action": "Scope the selected signature groups to these application routes after ADC catalog validation.",
            "deployment_mode": "Log",
            "status": "draft",
            "reason": "Routes were observed passively; no attack pattern was inferred from them.",
        })
    if field_names:
        custom_signature_proposals.append({
            "proposal_id": "app-field-scope",
            "name": "Application field scope",
            "kind": "field-context",
            "match_location": "FORM_FIELD_NAME_OR_ID",
            "observed_values": field_names[:50],
            "suggested_action": "Use observed field names to scope or review signature exceptions; keep enforcement disabled until validated.",
            "deployment_mode": "Log",
            "status": "draft",
            "reason": "Field names and formats were observed without retaining field values.",
        })

    app_url = next(iter(_source_urls(profile)), "")
    return {
        "status": "proposal-only",
        "changes_applied": False,
        "application": {
            "source_url": app_url,
            "primary_technology": primary,
            "technology_count": len(technologies),
        },
        "profile_recommendation": {
            "candidate": "technology-and-application-baseline",
            "selection_basis": selection_reasons,
            "deployment_mode": "Log",
            "requires_review": True,
        },
        "signature_recommendations": signature_recommendations,
        "custom_signature_proposals": custom_signature_proposals,
        "safety_notes": [
            "Signature groups are catalog keys and must be matched to the installed ADC signature catalog before deployment.",
            "No attack payloads or vulnerability probes were generated.",
            "All recommendations remain proposal-only and default to Log until reviewed.",
        ],
    }


def analyze(request: AnalysisRequest) -> dict[str, Any]:
    technology_names = names(request.profile)
    observations = request.observations
    route_candidates = request.profile.get("route_candidates", [])
    architecture: list[str] = []
    protections: list[dict[str, str]] = []
    gaps: list[str] = []
    observed_header_values: dict[str, list[str]] = {}

    if technology_names & {"wordpress", "drupal", "generated platform"}:
        architecture.append("CMS or generated web platform")
    if technology_names & {"next.js", "nuxt", "react", "vue.js", "angular"}:
        architecture.append("JavaScript client or server-rendered frontend")
    if technology_names & {"rest or json api", "graphql", "xml or soap"}:
        architecture.append("API surface")
        protections.append({"area": "API", "reason": "API response or protocol signals were observed", "priority": "high"})
    if route_candidates:
        architecture.append("Client-referenced API or application routes")
        protections.append({"area": "API route review", "reason": "Static route candidates were found in JavaScript bundles; they were not fetched", "priority": "medium"})
    if technology_names & {"php runtime", "java runtime", "asp.net runtime", "laravel"}:
        architecture.append("Stateful server-side application runtime")
    if technology_names & {"cloudflare", "reverse proxy or cache"}:
        architecture.append("CDN, reverse proxy, or caching layer")

    form_evidence = [item for item in request.profile.get("evidence", []) if item.get("evidence_type") == "technology" and item.get("technology") in {"HTML forms", "State-changing form surface", "File upload surface", "Authentication boundary"}]
    if form_evidence:
        protections.append({"area": "Web form input", "reason": "Form, POST, upload, or authentication surfaces were observed", "priority": "high"})
    if any(cookie for observation in observations for cookie in observation.get("observation", {}).get("response", {}).get("cookies", [])):
        protections.append({"area": "Session and cookies", "reason": "Set-Cookie metadata was observed", "priority": "medium"})

    for observation in observations:
        for key, value in observation.get("observation", {}).get("response", {}).get("headers", {}).items():
            observed_header_values.setdefault(key.lower(), []).append(str(value)[:500])

    security_headers = set(observed_header_values)
    route_origin = next((f"{urlparse(item.get('source_url', '')).scheme}://{urlparse(item.get('source_url', '')).netloc}" for item in request.profile.get("evidence", []) if item.get("evidence_type") == "route" and urlparse(item.get("source_url", "")).netloc), "")
    script_origins: set[str] = set()
    style_origins: set[str] = set()
    for item in request.profile.get("evidence", []):
        if item.get("evidence_type") != "asset":
            continue
        asset_url = item.get("source_url", "")
        parsed_asset = urlparse(asset_url)
        origin = f"{parsed_asset.scheme}://{parsed_asset.netloc}" if parsed_asset.netloc else ""
        suffix = parsed_asset.path.lower().rsplit(".", 1)[-1] if "." in parsed_asset.path else ""
        if origin and origin != route_origin and suffix in {"js", "mjs"}:
            script_origins.add(origin)
        if origin and origin != route_origin and suffix == "css":
            style_origins.add(origin)
    csp_script_sources = " ".join(["'self'"] + sorted(script_origins))
    csp_style_sources = " ".join(["'self'"] + sorted(style_origins))
    csp_report_uri = os.getenv("CSP_REPORT_URI", "/api/csp/report")[:512]
    csp_draft = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; script-src " + csp_script_sources + "; style-src " + csp_style_sources + "; img-src 'self' data:; connect-src 'self'; report-uri " + csp_report_uri + ";"
    header_specs = (
        ("content-security-policy", "CSP", "Browser script and content policy", csp_draft, "report-only", "Generated from observed same-origin and external JS/CSS asset origins; application-specific scripts, styles, APIs, frames, fonts, and reporting endpoints still require confirmation."),
        ("strict-transport-security", "HSTS", "Transport security", "max-age=31536000; includeSubDomains", "enforce-after-HTTPS-review", "Use only when the application and its subdomains are HTTPS-only."),
        ("x-content-type-options", "X-Content-Type-Options", "Content type hardening", "nosniff", "enforce", "Safe baseline response header."),
        ("x-frame-options", "X-Frame-Options", "Clickjacking protection", "SAMEORIGIN", "enforce-after-framing-review", "Change or omit if trusted cross-origin framing is required."),
        ("referrer-policy", "Referrer-Policy", "Referrer data minimization", "strict-origin-when-cross-origin", "enforce", "Safe baseline for reducing cross-origin URL disclosure."),
        ("permissions-policy", "Permissions-Policy", "Browser capability restriction", "geolocation=(), microphone=(), camera=()", "enforce-after-feature-review", "Review application feature requirements before applying."),
    )
    header_plan: list[dict[str, Any]] = []
    for header, display_name, area, suggested_value, mode, reason in header_specs:
        values = sorted(set(observed_header_values.get(header, [])))
        report_values = sorted(set(observed_header_values.get("content-security-policy-report-only", []))) if header == "content-security-policy" else []
        effective_values = values or report_values
        header_plan.append({
            "header": display_name,
            "observed": bool(effective_values),
            "observed_values": effective_values,
            "suggested_value": suggested_value,
            "deployment_mode": "already-observed" if effective_values else mode,
            "reason": reason,
            "area": area,
        })
        if not effective_values:
            gaps.append(f"{display_name} was not observed in the sampled responses")

    if not observations:
        gaps.append("No sanitized HTTP observations are available")
    else:
        if any(item.get("observation", {}).get("body_retained") is False for item in observations):
            gaps.append("Response bodies were intentionally not retained; body-level confirmation is unavailable")
        gaps.append("Discovery was anonymous and passive; authenticated behavior was not assessed")

    if not architecture:
        architecture.append("Web application technology not yet determined")
    if not protections:
        protections.append({"area": "Baseline web protection", "reason": "No strong application-specific signal was observed", "priority": "medium"})

    return {
        "run_id": request.run_id,
        "analysis_mode": "deterministic-synthesis",
        "ai_handoff_ready": True,
        "technology_profile": request.profile.get("technologies", []),
        "protection_plan": build_protection_plan(request.profile),
        "likely_architecture": sorted(set(architecture)),
        "candidate_protection_areas": protections,
        "security_headers": header_plan,
        "csp_draft": csp_draft,
        "csp_report_uri": csp_report_uri,
        "csp_external_script_origins": sorted(script_origins),
        "csp_external_style_origins": sorted(style_origins),
        "lb_response_header_plan": {
            "status": "proposal-only",
            "changes_applied": False,
            "target": "NetScaler LB response path",
            "entries": header_plan,
        },
        "evidence_gaps": gaps,
        "observation_count": len(observations),
        "route_candidate_count": len(route_candidates),
        "change_recommendation": "Review evidence and candidate protection areas before creating any NetScaler change plan.",
    }


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "analysis-service", "mode": "read-only"}


@app.post("/analyze")
async def run_analysis(request: AnalysisRequest) -> dict[str, Any]:
    return analyze(request)
