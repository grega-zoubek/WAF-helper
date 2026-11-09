"""Recommend NetScaler AppFW security checks from observed application evidence.

Everything here is a proposal: each check states what evidence supports it, how likely it is to
cause false positives, and what must be learned before enforcing. Actions are always LOG.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.field_roles import template_path

FIELD_TYPE_FOR_ROLE = {
    "email": "email", "numeric": "integer", "otp": "integer", "card": "integer", "phone": "phone-like",
    "username": "name (letters, digits, . _ - @)", "search": "text without HTML", "free-text": "text without HTML",
    "url": "url", "date": "date",
}
SKIP_FIELD_ROLES = {"password", "hidden", "csrf-token", "captcha", "choice", "file", "other"}


def _regex_for(path: str) -> str:
    """Anchored regex for a templated path: /p/{id:int} -> ^/p/[0-9]+$."""
    out = []
    for segment in path.split("/"):
        if re.fullmatch(r"\{id\d*:int\}", segment):
            out.append("[0-9]+")
        elif re.fullmatch(r"\{id\d*:uuid\}", segment):
            out.append("[0-9a-fA-F-]{36}")
        else:
            out.append(re.escape(segment))
    return "^" + "/".join(out) + "$"


def _server_paths(profile: dict[str, Any]) -> list[str]:
    paths: set[str] = set()
    for row in profile.get("route_inventory", []) or []:
        url = str(row.get("source_url") or "")
        parsed = urlparse(url)
        if parsed.path:
            paths.add(template_path(parsed.path))  # fragments (#/route) never reach the server
    for item in profile.get("api_endpoints", []) or []:
        parsed = urlparse(str(item.get("url") or ""))
        if parsed.path:
            paths.add(template_path(parsed.path))
    return sorted(paths)


def _cookie_names(profile: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for row in profile.get("evidence", []) or []:
        meta = row.get("metadata") if isinstance(row, dict) else None
        for name in (meta or {}).get("cookie_names", []) or []:
            names.add(str(name))
    return sorted(names)


def build_security_check_recommendations(profile: dict[str, Any], injection_surface: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    forms = [f for f in profile.get("form_endpoints", []) or [] if isinstance(f, dict)]
    static_forms = [f for f in forms if f.get("method") in {"GET", "POST"}]
    script_forms = [f for f in forms if f.get("method") == "SCRIPT"]
    fields = [f for f in profile.get("field_formats", []) or [] if isinstance(f, dict) and f.get("role") not in {None, "action"}]
    roles = {f["role"] for f in fields}
    api = bool(profile.get("api_endpoints"))
    paths = _server_paths(profile)
    cookies = _cookie_names(profile)
    injection_surface = injection_surface or []
    has_static_post = any(f.get("method") == "POST" for f in static_forms)
    upload = "file" in roles
    spa = bool(script_forms) and len(script_forms) >= len(static_forms)

    checks: list[dict[str, Any]] = []

    def add(check_id: str, name: str, settings: list[str], applicability: str, risk: str, why: str, evidence: list[str], *, objects: dict[str, Any] | None = None, notes: list[str] | None = None) -> None:
        checks.append({"check_id": check_id, "name": name, "profile_settings": settings, "applicability": applicability, "false_positive_risk": risk,
                       "why": why, "evidence": evidence, "proposed_objects": objects or {}, "notes": notes or [], "proposed_action": "LOG"})

    patterns = [_regex_for(p) for p in paths]
    add("start_url", "Start URL", ["startURLAction"], "recommended" if paths else "not-applicable", "high" if spa else "medium",
        "Only URLs the application really serves are allowed as entry points; everything else is logged.",
        [f"{len(paths)} server-visible paths (fragments excluded)", "single-page application" if spa else "server-rendered pages"],
        objects={"start_url_patterns": patterns[:60], "truncated": max(0, len(patterns) - 60)},
        notes=["Run in LOG with learning first: static assets and API paths change with every release.",
               "Client-side routes (#/...) never reach the appliance, so they cannot be allow-listed here."] if spa else ["Run in LOG with learning first."])

    types = []
    if api:
        types.append("application/json")
    if has_static_post:
        types.append("application/x-www-form-urlencoded")
    if upload:
        types.append("multipart/form-data")
    add("content_type", "Content type", ["contentTypeAction"], "recommended" if types else "not-applicable", "low",
        "Requests must use a content type the application is known to accept.", [f"observed request styles: {', '.join(types) or 'none'}"],
        objects={"allowed_content_types": types})

    formats = []
    for form in forms:
        for field in form.get("fields", []):
            suggestion = FIELD_TYPE_FOR_ROLE.get(field.get("role"))
            if field.get("role") in SKIP_FIELD_ROLES or not suggestion:
                continue
            formats.append({"form": f"{form.get('method')} {form.get('path_template')}", "field": field.get("name"), "role": field.get("role"), "suggested_type": suggestion})
    add("field_formats", "Field formats", ["fieldFormatAction"], "recommended" if formats else "not-applicable", "medium",
        "Each entry field gets an expected character class and length, so unexpected input is logged.",
        [f"{len(formats)} typed fields across {len({f['form'] for f in formats})} forms"], objects={"fields": formats[:200]},
        notes=["Confirm the type names with `show appfw fieldtype` on the appliance; passwords are deliberately not constrained.",
               "Use learning to set min/max lengths; guessing them is the main source of false positives."])

    add("form_field_consistency", "Form field consistency", ["fieldConsistencyAction"], "recommended" if static_forms else "not-applicable", "medium",
        "Server-rendered forms must come back with the same field names they were sent with.",
        [f"{len(static_forms)} server-rendered form endpoints", f"{len(script_forms)} script-driven forms (cannot be tracked)"],
        notes=["Script-driven (SPA) forms are submitted by JavaScript, so the appliance never sees the form it would compare against."] if script_forms else [])
    csrf_tokens = [f for f in fields if f.get("role") == "csrf-token"]
    add("csrf_form_tagging", "CSRF form tagging", ["CSRFtagAction"], "recommended" if has_static_post else "not-applicable", "medium",
        "Server-rendered POST forms get a per-session tag that must be returned.", [f"{sum(1 for f in static_forms if f.get('method') == 'POST')} server-rendered POST forms"],
        notes=(["The application already sends anti-forgery fields; check for conflicts with the appliance's own tag."] if csrf_tokens else []) + ([] if has_static_post else ["No server-rendered POST form was seen; token-based SPAs rely on their own CSRF defences."]))
    add("cookie_consistency", "Cookie consistency", ["cookieConsistencyAction"], "recommended" if cookies else "conditional", "medium",
        "Session cookies must come back unchanged.", [f"cookies observed: {', '.join(cookies) or 'none (anonymous scan)'}"], objects={"cookie_names": cookies},
        notes=[] if cookies else ["No cookie was set without logging in. Re-scan with an authenticated live-browser capture before deciding."])
    add("buffer_overflow", "Buffer overflow", ["bufferOverflowAction"], "recommended", "low", "Generic length limits for URL, headers and cookies.", ["applies to every HTTP application"],
        objects={"max_url_length": 1024, "max_header_length": 4096, "max_cookie_length": 4096}, notes=["Review the limits against the longest legitimate URL or cookie before enforcing."])
    prone = [s for s in injection_surface if s.get("fields")]
    add("html_injection", "HTML SQL / XSS / command injection", ["SQLInjectionAction", "crossSiteScriptingAction"], "recommended" if (static_forms or prone) else "conditional", "medium",
        "Input fields that commonly reach SQL, LDAP or command contexts are inspected.", [f"{len(prone)} injection-prone endpoints or control groups"],
        objects={"fields": [{"endpoint": s.get("endpoint"), "fields": s.get("fields", [])[:10], "roles": s.get("roles", [])} for s in prone[:40]]},
        notes=["Learning produces the relaxation rules; enable transform-special-characters only after reviewing them."])
    add("json_injection", "JSON SQL / XSS / command injection", ["JSONSQLInjectionAction", "JSONXSSAction", "JSONCMDInjectionAction"], "recommended" if api else "not-applicable", "medium",
        "JSON request bodies are inspected for the same injection classes.", [f"{len(profile.get('api_endpoints') or [])} API calls observed"],
        notes=["Requires a profile of type JSON (or HTML+JSON) and a NetScaler release that supports the JSON checks."])
    card = [f for f in fields if f.get("role") == "card"]
    add("credit_card", "Credit card", ["creditCardAction"], "conditional" if card else "not-applicable", "low", "Detects card numbers in responses.",
        [f"{len(card)} card-like fields"] if card else ["no card field observed"])
    summary: dict[str, int] = {}
    for check in checks:
        summary[check["applicability"]] = summary.get(check["applicability"], 0) + 1
    return {"status": "proposal-only", "default_action": "LOG", "changes_applied": False, "summary": summary, "checks": checks,
            "application_style": "single-page application" if spa else "server-rendered" if static_forms else "unknown"}
