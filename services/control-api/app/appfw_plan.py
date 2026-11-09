"""Turn security-check recommendations into a LOG-mode plan preview.

Nothing here is sent to an appliance. Commands are previews for review; their syntax is marked
unverified until it has been checked against the lab appliance (`set appfw profile ?`).
"""

from __future__ import annotations

import re
from typing import Any

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}$")
ACTION_ARGS = "log stats learn"
LEARNABLE = {"startURLAction", "contentTypeAction", "fieldFormatAction", "fieldConsistencyAction", "CSRFtagAction", "cookieConsistencyAction",
             "SQLInjectionAction", "crossSiteScriptingAction", "JSONSQLInjectionAction", "JSONXSSAction", "JSONCMDInjectionAction"}


def default_profile_name(hostname: str) -> str:
    base = re.sub(r"[^a-z0-9-]+", "-", str(hostname or "app").casefold()).strip("-") or "app"
    return f"waf-chk-{base}"[:31].rstrip("-.")


def build_plan_preview(recommendations: dict[str, Any], profile_name: str) -> dict[str, Any]:
    if not PROFILE_NAME_RE.fullmatch(profile_name):
        raise ValueError("Invalid profile name")
    commands: list[dict[str, Any]] = []
    relaxations: list[dict[str, Any]] = []
    for check in recommendations.get("checks", []):
        if check.get("applicability") != "recommended":
            continue
        for setting in check.get("profile_settings", []):
            args = ACTION_ARGS if setting in LEARNABLE else "log stats"
            commands.append({"check_id": check["check_id"], "command": f"set appfw profile {profile_name} -{setting} {args}", "purpose": f"{check['name']}: log and learn, never block", "syntax": "unverified"})
        objects = check.get("proposed_objects") or {}
        for pattern in objects.get("start_url_patterns", []):
            relaxations.append({"check_id": "start_url", "kind": "startURL", "value": pattern, "syntax": "unverified"})
        for field in objects.get("fields", []) if check["check_id"] == "field_formats" else []:
            relaxations.append({"check_id": "field_formats", "kind": "fieldFormat", **{k: field.get(k) for k in ("form", "field", "suggested_type")}, "syntax": "unverified"})
    return {
        "status": "preview-only", "changes_applied": False, "executed": False, "profile_name": profile_name, "action": "LOG",
        "commands": commands, "relaxations": relaxations[:300], "relaxation_count": len(relaxations),
        "warnings": ["Preview only: nothing is sent to an appliance and no write route exists for this plan.",
                     "Command and binding syntax is unverified; confirm each line with `?` help on the lab ADC before use.",
                     "Keep every action in LOG and let learning produce relaxations before any promotion."],
    }
