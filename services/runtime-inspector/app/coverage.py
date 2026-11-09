"""Coverage report for a browsing run. A page that did not load, or loaded without its scripts
and styles, is a coverage failure and is never reported as explored.

Pure function over already-redacted capture data (no values, bodies or cookies)."""

from __future__ import annotations

from typing import Any

ASSET_TYPES = {"script", "stylesheet", "font", "image", "media"}
SCRIPT_LIKE = {"script", "stylesheet"}
MAX_FAILURES = 100

# severity decides the overall status: any "critical" -> failed, any other failure -> degraded
SEVERITY = {
    "load_error": "critical", "no_document": "critical",
    "asset_redirect": "major", "mime_mismatch": "major", "application_error": "major", "failed_asset": "minor",
    "blocked_request": "minor", "permission_denied": "minor", "needs_classification": "major", "budget_exhausted": "major",
}


def _add(failures: dict[tuple[str, str], dict[str, Any]], kind: str, target: str, detail: str) -> None:
    key = (kind, target)
    entry = failures.get(key)
    if entry:
        entry["count"] += 1
    elif len(failures) < MAX_FAILURES:
        failures[key] = {"kind": kind, "severity": SEVERITY[kind], "target": target, "detail": detail, "count": 1}


def build_coverage(
    network: list[dict[str, Any]],
    *,
    load_error: str = "",
    blocked_hosts: dict[str, int] | None = None,
    permission_events: list[dict[str, Any]] | None = None,
    budget_exhausted: bool = False,
) -> dict[str, Any]:
    failures: dict[tuple[str, str], dict[str, Any]] = {}
    documents_ok = 0
    for item in network:
        status = item.get("status_code")
        rtype = item.get("resource_type", "")
        target = f"{item.get('method', 'GET')} {str(item.get('url', ''))[:200]}"
        ctype = str(item.get("response_content_type", "")).lower()
        if rtype == "document" and isinstance(status, int) and 200 <= status < 400:
            documents_ok += 1
        if rtype in SCRIPT_LIKE and isinstance(status, int) and 300 <= status < 400:
            _add(failures, "asset_redirect", target, f"{rtype} answered {status}; the page may render without it")
        elif rtype in SCRIPT_LIKE and isinstance(status, int) and status < 400 and ctype.startswith("text/html"):
            _add(failures, "mime_mismatch", target, f"{rtype} was served as text/html (often a login page or error page)")
        elif rtype in ASSET_TYPES and (status is None or (isinstance(status, int) and status >= 400)):
            _add(failures, "failed_asset", target, "no response recorded" if status is None else f"status {status}")
        elif rtype in {"document", "xhr", "fetch"} and isinstance(status, int) and status >= 500:
            _add(failures, "application_error", target, f"status {status}")
    for label, count in (blocked_hosts or {}).items():
        _add(failures, "blocked_request", label, "blocked by scope or session mode")
        failures[("blocked_request", label)]["count"] = count
    for event in permission_events or []:
        if event.get("action") == "pause":
            _add(failures, "needs_classification", f"{event.get('method', '')} {event.get('path', '')}", str(event.get("reason", "")))
        elif event.get("action") == "deny":
            _add(failures, "permission_denied", f"{event.get('method', '')} {event.get('path', '')} [{event.get('category')}]", str(event.get("reason", "")))
    if load_error:
        _add(failures, "load_error", "initial navigation", load_error)
    if documents_ok == 0:
        _add(failures, "no_document", "document", "no successful page load was recorded")
    if budget_exhausted:
        _add(failures, "budget_exhausted", "run budget", "request or action budget was reached; later activity was refused")

    ordered = sorted(failures.values(), key=lambda f: ({"critical": 0, "major": 1, "minor": 2}[f["severity"]], f["kind"]))
    severities = {f["severity"] for f in ordered}
    status = "failed" if "critical" in severities else "degraded" if ordered else "complete"
    counts: dict[str, int] = {}
    for failure in ordered:
        counts[failure["kind"]] = counts.get(failure["kind"], 0) + failure["count"]
    return {
        "status": status,
        "explored": status != "failed",
        "documents_loaded": documents_ok,
        "failure_counts": counts,
        "failures": ordered,
    }
