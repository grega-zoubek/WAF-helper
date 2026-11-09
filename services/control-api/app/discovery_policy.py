"""Discovery permissions: an administrator-selectable action catalog, deterministic request
classification and a per-run policy snapshot.

Pure functions only (no FastAPI/Playwright), so they are unit-testable. This file is copied
verbatim into services/control-api/app (parity test in tests/test_discovery_policy.py).

Rules that matter:
* A policy can only narrow what the target guard and session mode already allow; it never widens it.
* State-changing and probe categories are OFF unless a preset or the administrator enables them.
* Classification is deterministic from method, path, content type and body *shape*. Page content
  and model output never take part, so a page cannot talk its way into more permission.
* A request that cannot be classified is "ambiguous": by default it is held back (blocked and
  recorded for the operator) instead of inheriting a broad permission.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

POLICY_VERSION = 1

# id -> (label, changes state on the target)
CATEGORIES: dict[str, tuple[str, bool]] = {
    "navigation_read": ("Page navigation and read-only inspection", False),
    "search_filter": ("Search, filtering, sorting and pagination", False),
    "auth_session": ("Login, logout, SSO/MFA handoff and role switching", True),
    "form_submit": ("Form filling and submission", True),
    "registration": ("Registration and account creation", True),
    "file_transfer": ("File upload and download", True),
    "record_write": ("Record creation, editing and deletion", True),
    "checkout": ("Cart, checkout and payment-related journeys (test payment paths only)", True),
    "external_effect": ("Email, webhook and other external side effects (test sinks only)", True),
    "boundary_test": ("Boundary tests: empty values, lengths, Unicode, encodings, alternative types", True),
    "security_probe": ("Fixed security-probe families: SQLi, XSS, traversal, malformed JSON/XML", True),
}
# Categories no traffic classifier can recognise: they are chosen by the tool that generates the
# request, never inferred from a request that happened to go by.
TOOL_DECLARED = {"boundary_test", "security_probe"}

PRESETS: dict[str, dict[str, Any]] = {
    # GET requests carrying search/sort/page parameters are ordinary page loads, so read_only keeps them.
    "read_only": {"actor": "automated", "enabled": ["navigation_read", "search_filter"], "ambiguous": "pause"},
    "automated_default": {"actor": "automated", "enabled": ["navigation_read", "search_filter"], "ambiguous": "pause"},
    # A person is driving the mouse: everything a request can reveal is allowed. Probes stay off.
    "operator_free": {
        "actor": "operator",
        "enabled": [c for c in CATEGORIES if c not in TOOL_DECLARED],
        "ambiguous": "allow",
    },
}

DEFAULT_BUDGETS = {"max_requests": 5000, "max_actions": 1000, "max_seconds": 3600}
BUDGET_CEILINGS = {"max_requests": 50_000, "max_actions": 10_000, "max_seconds": 14_400}

_TOKEN = re.compile(r"[A-Za-z][a-z0-9]*|[0-9]+")
_AUTH = {"login", "signin", "authenticate", "authentication", "auth", "token", "oauth", "oidc", "saml", "sso", "mfa", "otp", "2fa", "session", "sessions", "logout", "signout", "impersonate", "switchrole"}
_REGISTER = {"register", "registration", "signup", "enroll", "enrol"}
_UPLOAD = {"upload", "uploads", "attachment", "attachments", "import"}
_DOWNLOAD = {"download", "downloads", "export"}
_CHECKOUT = {"cart", "basket", "baskets", "checkout", "order", "orders", "payment", "payments", "pay", "purchase", "billing", "coupon", "wallet"}
_EXTERNAL = {"mail", "email", "emails", "notify", "notification", "notifications", "webhook", "webhooks", "contact", "invite", "invitation", "sms", "message", "messages", "newsletter", "feedback", "subscribe"}
_WRITE_WORDS = {"create", "add", "new", "update", "edit", "delete", "remove", "save", "change", "modify", "set", "reset"}
_SEARCH_WORDS = {"search", "filter", "query", "lookup", "find", "suggest", "autocomplete"}
_SEARCH_PARAMS = {"q", "query", "search", "s", "keyword", "keywords", "term", "filter", "sort", "order", "orderby", "sortby", "page", "pagesize", "limit", "offset", "per_page", "size"}
_DOWNLOAD_EXT = (".pdf", ".zip", ".csv", ".xlsx", ".xls", ".docx", ".doc", ".tar", ".gz", ".7z", ".bak", ".sql")


def _tokens(path: str) -> set[str]:
    found = {token.lower() for token in _TOKEN.findall(path)}
    return found | {token[:-1] for token in found if len(token) > 3 and token.endswith("s")}  # Feedbacks -> feedback


def classify_request(method: str, url: str, content_type: str = "", body_format: str = "", resource_type: str = "") -> tuple[str | None, str]:
    """Return (category, reason). category is None when the request is ambiguous."""
    method = method.upper()
    parsed = urlparse(url)
    path = parsed.path or "/"
    tokens = _tokens(path)
    media = (content_type or "").split(";", 1)[0].strip().lower()

    if method in {"GET", "HEAD", "OPTIONS"}:
        if tokens & {"logout", "signout"}:
            return "auth_session", "logout path"
        if tokens & _DOWNLOAD or path.lower().endswith(_DOWNLOAD_EXT):
            return "file_transfer", "download path or file type"
        names = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        if names & _SEARCH_PARAMS or tokens & _SEARCH_WORDS:
            return "search_filter", "search/filter parameters"
        return "navigation_read", "read-only request"

    if tokens & {"logout", "signout"} or tokens & _AUTH:
        return "auth_session", "authentication path"
    if tokens & _REGISTER:
        return "registration", "registration path"
    if media.startswith("multipart/") or body_format == "multipart" or tokens & _UPLOAD:
        return "file_transfer", "multipart body or upload path"
    if tokens & _CHECKOUT:
        return "checkout", "cart/checkout/payment path"
    if tokens & _EXTERNAL:
        return "external_effect", "message/notification path"
    if method == "DELETE":
        return "record_write", "DELETE"
    if method in {"PUT", "PATCH"}:
        return "record_write", method
    if method == "POST":
        if tokens & _SEARCH_WORDS and not tokens & _WRITE_WORDS:
            return "search_filter", "POST search"
        if tokens & _WRITE_WORDS:
            return "record_write", "write verb in path"
        if resource_type == "document" and body_format in {"form", "none", ""}:
            return "form_submit", "HTML form submission"
    return None, "state-changing request with no recognisable intent"


def _clean_prefixes(values: Any) -> list[str]:
    out: list[str] = []
    for value in values if isinstance(values, list) else []:
        text = str(value).strip()
        if text.startswith("/") and len(text) <= 256 and ".." not in text:
            out.append(text)
    return out[:50]


def build_policy(preset: str | None = None, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate and normalise a policy. Raises ValueError for unknown names."""
    name = preset or "automated_default"
    if name not in PRESETS:
        raise ValueError(f"Unknown preset: {name}")
    base = PRESETS[name]
    overrides = overrides or {}
    enabled = overrides.get("enabled", base["enabled"])
    if not isinstance(enabled, list):
        raise ValueError("enabled must be a list of category ids")
    unknown = sorted({str(item) for item in enabled} - set(CATEGORIES))
    if unknown:
        raise ValueError(f"Unknown categories: {', '.join(unknown)}")
    ambiguous = overrides.get("ambiguous", base["ambiguous"])
    if ambiguous not in {"allow", "pause"}:
        raise ValueError("ambiguous must be 'allow' or 'pause'")
    actor = overrides.get("actor", base["actor"])
    if actor not in {"operator", "automated"}:
        raise ValueError("actor must be 'operator' or 'automated'")
    # Automated actors never get silent ambiguity: that is the point of pausing for the operator.
    if actor == "automated" and ambiguous == "allow":
        raise ValueError("Automated runs cannot allow ambiguous actions")
    budgets = dict(DEFAULT_BUDGETS)
    for key, value in (overrides.get("budgets") or {}).items():
        if key not in DEFAULT_BUDGETS:
            raise ValueError(f"Unknown budget: {key}")
        budgets[key] = max(1, min(int(value), BUDGET_CEILINGS[key]))
    scopes_in = overrides.get("route_scopes") or {}
    scopes: dict[str, list[str]] = {}
    for category, prefixes in scopes_in.items():
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category in route_scopes: {category}")
        scopes[category] = _clean_prefixes(prefixes)
    return {
        "version": POLICY_VERSION, "preset": name, "actor": actor,
        "enabled": sorted(set(map(str, enabled))), "route_scopes": scopes,
        "ambiguous": ambiguous, "budgets": budgets,
    }


def policy_fingerprint(policy: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def _in_scope(path: str, prefixes: list[str]) -> bool:
    return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") or p == "/" for p in prefixes)


def decide(policy: dict[str, Any], category: str | None, path: str) -> dict[str, str]:
    """Return {"action": "allow"|"deny"|"pause", "reason": ...} for one classified request."""
    if category is None:
        if policy.get("ambiguous") == "allow":
            return {"action": "allow", "reason": "ambiguous request allowed for an operator-driven session"}
        return {"action": "pause", "reason": "ambiguous request held for operator classification"}
    if category not in CATEGORIES:
        return {"action": "deny", "reason": "unknown category"}
    if category not in policy.get("enabled", []):
        return {"action": "deny", "reason": f"category '{category}' is not enabled for this run"}
    scope = (policy.get("route_scopes") or {}).get(category)
    if scope and not _in_scope(path or "/", scope):
        return {"action": "deny", "reason": f"category '{category}' is not enabled for this route"}
    return {"action": "allow", "reason": "category enabled"}


class Budget:
    """Counts requests and actions against the policy limits. Not thread-safe by design:
    a session owns exactly one and touches it from the event loop."""

    def __init__(self, limits: dict[str, int]) -> None:
        self.limits = limits
        self.requests = 0
        self.actions = 0

    def charge_request(self) -> bool:
        self.requests += 1
        return self.requests <= self.limits["max_requests"]

    def charge_action(self) -> bool:
        self.actions += 1
        return self.actions <= self.limits["max_actions"]

    def snapshot(self) -> dict[str, int]:
        return {"requests": self.requests, "actions": self.actions, **{f"limit_{k}": v for k, v in self.limits.items()}}


def describe_catalog() -> list[dict[str, Any]]:
    return [{"id": key, "label": label, "changes_state": changes, "default_enabled": key in PRESETS["automated_default"]["enabled"], "tool_declared": key in TOOL_DECLARED}
            for key, (label, changes) in CATEGORIES.items()]
