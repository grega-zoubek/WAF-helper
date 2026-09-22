"""Fail-closed policy helpers for one explicit guided-browser login POST."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _allowed_path(path: str, prefixes: list[str]) -> bool:
    normalized = path or "/"
    for prefix in prefixes or ["/"]:
        prefix = "/" + prefix.lstrip("/")
        if prefix == "/" or normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def validated_login_target(
    page_url: str,
    form_method: str,
    form_action: str,
    hostname: str,
    allowed_paths: list[str],
) -> tuple[str, str]:
    """Return (origin, path) only for a same-origin HTTPS POST in scope."""
    page = urlparse(page_url)
    action = urlparse(form_action)
    if page.scheme.casefold() != "https" or action.scheme.casefold() != "https":
        raise ValueError("Authentication requires an HTTPS page and form action")
    if form_method.upper() != "POST":
        raise ValueError("The selected login form must use POST")
    if page.username or page.password or action.username or action.password:
        raise ValueError("Credentials in browser URLs are not allowed")
    if (page.hostname or "").casefold() != hostname.casefold() or (action.hostname or "").casefold() != hostname.casefold():
        raise ValueError("The login page and form must remain on the selected host")
    try:
        page_port = page.port or 443
        action_port = action.port or 443
    except ValueError as exc:
        raise ValueError("Invalid login origin") from exc
    if page_port != action_port:
        raise ValueError("The login form must use the same origin")
    if action.query or action.fragment:
        raise ValueError("Login form actions must not contain query strings or fragments")
    path = action.path or "/"
    if not _allowed_path(path, allowed_paths):
        raise ValueError("The login form action is outside the selected path scope")
    origin = f"https://{action.netloc.lower()}"
    return origin, path


def guided_request_allowed(method: str, url: str, hostname: str, allowed_paths: list[str], session: dict[str, Any]) -> bool:
    """Allow normal scoped GET/HEAD, plus exactly one armed matching login POST."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    same_host = (parsed.hostname or "").casefold() == hostname.casefold()
    in_scope = parsed.scheme.casefold() in {"http", "https"} and same_host and _allowed_path(path, allowed_paths)
    method = method.upper()
    if method in {"GET", "HEAD"}:
        if not in_scope:
            return False
        if session.get("auth_post_used") or session.get("auth_state") in {"authenticated", "role-specific"}:
            expected = session.get("auth_post_target") or {}
            return parsed.scheme.casefold() == "https" and f"https://{parsed.netloc.lower()}" == expected.get("origin")
        return True
    expected = session.get("auth_post_target") or {}
    if (
        method == "POST"
        and session.get("auth_post_pending") is True
        and session.get("auth_post_used") is not True
        and in_scope
        and parsed.scheme.casefold() == "https"
        and not parsed.query
        and not parsed.fragment
        and f"https://{parsed.netloc.lower()}" == expected.get("origin")
        and path == expected.get("path")
    ):
        session["auth_post_pending"] = False
        session["auth_post_used"] = True
        return True
    return False
