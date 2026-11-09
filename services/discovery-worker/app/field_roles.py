"""Deterministic, explainable classification of data-entry controls.

Input is control metadata only (type, name, id, label, autocomplete ...). No values are
ever seen. The result names the role, the signals that produced it, whether the field is a
likely injection target (a passive pointer for WAF review, not a test) and a sensitivity.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

ROLES = ("search", "username", "password", "email", "phone", "card", "otp", "file", "csrf-token", "captcha",
         "numeric", "date", "url", "choice", "free-text", "hidden", "other")

# Roles whose values commonly reach SQL, LDAP, command or template contexts.
INJECTION_PRONE = {"search", "username", "email", "phone", "free-text", "numeric", "url"}
SENSITIVITY = {"password": "credential", "otp": "credential", "csrf-token": "secret", "card": "secret",
               "email": "personal", "phone": "personal", "username": "personal"}
_NON_FIELD_TYPES = {"button", "submit", "reset", "image"}


def _words(text: str) -> str:
    # split camelCase and separators so "userName", "user_name" and "user-name" compare alike
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return " " + re.sub(r"[^a-z0-9]+", " ", spaced.lower()).strip() + " "


def _has(text: str, *tokens: str) -> bool:
    return any(f" {token} " in text for token in tokens)


def classify_field(control: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return {"role", "signals", "injection_prone", "sensitivity"} or None for non-fields (buttons)."""
    tag = str(control.get("tag") or "").casefold()
    kind = str(control.get("type") or "").casefold()
    auto = str(control.get("autocomplete") or "").casefold()
    if kind in _NON_FIELD_TYPES or tag == "button":
        return None
    text = _words(" ".join(str(control.get(k) or "") for k in ("name", "id", "label", "placeholder", "aria_label")))
    signals: list[str] = []

    def done(role: str, *why: str) -> dict[str, Any]:
        signals.extend(why)
        return {"role": role, "signals": signals, "injection_prone": role in INJECTION_PRONE, "sensitivity": SENSITIVITY.get(role, "unknown")}

    if kind == "file":
        return done("file", "type=file" + (f" accept={control.get('accept')}" if control.get("accept") else ""))
    if kind == "password" or auto in {"current-password", "new-password"}:
        return done("password", "type=password" if kind == "password" else f"autocomplete={auto}")
    if kind == "hidden":
        if _has(text, "csrf", "xsrf", "token", "authenticity", "nonce", "csrfmiddlewaretoken"):
            return done("csrf-token", "hidden field named like an anti-forgery token")
        return done("hidden", "type=hidden")
    if auto == "one-time-code" or _has(text, "otp", "totp", "mfa", "2fa", "verification code", "security code"):
        return done("otp", "one-time-code signal")
    if auto.startswith("cc-") or _has(text, "card number", "cardnumber", "ccnum", "cvv", "cvc", "pan", "iban"):
        return done("card", "payment-card signal")
    if _has(text, "captcha"):
        return done("captcha", "name/label mentions captcha")
    if kind == "email" or auto == "email" or _has(text, "email", "e mail"):
        return done("email", "type=email" if kind == "email" else "email in name/label")
    if kind == "tel" or auto.startswith("tel") or _has(text, "phone", "mobile", "tel", "telephone"):
        return done("phone", "phone signal")
    if kind == "search" or kind == "search-component" or tag.endswith("search-bar") or _has(text, "search", "query", "keyword", "find", "q"):
        return done("search", "search type/component" if kind in {"search", "search-component"} else "search in name/label")
    if auto == "username" or _has(text, "username", "user name", "user", "login", "uname", "account"):
        return done("username", "username signal")
    if kind in {"date", "datetime-local", "month", "week", "time"} or _has(text, "date", "birthday", "dob"):
        return done("date", f"type={kind}" if kind else "date in name/label")
    if kind in {"number", "range"} or str(control.get("inputmode") or "").casefold() in {"numeric", "decimal"} or _has(text, "id", "qty", "quantity", "amount", "count", "page", "limit", "offset", "age", "zip", "postcode"):
        return done("numeric", f"type={kind}" if kind in {"number", "range"} else "numeric name/inputmode")
    if kind == "url" or _has(text, "url", "website", "link"):
        return done("url", "url signal")
    if kind in {"checkbox", "radio"} or tag == "select":
        return done("choice", f"{kind or tag} control")
    if tag == "textarea" or kind in {"text", ""} and tag in {"input", "textarea", ""}:
        return done("free-text", "textarea" if tag == "textarea" else "plain text input")
    return done("other", f"type={kind or tag or 'unknown'}")


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def template_path(path: str) -> str:
    """Turn concrete identifiers in a URL path into a template: /product/42 -> /product/{id:int}."""
    parts = []
    seen: dict[str, int] = {}
    for segment in path.split("/"):
        if _UUID.match(segment):
            kind = "uuid"
        elif re.fullmatch(r"\d{1,18}", segment):
            kind = "int"
        else:
            parts.append(segment)
            continue
        seen[kind] = seen.get(kind, 0) + 1
        parts.append("{id:%s}" % kind if seen[kind] == 1 else "{id%d:%s}" % (seen[kind], kind))
    return "/".join(parts)
