"""Pure helpers for the live (free-browsing) Browser Lab: request policy, metadata-only body
shapes and input-event mapping. No Playwright/FastAPI imports so they are unit-testable."""

from __future__ import annotations

import json
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.target_guard import scan_target_error

MODES = ("read_only", "free")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.:\[\]-]{0,127}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MAX_BODY_FIELDS = 100


def _path_in_scope(path: str, prefixes: list[str]) -> bool:
    normalized = path or "/"
    for prefix in prefixes or ["/"]:
        prefix = "/" + prefix.lstrip("/")
        if prefix == "/" or normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def live_request_allowed(mode: str, method: str, url: str, resource_type: str, hostname: str, allowed_paths: list[str]) -> bool:
    """Decide whether the live browser may send a request.

    read_only: scoped same-host GET/HEAD only.
    free: same-host any method (document navigations stay in the path scope); cross-host
    only GET/HEAD subresources so pages render, never cross-host navigations or writes.
    Platform-internal and reserved targets are refused in both modes.
    """
    if mode not in MODES:
        return False
    parsed = urlparse(url)
    if parsed.scheme.casefold() not in {"http", "https", "ws", "wss"}:
        return False
    if scan_target_error(url.replace("ws", "http", 1) if parsed.scheme.startswith("ws") else url, resolve=False):
        return False
    method = method.upper()
    same_host = (parsed.hostname or "").casefold() == hostname.casefold()
    in_scope = _path_in_scope(parsed.path or "/", allowed_paths)
    if mode == "read_only":
        return method in {"GET", "HEAD"} and same_host and in_scope
    if same_host:
        return in_scope if resource_type == "document" else True
    return method in {"GET", "HEAD"} and resource_type != "document"


def length_bucket(length: int) -> str:
    for limit, label in ((0, "0"), (8, "1-8"), (32, "9-32"), (128, "33-128"), (1024, "129-1024")):
        if length <= limit:
            return label
    return ">1024"


def value_class(value: Any) -> str:
    """Coarse class of a value. The value itself is never returned or stored."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    text = str(value)
    if not text:
        return "empty"
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return "number"
    if _UUID.match(text):
        return "uuid"
    if _EMAIL.match(text):
        return "email-like"
    if re.match(r"^https?://", text, re.IGNORECASE):
        return "url-like"
    return "short-text" if len(text) <= 64 else "long-text"


def _field(name: str, value: Any) -> dict[str, Any]:
    safe = name if SAFE_NAME.fullmatch(name) else "(invalid-name)"
    length = len(value) if isinstance(value, str) else len(json.dumps(value)) if isinstance(value, (list, dict)) else len(str(value))
    return {"name": safe[:128], "value_class": value_class(value), "length_bucket": length_bucket(length)}


def _flatten(prefix: str, value: Any, out: list[dict[str, Any]], depth: int) -> None:
    if len(out) >= MAX_BODY_FIELDS:
        return
    if isinstance(value, dict) and depth < 3:
        for key, child in value.items():
            _flatten(f"{prefix}.{key}" if prefix else str(key), child, out, depth + 1)
    elif prefix:
        out.append(_field(prefix, value))


def post_body_shape(content_type: str, body: str | None) -> dict[str, Any]:
    """Return field names with value class and length bucket only. The body is discarded."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    fields: list[dict[str, Any]] = []
    if body is None or body == "":
        return {"format": "none", "fields": []}
    if media == "application/x-www-form-urlencoded":
        for key, value in parse_qsl(body, keep_blank_values=True)[:MAX_BODY_FIELDS]:
            fields.append(_field(key, value))
        return {"format": "form", "fields": fields}
    if media.endswith("json"):
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return {"format": "json-invalid", "fields": []}
        if isinstance(parsed, dict):
            _flatten("", parsed, fields, 0)
        else:
            fields.append({"name": "(root)", "value_class": value_class(parsed), "length_bucket": length_bucket(len(body))})
        return {"format": "json", "fields": fields}
    if media.startswith("multipart/"):
        names = re.findall(r';\s*name="([^"]{1,128})"', body[:200_000])
        return {"format": "multipart", "fields": [{"name": n if SAFE_NAME.fullmatch(n) else "(invalid-name)", "value_class": "unknown", "length_bucket": "unknown"} for n in dict.fromkeys(names)][:MAX_BODY_FIELDS]}
    return {"format": "other", "fields": []}


_MOUSE_ACTIONS = {"move": "mouseMoved", "down": "mousePressed", "up": "mouseReleased", "wheel": "mouseWheel"}
_BUTTONS = {0: "left", 1: "middle", 2: "right"}


def _clamp(value: Any, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return max(low, min(high, number))


def mouse_to_cdp(message: dict[str, Any]) -> dict[str, Any] | None:
    cdp_type = _MOUSE_ACTIONS.get(str(message.get("action", "")))
    if not cdp_type:
        return None
    params: dict[str, Any] = {
        "type": cdp_type,
        "x": _clamp(message.get("x"), 0, 4096),
        "y": _clamp(message.get("y"), 0, 4096),
        "modifiers": int(_clamp(message.get("modifiers"), 0, 15)),
    }
    if cdp_type in {"mousePressed", "mouseReleased"}:
        params["button"] = _BUTTONS.get(int(_clamp(message.get("button"), 0, 2)), "left")
        params["clickCount"] = int(_clamp(message.get("click_count", 1), 1, 3))
    if cdp_type == "mouseWheel":
        params["deltaX"] = _clamp(message.get("delta_x"), -5000, 5000)
        params["deltaY"] = _clamp(message.get("delta_y"), -5000, 5000)
    return params


def key_to_cdp(message: dict[str, Any]) -> dict[str, Any] | None:
    """Map a browser KeyboardEvent summary to Input.dispatchKeyEvent parameters."""
    action = str(message.get("action", ""))
    if action not in {"down", "up"}:
        return None
    key = str(message.get("key", ""))[:32]
    code = str(message.get("code", ""))[:32]
    modifiers = int(_clamp(message.get("modifiers"), 0, 15))
    params: dict[str, Any] = {
        "type": "keyDown" if action == "down" else "keyUp",
        "key": key, "code": code, "modifiers": modifiers,
        "windowsVirtualKeyCode": int(_clamp(message.get("key_code"), 0, 255)),
    }
    printable = len(key) == 1 and not (modifiers & 0b0111)  # alt/ctrl/meta suppress text
    if action == "down" and printable:
        params["text"] = key
        params["unmodifiedText"] = key
    elif action == "down" and key == "Enter":
        params["text"] = "\r"
    return params


def new_live_session_id() -> str:
    return f"live-{uuid.uuid4()}"


def redact_url(value: str) -> str:
    """Drop query/fragment values; keep parameter names."""
    from urllib.parse import urlencode, urlunparse

    parsed = urlparse(value)
    query = urlencode([(key, "REDACTED") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))
