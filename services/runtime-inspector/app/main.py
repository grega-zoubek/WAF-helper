from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from playwright.async_api import Browser, TimeoutError as PlaywrightTimeoutError, async_playwright
from pydantic import BaseModel, Field, SecretStr

from app.auth_journey import guided_request_allowed, validated_login_target

app = FastAPI(title="WAF Runtime Inspector", version="0.2.0")
inspection_lock = asyncio.Lock()
browser_lab_lock = asyncio.Lock()
browser_sessions: dict[str, dict[str, Any]] = {}
guided_browser: Browser | None = None
guided_playwright: Any = None
GUIDED_SESSION_TTL_SECONDS = 900
MAX_GUIDED_SESSIONS = 5
MAX_NETWORK_EVENTS = 200
MAX_INTERACTION_EVENTS = 100
GUIDED_CORRELATION_WINDOW_SECONDS = 2.0
SENSITIVE_FIELD_NAME_RE = re.compile(r"(?:pass(?:word)?|secret|token|credential|authorization|api[_-]?key|session|csrf|xsrf|username|user[_-]?id|email|otp|one[_-]?time)", re.I)
INTERESTING_NETWORK_MARKERS = ("/api/", "/auth", "/login", "/signin", "/oauth", "/token", "/graphql", "/rest/", "/user")
SAFE_RESPONSE_HEADERS = {
    "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy",
    "cache-control", "content-type", "location", "www-authenticate",
}
SAFE_RESPONSE_HEADER_NAMES = SAFE_RESPONSE_HEADERS | {"content-security-policy", "content-security-policy-report-only"}


def is_same_host(value: str, hostname: str) -> bool:
    return (urlparse(value).hostname or "").lower() == hostname.lower()


def is_interesting_request(url: str, resource_type: str) -> bool:
    path = urlparse(url).path.lower()
    return resource_type in {"document", "xhr", "fetch"} or any(marker in path for marker in INTERESTING_NETWORK_MARKERS)


def safe_headers(headers: dict[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized = key.lower()
        if normalized not in SAFE_RESPONSE_HEADERS:
            continue
        safe_value = redact_url(value) if normalized == "location" else value
        result[normalized] = safe_value[:500]
    return result


def classify_auth_surface(source_url: str, final_url: str, controls: list[dict[str, Any]], headings: list[str], markers: list[str], buttons: list[str]) -> dict[str, Any]:
    route_text = f"{source_url} {final_url}".casefold()
    control_text = " ".join(
        f"{item.get('type', '')} {item.get('name', '')} {item.get('id', '')} {item.get('aria_label', '')} {item.get('placeholder', '')} {item.get('autocomplete', '')}"
        for item in controls
    ).casefold()
    text = " ".join(headings).casefold()
    password_count = sum(1 for item in controls if str(item.get("type", "")).casefold() == "password")
    identifier_count = sum(
        1 for item in controls
        if str(item.get("tag", "")).casefold() in {"input", "textarea", "select"}
        and any(token in " ".join(str(item.get(key, "")) for key in ("type", "name", "id", "aria_label", "placeholder", "autocomplete")).casefold() for token in ("username", "user-name", "email", "e-mail", "login"))
    )
    auth_tokens = ("login", "sign in", "signin", "password", "username", "register", "forgot password", "two-factor", "authentication")
    auth_text = f"{route_text} {control_text} {text}"
    auth_markers = sorted({token for token in auth_tokens if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", auth_text)})
    route_paths = [urlparse(source_url).fragment, urlparse(source_url).path, urlparse(final_url).fragment, urlparse(final_url).path]
    route_segments = {segment for path in route_paths for segment in re.split(r"[/#?&=]", path.casefold()) if segment}
    is_auth_route = bool(route_segments.intersection({"login", "signin", "sign-in", "register", "forgot-password", "change-password", "auth", "2fa", "two-factor-authentication"}))
    detected = bool(auth_markers or password_count or is_auth_route)
    classification = "login" if detected and (is_auth_route or password_count or "login" in auth_markers or "sign in" in auth_markers or "signin" in auth_markers) else "authentication-related"
    return {
        "detected": detected,
        "classification": classification if detected else "none",
        "route_match": is_auth_route,
        "markers": auth_markers,
        "password_field_count": password_count,
        "identifier_field_count": min(identifier_count, len(controls)),
        "submit_control_count": sum(1 for item in controls if str(item.get("type", "")).casefold() in {"submit", "button"}),
        "values_submitted": False,
    }


class InspectionRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=50)
    hostname: str = Field(min_length=1, max_length=253)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])


class GuidedSessionRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    hostname: str = Field(min_length=1, max_length=253)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"], max_length=100)
    ignore_https_errors: bool = False


class GuidedNavigateRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class GuidedSelectRequest(BaseModel):
    element_index: int = Field(ge=0, le=999)


class GuidedPointSelectRequest(BaseModel):
    x: float = Field(ge=0, le=4096)
    y: float = Field(ge=0, le=4096)


class GuidedAuthenticateRequest(BaseModel):
    username: SecretStr = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=512)
    username_index: int = Field(ge=0, le=999)
    password_index: int = Field(ge=0, le=999)
    submit_index: int = Field(ge=0, le=999)
    identity_label: str = Field(default="test-user", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    authorize_single_login_post: bool = False


def allowed_path(path: str, prefixes: list[str]) -> bool:
    normalized = path or "/"
    for prefix in prefixes or ["/"]:
        prefix = "/" + prefix.lstrip("/")
        if prefix == "/" or normalized == prefix.rstrip("/") or normalized.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def in_scope(value: str, request: InspectionRequest) -> bool:
    parsed = urlparse(value)
    logical_path = parsed.fragment if parsed.fragment.startswith("/") else parsed.path
    return bool(parsed.scheme in {"http", "https"} and parsed.hostname and parsed.hostname.lower() == request.hostname.lower() and allowed_path(logical_path, request.allowed_paths))


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    def redact_pairs(query: str) -> str:
        return "&".join(f"{part.split('=', 1)[0]}=REDACTED" if "=" in part else part for part in query.split("&"))

    query = redact_pairs(parsed.query) if parsed.query else ""
    fragment = parsed.fragment
    if "?" in fragment:
        head, fragment_query = fragment.split("?", 1)
        fragment = f"{head}?{redact_pairs(fragment_query)}"
    elif "=" in fragment:
        fragment = redact_pairs(fragment)
    return parsed._replace(query=query, fragment=fragment).geturl()


def redacted_route_template(value: str) -> str:
    parsed = urlparse(value)
    parts: list[str] = []
    for segment in parsed.path.split("/"):
        if segment.isdecimal():
            parts.append("{id:int}")
        else:
            try:
                import uuid
                uuid.UUID(segment)
                parts.append("{id:uuid}")
            except (ValueError, AttributeError):
                token_segment = (
                    len(segment) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+", segment)
                    and re.search(r"[A-Z]", segment) and re.search(r"[a-z]", segment) and re.search(r"\d", segment)
                ) or bool(re.fullmatch(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", segment))
                if token_segment:
                    parts.append("{path_segment}")
                else:
                    parts.append(segment)
    path = "/".join(parts) or "/"
    return path if path.startswith("/") else "/" + path


def correlate_focus_to_requests(
    element: dict[str, Any], event_started: float, requests: list[dict[str, Any]], hostname: str,
    resource_types: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Correlate metadata-only UI events to later safe same-host requests."""
    field_names = {str(element.get(key, "")).casefold() for key in ("name", "id")}
    field_names.discard("")
    correlated: list[dict[str, Any]] = []
    for item in requests:
        started = item.get("started_at")
        if not isinstance(started, (int, float)) or started < event_started:
            continue
        delta = started - event_started
        if delta > GUIDED_CORRELATION_WINDOW_SECONDS:
            continue
        if item.get("resource_type") not in (resource_types or {"xhr", "fetch"}) or not is_same_host(str(item.get("url", "")), hostname):
            continue
        parsed = urlparse(str(item.get("url", "")))
        query_names = {name.casefold() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        matched = sorted(field_names.intersection(query_names))
        correlated.append({
            "request_id": item.get("id"),
            "method": item.get("method"),
            "path_template": redacted_route_template(str(item.get("url", ""))),
            "matched_parameter_names": matched,
            "confidence": 0.7 if matched else 0.25,
            "time_delta_ms": round(delta * 1000),
            "reason": "DOM field name/id matches a query key on a subsequent safe request" if matched else "Safe same-host XHR/fetch occurred shortly after focus; field-level linkage is unconfirmed",
            "raw_values_captured": False,
        })
    return correlated[:20]


def validate_request(request: InspectionRequest) -> None:
    try:
        ipaddress.ip_address(request.hostname)
    except ValueError:
        if not request.hostname or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in request.hostname):
            raise HTTPException(status_code=422, detail="Runtime inspection hostname is invalid")
    if any(not in_scope(url, request) for url in request.urls):
        raise HTTPException(status_code=422, detail="Runtime inspection URL is outside the selected scope")


def validate_guided_request(request: GuidedSessionRequest, url: str | None = None) -> None:
    try:
        ipaddress.ip_address(request.hostname)
    except ValueError:
        if not request.hostname or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in request.hostname):
            raise HTTPException(status_code=422, detail="Guided browser hostname is invalid")
    target = url or request.url
    if urlparse(target).username or urlparse(target).password:
        raise HTTPException(status_code=422, detail="Credentials in browser URLs are not allowed")
    if not in_scope(target, InspectionRequest(urls=[target], hostname=request.hostname, allowed_paths=request.allowed_paths)):
        raise HTTPException(status_code=422, detail="Guided browser URL is outside the selected host/path scope")


async def guard_guided_route(route: Any, scope: InspectionRequest, session: dict[str, Any] | None = None) -> None:
    target = route.request.url
    was_used = bool(session and session.get("auth_post_used"))
    allowed = guided_request_allowed(route.request.method, target, scope.hostname, scope.allowed_paths, session or {})
    if not allowed:
        await route.abort("blockedbyclient")
        return
    if session and not was_used and session.get("auth_post_used"):
        session["auth_sequence_start"] = len(session.get("network_sequence", []))
    await route.continue_()


async def block_guided_websocket(websocket_route: Any) -> None:
    await websocket_route.close(code=1008, reason="WebSocket traffic is disabled in read-only browser sessions")


async def guided_snapshot(session: dict[str, Any]) -> dict[str, Any]:
    page = session["page"]
    await page.evaluate("""() => {
      if (document.getElementById('waf-intelligence-redaction-style')) return;
      const style = document.createElement('style');
      style.id = 'waf-intelligence-redaction-style';
      style.textContent = "input, textarea, select, [contenteditable='true'] { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; }";
      document.head.appendChild(style);
    }""")
    dom = await page.evaluate("""() => {
      const visible = el => { const s = getComputedStyle(el), r = el.getBoundingClientRect(); return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; };
      const controls = Array.from(document.querySelectorAll('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')).slice(0, 250).map((el, index) => ({
        index, tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
        effective_type: el.type || '',
        role: el.getAttribute('role') || '', aria_label: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
        required: el.hasAttribute('required'), disabled: el.hasAttribute('disabled'), autocomplete: el.getAttribute('autocomplete') || '',
        minlength: el.getAttribute('minlength') || '', maxlength: el.getAttribute('maxlength') || '', pattern: el.getAttribute('pattern') || '',
        form_id: el.form ? (el.form.id || el.form.getAttribute('name') || '') : '',
        form_method: el.form ? (el.form.method || 'get').toUpperCase() : '',
        form_action: el.form ? el.form.action : '',
        selector: el.id ? `#${CSS.escape(el.id)}` : `${el.tagName.toLowerCase()}${el.getAttribute('name') ? `[name="${CSS.escape(el.getAttribute('name'))}"]` : ''}`,
        labels: Array.from(el.labels || []).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120)),
        text: (el.innerText || el.getAttribute('title') || '').replace(/\\s+/g, ' ').trim().slice(0, 120), visible: visible(el)
      }));
      const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({text: (a.innerText || a.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim().slice(0, 120), href: a.href})).slice(0, 200);
      const forms = Array.from(document.forms).map(f => ({id: f.id || '', name: f.getAttribute('name') || '', action: f.action, method: (f.method || 'get').toUpperCase(), enctype: f.enctype || '', fields: f.elements.length, field_names: Array.from(f.elements).map(el => el.getAttribute('name') || '').filter(Boolean).slice(0, 100)})).slice(0, 50);
      return {title: document.title.slice(0, 250), viewport: {width: innerWidth, height: innerHeight}, headings: Array.from(document.querySelectorAll('h1,h2,h3,[role="heading"]')).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 180)).filter(Boolean).slice(0, 40), controls, links, forms};
    }""")
    requests = list(session["network_events"].values())[-200:]
    screenshot = await page.screenshot(type="jpeg", quality=55, full_page=False, timeout=5_000)
    session["touched"] = time.monotonic()
    return {
        "session_id": session["id"], "url": redact_url(page.url), "title": dom["title"], "status_code": session.get("status_code"),
        "viewport": dom["viewport"],
        "headings": dom["headings"], "controls": dom["controls"], "forms": [{**form, "action": redact_url(form["action"])} for form in dom["forms"]],
        "links": [{**link, "href": redact_url(link["href"])} for link in dom["links"] if is_same_host(link["href"], session["hostname"]) and allowed_path(urlparse(link["href"]).path, session["allowed_paths"])],
        "network_requests": requests, "screenshot_data_uri": "data:image/jpeg;base64," + base64.b64encode(screenshot).decode("ascii"),
        "authentication": {"state": session.get("auth_state", "anonymous"), "identity_label": session.get("identity_label", ""), "attempted": bool(session.get("auth_attempt_count")), "result": session.get("auth_result", "not-attempted")},
        "capture_policy": "same-host, in-scope GET/HEAD only except a separately authorized single HTTPS login POST; all other unsafe methods, WebSockets, downloads, request bodies, cookies, and raw field values are blocked or not captured",
        "values_submitted": bool(session.get("auth_post_used")),
    }


async def expire_guided_sessions() -> None:
    now = time.monotonic()
    expired = [key for key, item in browser_sessions.items() if now - item.get("touched", now) > GUIDED_SESSION_TTL_SECONDS]
    for key in expired:
        item = browser_sessions.pop(key)
        await item["context"].close()


async def inspect_page(browser: Browser, url: str) -> dict[str, Any]:
    page = await browser.new_page()
    hostname = urlparse(url).hostname or ""
    network_events: dict[tuple[str, str, str], dict[str, Any]] = {}

    def capture_request(request: Any) -> None:
        if not is_same_host(request.url, hostname) or not is_interesting_request(request.url, request.resource_type):
            return
        key = (request.method, redact_url(request.url), request.resource_type)
        if len(network_events) < MAX_NETWORK_EVENTS or key in network_events:
            network_events.setdefault(key, {
                "method": request.method,
                "url": redact_url(request.url),
                "resource_type": request.resource_type,
                "status_code": None,
            })

    def capture_response(response: Any) -> None:
        request = response.request
        key = (request.method, redact_url(request.url), request.resource_type)
        if key in network_events:
            network_events[key]["status_code"] = response.status
            network_events[key]["response_headers"] = safe_headers(response.headers)

    page.on("request", capture_request)
    page.on("response", capture_response)
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        await page.wait_for_timeout(750)
        dom = await page.evaluate("""() => ({
            visible: el => {
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
            },
            text: el => (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 200),
            forms: Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.getAttribute('action') || '',
                method: (form.getAttribute('method') || 'get').toUpperCase(),
                enctype: form.getAttribute('enctype') || '',
                id: form.getAttribute('id') || '',
                name: form.getAttribute('name') || '',
                visible: (() => { const rect = form.getBoundingClientRect(); const style = window.getComputedStyle(form); return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0; })(),
            })),
            controls: Array.from(document.querySelectorAll('input,button,select,textarea')).map(el => ({
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || '',
                name: el.getAttribute('name') || '',
                id: el.getAttribute('id') || '',
                required: el.hasAttribute('required'),
                autocomplete: el.getAttribute('autocomplete') || '',
                aria_label: el.getAttribute('aria-label') || '',
                placeholder: el.getAttribute('placeholder') || '',
                pattern: el.getAttribute('pattern') || '',
                inputmode: el.getAttribute('inputmode') || '',
                minlength: el.getAttribute('minlength') || '',
                maxlength: el.getAttribute('maxlength') || '',
                accept: el.getAttribute('accept') || '',
                role: el.getAttribute('role') || '',
                visible: (() => { const rect = el.getBoundingClientRect(); const style = window.getComputedStyle(el); return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0; })(),
                disabled: el.hasAttribute('disabled'),
                labels: Array.from(el.labels || []).map(label => (label.innerText || label.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 200)),
                text: (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 200)
            })),
            search_components: Array.from(document.querySelectorAll('*')).filter(el => el.tagName.toLowerCase().includes('search-bar')).map(el => ({
                tag: el.tagName.toLowerCase(),
                type: 'search-component',
                name: el.getAttribute('name') || '',
                id: el.getAttribute('id') || '',
                aria_label: el.getAttribute('aria-label') || ''
            })),
            links: Array.from(document.querySelectorAll('a[href]')).map(el => el.href).slice(0, 200),
            headings: Array.from(document.querySelectorAll('h1,h2,h3,[role="heading"]')).map(el => (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 200)).filter(Boolean).slice(0, 50),
            button_labels: Array.from(document.querySelectorAll('button,[role="button"]')).map(el => (el.innerText || el.getAttribute('aria-label') || el.getAttribute('title') || '').replace(/\\s+/g, ' ').trim().slice(0, 200)).filter(Boolean).slice(0, 100),
            visible_text_markers: Array.from(new Set(['login','sign in','signin','password','username','register','forgot password','change password','two-factor','authentication'].filter(marker => (document.body.innerText || '').toLowerCase().includes(marker)))),
            local_storage_keys: (() => { try { return Object.keys(localStorage).slice(0, 100); } catch (_) { return []; } })(),
            session_storage_keys: (() => { try { return Object.keys(sessionStorage).slice(0, 100); } catch (_) { return []; } })(),
            script_urls: Array.from(document.scripts).map(script => script.src).filter(Boolean).slice(0, 100),
            stylesheet_urls: Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map(link => link.href).filter(Boolean).slice(0, 100)
        })""")
        controls = dom.get("controls", [])
        search_components = dom.get("search_components", [])
        for component in search_components:
            if component not in controls:
                controls.append(component)
        for form in dom.get("forms", []):
            form["action"] = redact_url(form.get("action", ""))
        source_url = redact_url(url)
        final_url = redact_url(page.url)
        headings = dom.get("headings", [])[:50]
        button_labels = dom.get("button_labels", [])[:100]
        visible_text_markers = dom.get("visible_text_markers", [])[:30]
        auth_surface = classify_auth_surface(source_url, final_url, controls, headings, visible_text_markers, button_labels)
        requests = list(network_events.values())
        api_requests = [item for item in requests if item.get("resource_type") in {"xhr", "fetch"} or any(marker in urlparse(item.get("url", "")).path.lower() for marker in INTERESTING_NETWORK_MARKERS)]
        return {
            "source_url": source_url,
            "final_url": final_url,
            "status_code": response.status if response else None,
            "forms": dom.get("forms", [])[:50],
            "controls": controls[:200],
            "search_surfaces": search_components[:50],
            "links": [redact_url(link) for link in dom.get("links", [])[:200]],
            "headings": headings,
            "button_labels": button_labels,
            "visible_text_markers": visible_text_markers,
            "auth_surface": auth_surface,
            "network_requests": requests[:MAX_NETWORK_EVENTS],
            "api_requests": api_requests[:MAX_NETWORK_EVENTS],
            "storage_keys": {"local": dom.get("local_storage_keys", [])[:100], "session": dom.get("session_storage_keys", [])[:100]},
            "script_urls": [redact_url(item) for item in dom.get("script_urls", [])[:100]],
            "stylesheet_urls": [redact_url(item) for item in dom.get("stylesheet_urls", [])[:100]],
            "security_headers": safe_headers(response.headers if response else {}),
            "values_submitted": False,
        }
    except PlaywrightTimeoutError:
        return {"source_url": redact_url(url), "status_code": None, "forms": [], "controls": [], "search_surfaces": [], "links": [], "values_submitted": False, "error_type": "timeout"}
    finally:
        await page.close()


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "runtime-inspector", "mode": "render-and-inspect-only"}


@app.post("/inspect")
async def inspect(request: InspectionRequest) -> dict[str, Any]:
    validate_request(request)
    async with inspection_lock:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, executable_path="/usr/bin/chromium", args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                pages = [await inspect_page(browser, url) for url in request.urls]
            finally:
                await browser.close()
    return {"mode": "render-and-inspect-only", "values_submitted": False, "pages": pages}


@app.post("/guided/sessions", status_code=201)
async def start_guided_session(request: GuidedSessionRequest) -> dict[str, Any]:
    global guided_browser, guided_playwright
    validate_guided_request(request)
    async with browser_lab_lock:
        await expire_guided_sessions()
        if len(browser_sessions) >= MAX_GUIDED_SESSIONS:
            raise HTTPException(status_code=429, detail="Guided browser session limit reached")
        if guided_playwright is None:
            guided_playwright = await async_playwright().start()
        if guided_browser is None or not guided_browser.is_connected():
            guided_browser = await guided_playwright.chromium.launch(headless=True, executable_path="/usr/bin/chromium", args=["--no-sandbox", "--disable-dev-shm-usage"])
        context = await guided_browser.new_context(viewport={"width": 1365, "height": 900}, accept_downloads=False, service_workers="block", ignore_https_errors=request.ignore_https_errors)
        page = await context.new_page()
        scope = InspectionRequest(urls=[request.url], hostname=request.hostname, allowed_paths=request.allowed_paths)
        session_id = str(uuid4())
        session: dict[str, Any] = {
                "id": session_id, "context": context, "page": page, "hostname": request.hostname.lower(),
                "allowed_paths": request.allowed_paths or ["/"], "network_events": {}, "network_sequence": [],
                "interaction_events": [], "selected_elements": [], "status_code": None,
                "auth_attempt_count": 0, "auth_state": "anonymous", "identity_label": "",
                "auth_post_pending": False, "auth_post_used": False, "auth_post_target": None,
                "auth_response_status": None, "auth_response_event": None,
                "created": time.monotonic(), "touched": time.monotonic(),
        }
        async def guarded_route(route: Any) -> None:
            await guard_guided_route(route, scope, session)

        await context.route("**/*", guarded_route)
        await context.route_web_socket("**/*", block_guided_websocket)
        def record_request(browser_request: Any) -> None:
                if browser_request.method.upper() not in {"GET", "HEAD"} or not in_scope(browser_request.url, scope):
                    return
                key = (browser_request.method, redact_url(browser_request.url), browser_request.resource_type)
                event_item = {
                    "id": str(uuid4()), "method": browser_request.method,
                    "url": redact_url(browser_request.url), "resource_type": browser_request.resource_type,
                    "authentication": session.get("auth_state", "anonymous"),
                    "status_code": None, "started_at": time.monotonic(),
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "request_header_names": sorted(str(name).lower()[:128] for name in browser_request.headers.keys())[:100],
                    "response_header_names": [],
                }
                session["network_sequence"].append(event_item)
                session["network_sequence"] = session["network_sequence"][-MAX_NETWORK_EVENTS:]
                if len(session["network_events"]) < MAX_NETWORK_EVENTS or key in session["network_events"]:
                    session["network_events"].setdefault(key, {"method": browser_request.method, "url": redact_url(browser_request.url), "resource_type": browser_request.resource_type, "status_code": None})

        def record_response(browser_response: Any) -> None:
                browser_request = browser_response.request
                if browser_request.method.upper() == "POST" and session.get("auth_post_used"):
                    expected = session.get("auth_post_target") or {}
                    parsed = urlparse(browser_request.url)
                    if f"{parsed.scheme}://{parsed.netloc.lower()}" == expected.get("origin") and parsed.path == expected.get("path"):
                        session["auth_response_status"] = browser_response.status
                        response_event = session.get("auth_response_event")
                        if response_event:
                            response_event.set()
                    return
                safe_response_headers = safe_headers(browser_response.headers)
                response_header_names = sorted(str(name).lower()[:128] for name in browser_response.headers.keys() if str(name).lower() in SAFE_RESPONSE_HEADER_NAMES)
                for sequence_item in reversed(session["network_sequence"]):
                    if (sequence_item["method"] == browser_request.method
                            and sequence_item["url"] == redact_url(browser_request.url)
                            and sequence_item["resource_type"] == browser_request.resource_type
                            and sequence_item["status_code"] is None):
                        sequence_item["status_code"] = browser_response.status
                        sequence_item["response_content_type"] = safe_response_headers.get("content-type", "").split(";", 1)[0][:128]
                        sequence_item["response_header_names"] = response_header_names
                        break
                key = (browser_request.method, redact_url(browser_request.url), browser_request.resource_type)
                if key in session["network_events"]:
                    session["network_events"][key]["status_code"] = browser_response.status
                    session["network_events"][key]["response_headers"] = safe_response_headers
                if browser_request.is_navigation_request():
                    session["status_code"] = browser_response.status

        page.on("request", record_request)
        page.on("response", record_response)
        async def record_dom_event(source: Any, event: dict[str, Any]) -> None:
            allowed_events = {"focus", "click", "input", "change", "submit"}
            event_type = str(event.get("type", ""))
            if event_type not in allowed_events:
                return
            safe_event = {
                "id": str(uuid4()),
                "type": event_type,
                "tag": str(event.get("tag", ""))[:32].lower(),
                "input_type": str(event.get("input_type", ""))[:32].lower(),
                "name": str(event.get("name", ""))[:256],
                "id_attribute": str(event.get("id", ""))[:256],
                "role": str(event.get("role", ""))[:64],
                "form_method": str(event.get("form_method", ""))[:16].upper(),
                "form_action": redact_url(str(event.get("form_action", ""))[:2048]),
                "started_at": time.monotonic(),
            }
            session["interaction_events"].append(safe_event)
            session["interaction_events"] = session["interaction_events"][-MAX_INTERACTION_EVENTS:]

        await page.expose_binding("__wafGuidedRecord", record_dom_event)
        await page.add_init_script("""() => {
          const selector = el => el.id ? `#${CSS.escape(el.id)}` : `${el.tagName.toLowerCase()}${el.getAttribute('name') ? `[name="${CSS.escape(el.getAttribute('name'))}"]` : ''}`;
          const emit = (type, el) => {
            if (!el || typeof window.__wafGuidedRecord !== 'function') return;
            const form = el.tagName === 'FORM' ? el : el.form;
            window.__wafGuidedRecord({
              type,
              tag: el.tagName.toLowerCase(), input_type: el.type || '', name: el.getAttribute('name') || '',
              id: el.id || '', role: el.getAttribute('role') || '', selector: selector(el),
              form_method: form ? (form.method || 'get').toUpperCase() : '', form_action: form ? form.action : ''
            }).catch(() => {});
          };
          const record = event => {
            const source = event.target;
            const el = source?.closest?.('input,button,select,textarea,a,form,[role="button"],[role="textbox"]');
            if (event.type === 'submit') {
              if (window.__wafAuthSubmitArmed === true) window.__wafAuthSubmitArmed = false;
              else { event.preventDefault(); event.stopImmediatePropagation(); }
            }
            emit(event.type, el);
          };
          const nativeSubmit = HTMLFormElement.prototype.submit;
          const nativeRequestSubmit = HTMLFormElement.prototype.requestSubmit;
          const blockedSubmit = function(...args) { if (window.__wafAuthSubmitArmed === true) { window.__wafAuthSubmitArmed = false; return nativeSubmit.apply(this, args); } emit('submit', this); };
          const blockedRequestSubmit = function(...args) { if (window.__wafAuthSubmitArmed === true) return nativeRequestSubmit.apply(this, args); emit('submit', this); };
          try { Object.defineProperty(HTMLFormElement.prototype, 'submit', {configurable: true, value: blockedSubmit}); } catch (_) {}
          try { Object.defineProperty(HTMLFormElement.prototype, 'requestSubmit', {configurable: true, value: blockedRequestSubmit}); } catch (_) {}
          for (const type of ['click','input','change','submit']) document.addEventListener(type, record, true);
        }""")
        browser_sessions[session_id] = session
        try:
            await page.goto(request.url, wait_until="domcontentloaded", timeout=20_000)
            await page.wait_for_timeout(500)
            return await guided_snapshot(session)
        except PlaywrightTimeoutError:
            return await guided_snapshot(session)
        except Exception as exc:
            await context.close()
            browser_sessions.pop(session_id, None)
            raise HTTPException(status_code=502, detail=f"Guided browser navigation failed: {type(exc).__name__}") from exc


@app.get("/guided/sessions/{session_id}")
async def get_guided_session(session_id: str) -> dict[str, Any]:
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        return await guided_snapshot(session)


@app.post("/guided/sessions/{session_id}/authenticate")
async def authenticate_guided_session(session_id: str, request: Request, response: Response) -> dict[str, Any]:
    """Perform at most one explicitly authorized HTTPS login POST, then resume GET/HEAD only."""
    try:
        raw_payload = await request.body()
        if len(raw_payload) > 4_096:
            raise HTTPException(status_code=413, detail="Authentication request is too large")
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict):
            raise ValueError("Expected JSON object")
        credentials = GuidedAuthenticateRequest.model_validate(payload)
        payload.clear()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=422, detail="Authentication request is invalid; credential values were not echoed")
    response.headers["Cache-Control"] = "no-store"
    if not credentials.authorize_single_login_post:
        raise HTTPException(status_code=422, detail="Explicit confirmation of the single login POST is required")
    if len(str(credentials.identity_label)) > 64:
        raise HTTPException(status_code=422, detail="Identity label is invalid")

    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        if session.get("auth_attempt_count", 0) >= 1:
            raise HTTPException(status_code=409, detail="This browser session has already used its single login attempt")
        page = session["page"]
        if urlparse(page.url).scheme.casefold() != "https":
            raise HTTPException(status_code=422, detail="Target authentication requires an HTTPS page")
        indexes = (credentials.username_index, credentials.password_index, credentials.submit_index)
        if len(set(indexes)) != 3:
            raise HTTPException(status_code=422, detail="Choose three distinct login controls")
        controls = page.locator('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')
        control_count = await controls.count()
        if any(index >= control_count for index in indexes):
            raise HTTPException(status_code=404, detail="A selected login control is no longer present")
        details = await page.evaluate("""indexes => {
          const all = Array.from(document.querySelectorAll('input,button,select,textarea,a[href],[role="button"],[role="textbox"]'));
          const chosen = indexes.map(index => all[index]);
          if (chosen.some(item => !item)) return null;
          const [user, pass, submit] = chosen;
          const visible = el => { const s=getComputedStyle(el), r=el.getBoundingClientRect(); return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; };
          const form = user.form;
          return {
            username_ok: user.tagName === 'INPUT' && ['text','email'].includes((user.type || 'text').toLowerCase()) && visible(user) && !user.disabled,
            password_ok: pass.tagName === 'INPUT' && pass.type.toLowerCase() === 'password' && visible(pass) && !pass.disabled,
            submit_ok: ((submit.tagName === 'BUTTON' && (submit.type || 'submit').toLowerCase() === 'submit') || (submit.tagName === 'INPUT' && submit.type.toLowerCase() === 'submit')) && visible(submit) && !submit.disabled,
            same_form: Boolean(form) && pass.form === form && submit.form === form,
            method: form ? (form.method || 'GET').toUpperCase() : '',
            action: form ? form.action : ''
          };
        }""", list(indexes))
        if not details or not details["username_ok"] or not details["password_ok"] or not details["submit_ok"] or not details["same_form"]:
            raise HTTPException(status_code=422, detail="Select a visible username field, password field, and submit button from the same login form")
        try:
            target = validated_login_target(page.url, details["method"], details["action"], session["hostname"], session["allowed_paths"])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        session["auth_attempt_count"] = 1
        session["identity_label"] = credentials.identity_label
        session["auth_post_target"] = {"origin": target[0], "path": target[1]}
        session["auth_post_pending"] = True
        session["auth_post_used"] = False
        session["auth_response_status"] = None
        session["auth_response_event"] = asyncio.Event()
        session["auth_result"] = "attempt-started"
        session["touched"] = time.monotonic()
        user_control = controls.nth(credentials.username_index)
        password_control = controls.nth(credentials.password_index)
        submit_control = controls.nth(credentials.submit_index)
        try:
            await user_control.fill(credentials.username.get_secret_value(), timeout=3_000)
            await password_control.fill(credentials.password.get_secret_value(), timeout=3_000)
            await page.evaluate("window.__wafAuthSubmitArmed = true")
            try:
                await submit_control.click(timeout=5_000)
            except PlaywrightTimeoutError:
                # A normal POST navigation may outlive the click's navigation wait.
                pass
            try:
                await asyncio.wait_for(session["auth_response_event"].wait(), timeout=10)
            except asyncio.TimeoutError:
                pass
        except PlaywrightTimeoutError as exc:
            session["auth_post_pending"] = False
            session["auth_result"] = "login-controls-unavailable"
            raise HTTPException(status_code=422, detail="Login controls could not be used; credential values were not returned") from exc
        except Exception as exc:
            session["auth_post_pending"] = False
            session["auth_result"] = "login-attempt-failed"
            raise HTTPException(status_code=502, detail="The isolated browser could not complete the authorized login attempt") from exc
        finally:
            session["auth_post_pending"] = False
            try:
                await page.evaluate("window.__wafAuthSubmitArmed = false")
                await user_control.fill("", timeout=1_000)
                await password_control.fill("", timeout=1_000)
            except Exception:
                # A successful navigation destroys the old document and its input values.
                pass

        response_status = session.get("auth_response_status")
        if not session.get("auth_post_used"):
            session["auth_result"] = "login-post-not-observed"
            session["auth_state"] = "anonymous"
        elif response_status is None:
            session["auth_result"] = "login-response-unobserved"
            session["auth_state"] = "unknown"
        elif response_status >= 400:
            session["auth_result"] = "login-rejected-or-error"
            session["auth_state"] = "anonymous"
        else:
            try:
                password_still_visible = await page.locator('input[type="password"]').evaluate_all("items => items.some(el => { const r=el.getBoundingClientRect(), s=getComputedStyle(el); return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; })")
            except Exception:
                password_still_visible = True
            if password_still_visible:
                session["auth_result"] = "login-submitted-unconfirmed"
                session["auth_state"] = "unknown"
            else:
                session["auth_result"] = "likely-authenticated"
                session["auth_state"] = "role-specific"
        session["auth_response_event"] = None
        auth_sequence_start = session.get("auth_sequence_start")
        if isinstance(auth_sequence_start, int):
            for event_item in session["network_sequence"][auth_sequence_start:]:
                event_item["authentication"] = session["auth_state"]
        session["touched"] = time.monotonic()
        return {
            "snapshot": await guided_snapshot(session),
            "authentication": {"state": session["auth_state"], "identity_label": session["identity_label"], "result": session["auth_result"], "login_http_status": response_status, "login_post_sent": bool(session.get("auth_post_used")), "values_submitted": bool(session.get("auth_post_used")), "credentials_retained": False},
        }


@app.post("/guided/sessions/{session_id}/navigate")
async def navigate_guided_session(session_id: str, request: GuidedNavigateRequest) -> dict[str, Any]:
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        scope = InspectionRequest(urls=[request.url], hostname=session["hostname"], allowed_paths=session["allowed_paths"])
        if not in_scope(request.url, scope) or urlparse(request.url).username or urlparse(request.url).password:
            raise HTTPException(status_code=422, detail="Navigation is outside the session's host/path scope")
        session["status_code"] = None
        try:
            await session["page"].goto(request.url, wait_until="domcontentloaded", timeout=20_000)
            await session["page"].wait_for_timeout(300)
        except PlaywrightTimeoutError:
            pass
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Guided browser navigation failed: {type(exc).__name__}") from exc
        return await guided_snapshot(session)


@app.post("/guided/sessions/{session_id}/select")
async def select_guided_element(session_id: str, request: GuidedSelectRequest) -> dict[str, Any]:
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        items = session["page"].locator('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')
        if request.element_index >= await items.count():
            raise HTTPException(status_code=404, detail="Selectable element is no longer present")
        selected = await items.nth(request.element_index).evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          role: el.getAttribute('role') || '', aria_label: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
          required: el.hasAttribute('required'), disabled: el.hasAttribute('disabled'), autocomplete: el.getAttribute('autocomplete') || '',
          minlength: el.getAttribute('minlength') || '', maxlength: el.getAttribute('maxlength') || '', pattern: el.getAttribute('pattern') || '',
          labels: Array.from(el.labels || []).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120)),
          form_method: el.form ? (el.form.method || 'get').toUpperCase() : '', form_action: el.form ? el.form.action : '',
          values_submitted: false
        })""")
        selected["form_action"] = redact_url(selected.get("form_action", ""))
        field_names = {str(selected.get("name", "")).casefold(), str(selected.get("id", "")).casefold()}
        field_names.discard("")
        correlated: list[dict[str, Any]] = []
        if field_names:
            for item in session["network_events"].values():
                parsed = urlparse(item["url"])
                query_names = {name.casefold() for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
                matched = sorted(field_names.intersection(query_names))
                if matched:
                    correlated.append({
                        "method": item["method"], "path_template": redacted_route_template(item["url"]),
                        "matched_parameter_names": matched, "confidence": 0.55,
                        "reason": "DOM name or id equals a query parameter name on an observed safe request",
                        "raw_values_captured": False,
                    })
        selected["correlated_requests"] = correlated[:20]
        stored_keys = ("tag", "type", "effective_type", "name", "id", "role", "form_id", "form_method", "form_action")
        session["selected_elements"].append({key: selected.get(key) for key in stored_keys})
        session["selected_elements"] = session["selected_elements"][-MAX_INTERACTION_EVENTS:]
        session["touched"] = time.monotonic()
        return {"page_url": redact_url(session["page"].url), "element": selected, "evidence_kind": "dom_metadata_only", "raw_value_captured": False}


@app.post("/guided/sessions/{session_id}/focus")
async def focus_guided_element(session_id: str, request: GuidedSelectRequest) -> dict[str, Any]:
    """Focus a selected control (never click/type/submit) and correlate safe follow-on requests."""
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        items = session["page"].locator('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')
        if request.element_index >= await items.count():
            raise HTTPException(status_code=404, detail="Selectable element is no longer present")
        element = await items.nth(request.element_index).evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          role: el.getAttribute('role') || '', aria_label: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
          required: el.hasAttribute('required'), disabled: el.hasAttribute('disabled'), autocomplete: el.getAttribute('autocomplete') || '',
          minlength: el.getAttribute('minlength') || '', maxlength: el.getAttribute('maxlength') || '',
          labels: Array.from(el.labels || []).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120))
        })""")
        if element.get("disabled"):
            raise HTTPException(status_code=422, detail="Disabled controls cannot be focused")
        event_started = time.monotonic()
        interaction = {
            "id": str(uuid4()), "type": "focus", "element_index": request.element_index,
            "tag": element.get("tag", ""), "input_type": element.get("type", ""),
            "name": element.get("name", ""), "id_attribute": element.get("id", ""),
            "started_at": event_started,
        }
        session["interaction_events"].append(interaction)
        session["interaction_events"] = session["interaction_events"][-MAX_INTERACTION_EVENTS:]
        try:
            await items.nth(request.element_index).focus(timeout=2_000)
            await session["page"].wait_for_timeout(1_200)
        except PlaywrightTimeoutError:
            raise HTTPException(status_code=422, detail="Control could not be focused")
        correlated = correlate_focus_to_requests(element, event_started, session["network_sequence"], session["hostname"])
        interaction["correlated_request_ids"] = [item.get("request_id") for item in correlated if item.get("request_id")]
        interaction["matched_parameter_names"] = sorted({name for item in correlated for name in item.get("matched_parameter_names", [])})
        session["touched"] = time.monotonic()
        return {
            "page_url": redact_url(session["page"].url),
            "event": {"type": "focus", "element": element, "evidence_id": interaction["id"]},
            "correlation_status": "matched" if correlated else "no_request_observed",
            "correlated_requests": correlated,
            "capture_policy": "metadata-only; focus only; GET/HEAD same-host in-scope requests; no click, typing, form submission, request bodies, or raw field values",
            "raw_value_captured": False,
        }


@app.post("/guided/sessions/{session_id}/activate")
async def activate_guided_element(session_id: str, request: GuidedSelectRequest) -> dict[str, Any]:
    """Explicitly click only an in-scope link or a non-submit button; unsafe methods remain blocked."""
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        items = session["page"].locator('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')
        if request.element_index >= await items.count():
            raise HTTPException(status_code=404, detail="Selectable element is no longer present")
        element = await items.nth(request.element_index).evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', effective_type: el.type || '',
          name: el.getAttribute('name') || '', id: el.id || '', role: el.getAttribute('role') || '',
          disabled: el.hasAttribute('disabled'), href: el.href || '', target: el.getAttribute('target') || '',
          form_associated: Boolean(el.form),
          form_method: el.form ? (el.form.method || 'get').toUpperCase() : '', form_action: el.form ? el.form.action : ''
        })""")
        is_link = element["tag"] == "a" and bool(element["href"])
        is_non_submit_button = element["tag"] == "button" and element["effective_type"].casefold() == "button"
        is_role_button = element["role"] == "button" and not element["disabled"] and not element["form_associated"]
        if element["disabled"] or element["target"] and element["target"].casefold() != "_self":
            raise HTTPException(status_code=422, detail="Disabled and new-window controls cannot be activated")
        if not (is_link or is_non_submit_button or is_role_button):
            raise HTTPException(status_code=422, detail="Only in-scope links and explicit non-submit buttons can be activated")
        if is_link:
            scope = InspectionRequest(urls=[element["href"]], hostname=session["hostname"], allowed_paths=session["allowed_paths"])
            if not in_scope(element["href"], scope):
                raise HTTPException(status_code=422, detail="Link is outside the guided session scope")
        event_started = time.monotonic()
        try:
            await items.nth(request.element_index).click(timeout=3_000, no_wait_after=True)
            await session["page"].wait_for_timeout(1_200)
        except PlaywrightTimeoutError:
            raise HTTPException(status_code=422, detail="Control could not be activated")
        correlated = correlate_focus_to_requests(element, event_started, session["network_sequence"], session["hostname"], {"document", "xhr", "fetch"})
        click_event = next((item for item in reversed(session["interaction_events"]) if item.get("type") == "click" and item.get("started_at", 0) >= event_started), None)
        if click_event is None:
            click_event = {"id": str(uuid4()), "type": "click", "tag": element["tag"], "input_type": element.get("effective_type", ""), "name": element.get("name", ""), "id_attribute": element.get("id", ""), "role": element.get("role", ""), "form_method": element.get("form_method", ""), "form_action": redact_url(element.get("form_action", "")), "started_at": event_started}
            session["interaction_events"].append(click_event)
            session["interaction_events"] = session["interaction_events"][-MAX_INTERACTION_EVENTS:]
        click_event["correlated_request_ids"] = [item.get("request_id") for item in correlated if item.get("request_id")]
        click_event["matched_parameter_names"] = sorted({name for item in correlated for name in item.get("matched_parameter_names", [])})
        session["touched"] = time.monotonic()
        safe_element = {**element, "href": redact_url(element.get("href", "")), "form_action": redact_url(element.get("form_action", ""))}
        return {
            "page_url": redact_url(session["page"].url),
            "event": {"type": "click", "element": safe_element},
            "correlation_status": "matched" if correlated else "no_request_observed",
            "correlated_requests": correlated,
            "capture_policy": "explicit click on an in-scope link or non-submit button; only same-host, in-scope GET/HEAD requests are allowed; form submission and request bodies are blocked/not captured",
            "raw_value_captured": False,
            "snapshot": await guided_snapshot(session),
        }


@app.post("/guided/sessions/{session_id}/probe-input")
async def probe_guided_input(session_id: str, request: GuidedSelectRequest) -> dict[str, Any]:
    """Use a fixed benign value in an eligible empty text field; never submit or return the value."""
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        items = session["page"].locator('input,button,select,textarea,a[href],[role="button"],[role="textbox"]')
        if request.element_index >= await items.count():
            raise HTTPException(status_code=404, detail="Selectable input is no longer present")
        element = await items.nth(request.element_index).evaluate("""el => ({
          tag: el.tagName.toLowerCase(), type: (el.type || '').toLowerCase(), name: el.getAttribute('name') || '',
          id: el.id || '', autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
          disabled: el.hasAttribute('disabled'), read_only: el.hasAttribute('readonly'),
          has_value: Boolean(el.value), form_method: el.form ? (el.form.method || 'get').toUpperCase() : ''
        })""")
        if element["tag"] not in {"input", "textarea"} or element["disabled"] or element["read_only"]:
            raise HTTPException(status_code=422, detail="Only enabled editable text fields can be probed")
        if element["type"] not in {"", "text", "search", "email", "url", "tel", "number"}:
            raise HTTPException(status_code=422, detail="This input type is not eligible for a synthetic probe")
        if element["has_value"]:
            raise HTTPException(status_code=422, detail="Non-empty fields are not overwritten by a synthetic probe")
        if SENSITIVE_FIELD_NAME_RE.search(f"{element['name']} {element['id']} {element['autocomplete']}"):
            raise HTTPException(status_code=422, detail="Credential and sensitive fields cannot be synthetically probed")
        probe_value = "1" if element["type"] == "number" else (
            "https://waf-observation.invalid/" if element["type"] == "url" else (
                "waf-observation@example.invalid" if element["type"] == "email" else "waf-observation"
            )
        )
        event_started = time.monotonic()
        try:
            await items.nth(request.element_index).fill(probe_value, timeout=2_000)
            await session["page"].wait_for_timeout(1_200)
        except PlaywrightTimeoutError:
            raise HTTPException(status_code=422, detail="Input probe could not be applied")
        correlated = correlate_focus_to_requests(element, event_started, session["network_sequence"], session["hostname"])
        input_event = next((item for item in reversed(session["interaction_events"]) if item.get("type") == "input" and item.get("started_at", 0) >= event_started), None)
        if input_event is None:
            input_event = {"id": str(uuid4()), "type": "input", "tag": element["tag"], "input_type": element["type"], "name": element["name"], "id_attribute": element["id"], "started_at": event_started}
            session["interaction_events"].append(input_event)
            session["interaction_events"] = session["interaction_events"][-MAX_INTERACTION_EVENTS:]
        input_event["correlated_request_ids"] = [item.get("request_id") for item in correlated if item.get("request_id")]
        input_event["matched_parameter_names"] = sorted({name for item in correlated for name in item.get("matched_parameter_names", [])})
        session["touched"] = time.monotonic()
        return {
            "event": {"type": "input", "element": {key: element[key] for key in ("tag", "type", "name", "id", "autocomplete", "form_method")}},
            "correlation_status": "matched" if correlated else "no_request_observed",
            "correlated_requests": correlated,
            "capture_policy": "fixed synthetic input; not applied to sensitive or non-empty fields; no submit; values and bodies are never returned; unsafe methods are blocked",
            "synthetic_probe": True,
            "raw_value_captured": False,
        }


@app.post("/guided/sessions/{session_id}/select-at")
async def select_guided_point(session_id: str, request: GuidedPointSelectRequest) -> dict[str, Any]:
    """Select a visible page element from screenshot coordinates without activating it."""
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        selected = await session["page"].evaluate("""({x, y}) => {
          const hit = document.elementFromPoint(x, y);
          if (!hit) return null;
          const el = hit.closest('input,button,select,textarea,a,form,[role="button"],[role="textbox"]') || hit;
          const form = el.tagName === 'FORM' ? el : el.form;
          const r = el.getBoundingClientRect();
          return {
            tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', effective_type: el.type || '',
            name: el.getAttribute('name') || '', id: el.id || '', role: el.getAttribute('role') || '',
            aria_label: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
            required: el.hasAttribute('required'), disabled: el.hasAttribute('disabled'),
            selector: el.id ? `#${CSS.escape(el.id)}` : `${el.tagName.toLowerCase()}${el.getAttribute('name') ? `[name="${CSS.escape(el.getAttribute('name'))}"]` : ''}`,
            labels: Array.from(el.labels || []).map(label => (label.innerText || label.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120)),
            form_id: form ? (form.id || form.getAttribute('name') || '') : '',
            form_method: form ? (form.method || 'get').toUpperCase() : '', form_action: form ? form.action : '',
            bounds: {x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height)}
          };
        }""", {"x": request.x, "y": request.y})
        if selected is None:
            raise HTTPException(status_code=422, detail="No page element exists at the selected coordinate")
        selected["form_action"] = redact_url(selected.get("form_action", ""))
        stored_keys = ("tag", "type", "effective_type", "name", "id", "role", "form_id", "form_method", "form_action")
        session["selected_elements"].append({key: selected.get(key) for key in stored_keys})
        session["selected_elements"] = session["selected_elements"][-MAX_INTERACTION_EVENTS:]
        session["touched"] = time.monotonic()
        snapshot = await guided_snapshot(session)
        return {"element": selected, "snapshot": snapshot, "evidence_kind": "screenshot_point_selection", "raw_value_captured": False}


@app.get("/guided/sessions/{session_id}/candidate-source")
async def guided_candidate_source(session_id: str) -> dict[str, Any]:
    """Return bounded, already-redacted metadata for in-memory candidate generation."""
    async with browser_lab_lock:
        await expire_guided_sessions()
        session = browser_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found or expired")
        requests: list[dict[str, Any]] = []
        for item in session["network_sequence"]:
            parsed = urlparse(item["url"])
            query_names = sorted({name[:256] for name, _ in parse_qsl(parsed.query, keep_blank_values=False) if name and len(name) <= 256})
            requests.append({
                "id": item["id"], "method": item["method"], "path_template": redacted_route_template(item["url"]),
                "scheme": urlparse(item["url"]).scheme.lower(),
                "authentication": item.get("authentication", "anonymous"),
                "resource_type": item["resource_type"], "status_code": item["status_code"],
                "query_names": query_names, "request_header_names": item.get("request_header_names", []),
                "cookie_header_present": "cookie" in item.get("request_header_names", []),
                "response_header_names": item.get("response_header_names", []),
                "response_content_type": item.get("response_content_type", ""),
                "observed_at": item["observed_at"],
            })
        cookie_metadata: list[dict[str, Any]] = []
        for cookie in await session["context"].cookies():
            domain = str(cookie.get("domain", "")).lstrip(".").lower()
            cookie_path = str(cookie.get("path", "/")) or "/"
            if (session["hostname"] == domain or session["hostname"].endswith("." + domain)) and allowed_path(cookie_path, session["allowed_paths"]):
                cookie_metadata.append({
                    "name": str(cookie.get("name", ""))[:256], "domain": str(cookie.get("domain", ""))[:253],
                    "path": cookie_path[:2048], "secure": bool(cookie.get("secure")),
                    "http_only": bool(cookie.get("httpOnly")), "same_site": str(cookie.get("sameSite", ""))[:32],
                    "session": float(cookie.get("expires", -1)) <= 0,
                })
        safe_interactions = []
        for item in session["interaction_events"]:
            safe_interaction = {
                key: item.get(key)
                for key in ("id", "type", "tag", "input_type", "name", "id_attribute", "role", "form_method", "correlated_request_ids", "matched_parameter_names")
            }
            safe_interaction["form_action"] = redact_url(str(item.get("form_action", "")))
            safe_interactions.append(safe_interaction)
        return {
            "session_id": session["id"], "hostname": session["hostname"],
            "requests": requests, "selected_elements": session["selected_elements"][-MAX_INTERACTION_EVENTS:],
            "interaction_events": safe_interactions, "cookie_metadata": cookie_metadata[:200],
            "auth_state": session.get("auth_state", "anonymous"),
            "identity_label": session.get("identity_label", ""),
            "auth_attempted": bool(session.get("auth_attempt_count")),
            "auth_result": session.get("auth_result", "not-attempted"),
            "privacy": {"raw_values_returned": False, "request_bodies_returned": False, "cookie_values_returned": False},
        }


@app.delete("/guided/sessions/{session_id}")
async def stop_guided_session(session_id: str) -> dict[str, bool]:
    async with browser_lab_lock:
        session = browser_sessions.pop(session_id, None)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found")
        await session["context"].close()
        return {"closed": True}
