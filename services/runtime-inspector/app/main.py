from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from playwright.async_api import Browser, TimeoutError as PlaywrightTimeoutError, async_playwright
from pydantic import BaseModel, Field

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
INTERESTING_NETWORK_MARKERS = ("/api/", "/auth", "/login", "/signin", "/oauth", "/token", "/graphql", "/rest/", "/user")
SAFE_RESPONSE_HEADERS = {
    "content-security-policy", "content-security-policy-report-only", "strict-transport-security",
    "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy",
    "cache-control", "content-type", "location", "www-authenticate",
}


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


class GuidedNavigateRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class GuidedSelectRequest(BaseModel):
    element_index: int = Field(ge=0, le=999)


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
    if not parsed.query:
        return value
    return parsed._replace(query="&".join(f"{key}=REDACTED" for key, _ in [part.split("=", 1) if "=" in part else (part, "") for part in parsed.query.split("&")])).geturl()


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
                parts.append(segment)
    path = "/".join(parts) or "/"
    return path if path.startswith("/") else "/" + path


def correlate_focus_to_requests(element: dict[str, Any], event_started: float, requests: list[dict[str, Any]], hostname: str) -> list[dict[str, Any]]:
    """Correlate metadata-only focus events to later safe same-host XHR/fetch requests."""
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
        if item.get("resource_type") not in {"xhr", "fetch"} or not is_same_host(str(item.get("url", "")), hostname):
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
      const controls = Array.from(document.querySelectorAll('input,button,select,textarea,[role="button"],[role="textbox"]')).slice(0, 250).map((el, index) => ({
        index, tag: el.tagName.toLowerCase(), type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
        role: el.getAttribute('role') || '', aria_label: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
        required: el.hasAttribute('required'), disabled: el.hasAttribute('disabled'), autocomplete: el.getAttribute('autocomplete') || '',
        minlength: el.getAttribute('minlength') || '', maxlength: el.getAttribute('maxlength') || '', pattern: el.getAttribute('pattern') || '',
        labels: Array.from(el.labels || []).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120)),
        text: (el.innerText || el.getAttribute('title') || '').replace(/\\s+/g, ' ').trim().slice(0, 120), visible: visible(el)
      }));
      const links = Array.from(document.querySelectorAll('a[href]')).map(a => ({text: (a.innerText || a.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim().slice(0, 120), href: a.href})).slice(0, 200);
      const forms = Array.from(document.forms).map(f => ({id: f.id || '', name: f.getAttribute('name') || '', action: f.action, method: (f.method || 'get').toUpperCase(), enctype: f.enctype || '', fields: f.elements.length})).slice(0, 50);
      return {title: document.title.slice(0, 250), headings: Array.from(document.querySelectorAll('h1,h2,h3,[role="heading"]')).map(x => (x.innerText || x.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 180)).filter(Boolean).slice(0, 40), controls, links, forms};
    }""")
    requests = list(session["network_events"].values())[-200:]
    screenshot = await page.screenshot(type="jpeg", quality=55, full_page=False, timeout=5_000)
    session["touched"] = time.monotonic()
    return {
        "session_id": session["id"], "url": redact_url(page.url), "title": dom["title"], "status_code": session.get("status_code"),
        "headings": dom["headings"], "controls": dom["controls"], "forms": [{**form, "action": redact_url(form["action"])} for form in dom["forms"]],
        "links": [{**link, "href": redact_url(link["href"])} for link in dom["links"] if is_same_host(link["href"], session["hostname"]) and allowed_path(urlparse(link["href"]).path, session["allowed_paths"])],
        "network_requests": requests, "screenshot_data_uri": "data:image/jpeg;base64," + base64.b64encode(screenshot).decode("ascii"),
        "capture_policy": "same-host, in-scope GET/HEAD only; WebSockets and downloads blocked; no form submission; request bodies, cookies, and raw field values are not captured",
        "values_submitted": False,
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
        context = await guided_browser.new_context(viewport={"width": 1365, "height": 900}, accept_downloads=False, service_workers="block")
        page = await context.new_page()
        scope = InspectionRequest(urls=[request.url], hostname=request.hostname, allowed_paths=request.allowed_paths)

        async def guard_route(route: Any) -> None:
            target = route.request.url
            if route.request.method.upper() not in {"GET", "HEAD"} or not in_scope(target, scope):
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        async def block_websocket(websocket_route: Any) -> None:
            await websocket_route.close(code=1008, reason="WebSocket traffic is disabled in read-only browser sessions")

        await page.route("**/*", guard_route)
        await page.route_web_socket("**/*", block_websocket)
        session_id = str(uuid4())
        session: dict[str, Any] = {
                "id": session_id, "context": context, "page": page, "hostname": request.hostname.lower(),
                "allowed_paths": request.allowed_paths or ["/"], "network_events": {}, "network_sequence": [],
                "interaction_events": [], "status_code": None,
                "created": time.monotonic(), "touched": time.monotonic(),
        }
        def record_request(browser_request: Any) -> None:
                if browser_request.method.upper() not in {"GET", "HEAD"} or not in_scope(browser_request.url, scope):
                    return
                key = (browser_request.method, redact_url(browser_request.url), browser_request.resource_type)
                event_item = {
                    "id": str(uuid4()), "method": browser_request.method,
                    "url": redact_url(browser_request.url), "resource_type": browser_request.resource_type,
                    "status_code": None, "started_at": time.monotonic(),
                }
                session["network_sequence"].append(event_item)
                session["network_sequence"] = session["network_sequence"][-MAX_NETWORK_EVENTS:]
                if len(session["network_events"]) < MAX_NETWORK_EVENTS or key in session["network_events"]:
                    session["network_events"].setdefault(key, {"method": browser_request.method, "url": redact_url(browser_request.url), "resource_type": browser_request.resource_type, "status_code": None})

        def record_response(browser_response: Any) -> None:
                browser_request = browser_response.request
                for sequence_item in reversed(session["network_sequence"]):
                    if (sequence_item["method"] == browser_request.method
                            and sequence_item["url"] == redact_url(browser_request.url)
                            and sequence_item["resource_type"] == browser_request.resource_type
                            and sequence_item["status_code"] is None):
                        sequence_item["status_code"] = browser_response.status
                        break
                key = (browser_request.method, redact_url(browser_request.url), browser_request.resource_type)
                if key in session["network_events"]:
                    session["network_events"][key]["status_code"] = browser_response.status
                    session["network_events"][key]["response_headers"] = safe_headers(browser_response.headers)
                if browser_request.is_navigation_request():
                    session["status_code"] = browser_response.status

        page.on("request", record_request)
        page.on("response", record_response)
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
        items = session["page"].locator('input,button,select,textarea,[role="button"],[role="textbox"]')
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
        items = session["page"].locator('input,button,select,textarea,[role="button"],[role="textbox"]')
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
            "id": str(uuid4()), "event": "focus", "element_index": request.element_index,
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
        session["touched"] = time.monotonic()
        return {
            "page_url": redact_url(session["page"].url),
            "event": {"type": "focus", "element": element, "evidence_id": interaction["id"]},
            "correlation_status": "matched" if correlated else "no_request_observed",
            "correlated_requests": correlated,
            "capture_policy": "metadata-only; focus only; GET/HEAD same-host in-scope requests; no click, typing, form submission, request bodies, or raw field values",
            "raw_value_captured": False,
        }


@app.delete("/guided/sessions/{session_id}")
async def stop_guided_session(session_id: str) -> dict[str, bool]:
    async with browser_lab_lock:
        session = browser_sessions.pop(session_id, None)
        if not session:
            raise HTTPException(status_code=404, detail="Guided browser session not found")
        await session["context"].close()
        return {"closed": True}
