from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from playwright.async_api import Browser, TimeoutError as PlaywrightTimeoutError, async_playwright
from pydantic import BaseModel, Field

app = FastAPI(title="WAF Runtime Inspector", version="0.2.0")
inspection_lock = asyncio.Lock()
MAX_NETWORK_EVENTS = 200
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
    return {key.lower(): value[:500] for key, value in (headers or {}).items() if key.lower() in SAFE_RESPONSE_HEADERS}


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


def validate_request(request: InspectionRequest) -> None:
    try:
        ipaddress.ip_address(request.hostname)
    except ValueError:
        if not request.hostname or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in request.hostname):
            raise HTTPException(status_code=422, detail="Runtime inspection hostname is invalid")
    if any(not in_scope(url, request) for url in request.urls):
        raise HTTPException(status_code=422, detail="Runtime inspection URL is outside the selected scope")


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
