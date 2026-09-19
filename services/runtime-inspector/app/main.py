from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from playwright.async_api import Browser, TimeoutError as PlaywrightTimeoutError, async_playwright
from pydantic import BaseModel, Field

app = FastAPI(title="WAF Runtime Inspector", version="0.1.0")
inspection_lock = asyncio.Lock()


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
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=15_000)
        await page.wait_for_timeout(750)
        dom = await page.evaluate("""() => ({
            forms: Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.getAttribute('action') || '',
                method: (form.getAttribute('method') || 'get').toUpperCase(),
                enctype: form.getAttribute('enctype') || ''
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
                accept: el.getAttribute('accept') || ''
            })),
            search_components: Array.from(document.querySelectorAll('*')).filter(el => el.tagName.toLowerCase().includes('search-bar')).map(el => ({
                tag: el.tagName.toLowerCase(),
                type: 'search-component',
                name: el.getAttribute('name') || '',
                id: el.getAttribute('id') || '',
                aria_label: el.getAttribute('aria-label') || ''
            })),
            links: Array.from(document.querySelectorAll('a[href]')).map(el => el.href).slice(0, 200)
        })""")
        controls = dom.get("controls", [])
        search_components = dom.get("search_components", [])
        for component in search_components:
            if component not in controls:
                controls.append(component)
        for form in dom.get("forms", []):
            form["action"] = redact_url(form.get("action", ""))
        return {
            "source_url": redact_url(url),
            "final_url": redact_url(page.url),
            "status_code": response.status if response else None,
            "forms": dom.get("forms", [])[:50],
            "controls": controls[:200],
            "search_surfaces": search_components[:50],
            "links": [redact_url(link) for link in dom.get("links", [])[:200]],
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
