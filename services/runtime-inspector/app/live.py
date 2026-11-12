"""Live Browser Lab: a real, interactive headless Chromium streamed to the admin.

Frames are streamed with the CDP screencast; mouse/keyboard events come back over a
WebSocket. Only metadata is recorded (field names, types, request shapes) - never typed
values, request/response bodies, cookies or frames.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, urlparse

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.coverage import build_coverage
from app.discovery_policy import Budget, build_policy, classify_request, decide, policy_fingerprint
from app.field_roles import classify_field
from app.live_policy import (
    MODES, key_to_cdp, live_request_allowed, mouse_to_cdp, new_live_session_id, post_body_shape, redact_url,
)
from app.target_guard import scan_target_error

MAX_LIVE_SESSIONS = 5
IDLE_TTL_SECONDS = 900
MAX_DURATION_SECONDS = 3600
UNCLAIMED_TTL_SECONDS = 60
MAX_NETWORK = 300
MAX_EVENTS = 200
SNAPSHOT_INTERVAL_SECONDS = 2.0
VIEWPORT = (1280, 800)

live_sessions: dict[str, dict[str, Any]] = {}
_reaper: asyncio.Task[Any] | None = None
_create_lock = asyncio.Lock()


class LiveSessionRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    hostname: str = Field(min_length=1, max_length=253)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"], max_length=100)
    mode: str = Field(default="read_only")
    ignore_https_errors: bool = False
    # Optional discovery policy; defaults to the preset matching the mode. It can only narrow the mode.
    policy_preset: str | None = None
    policy_overrides: dict[str, Any] | None = None


MAX_PERMISSION_EVENTS = 200


def _body_format(content_type: str) -> str:
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media.startswith("multipart/"):
        return "multipart"
    if media == "application/x-www-form-urlencoded":
        return "form"
    return "json" if media.endswith("json") else ""


def apply_policy(session: dict[str, Any], method: str, url: str, resource_type: str, content_type: str = "") -> bool:
    """Classify one outgoing request, enforce the run policy and keep a metadata-only record.

    Returns True when the request may proceed. Runs for every request the page makes, including
    those triggered indirectly by page scripts."""
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != session["hostname"]:
        return True  # cross-host traffic is already limited to GET/HEAD subresources by the mode guard
    category, why = classify_request(method, url, content_type, _body_format(content_type), resource_type)
    verdict = decide(session["policy"], category, parsed.path or "/")
    if verdict["action"] == "allow" and not session["budget"].charge_request():
        verdict = {"action": "deny", "reason": "request budget exhausted"}
        session["budget_exhausted"] = True
    counts = session["permission_counts"]
    key = f"{category or 'ambiguous'}:{verdict['action']}"
    counts[key] = counts.get(key, 0) + 1
    if verdict["action"] != "allow" and len(session["permission_events"]) < MAX_PERMISSION_EVENTS:
        session["permission_events"].append({
            "action": verdict["action"], "category": category or "ambiguous", "method": method.upper(),
            "path": redact_url(url).split("?", 1)[0][:300], "reason": verdict["reason"], "classified_by": why, "observed_at": _now(),
        })
    return verdict["action"] == "allow"


INIT_SCRIPT = """() => {
  const bucket = n => n === 0 ? '0' : n <= 8 ? '1-8' : n <= 32 ? '9-32' : n <= 128 ? '33-128' : n <= 1024 ? '129-1024' : '>1024';
  const emit = (type, el) => {
    if (!el || typeof window.__wafLiveRecord !== 'function') return;
    const form = el.tagName === 'FORM' ? el : el.form;
    const textual = ['INPUT', 'TEXTAREA'].includes(el.tagName) && !['checkbox', 'radio', 'file'].includes(el.type) && typeof el.value === 'string';
    window.__wafLiveRecord({
      type, tag: el.tagName.toLowerCase(), input_type: el.type || '', name: el.getAttribute('name') || '', id: el.id || '',
      form_method: form ? (form.method || 'get').toUpperCase() : '', form_action: form ? form.action : '',
      length_bucket: textual ? bucket(el.value.length) : ''
    }).catch(() => {});
  };
  for (const t of ['focusin', 'input', 'change', 'submit', 'click']) {
    document.addEventListener(t, e => {
      const el = e.target && e.target.closest ? e.target.closest('input,button,select,textarea,form,a') : null;
      emit(t === 'focusin' ? 'focus' : t, el);
    }, true);
  }
}"""

SNAPSHOT_SCRIPT = """() => {
  const vis = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0; };
  const forms = Array.from(document.forms).slice(0, 50);
  return {
    url: location.href, title: document.title.slice(0, 200),
    forms: forms.map((f, index) => ({ index, id: f.id || '', name: f.getAttribute('name') || '', action: f.action || '', method: (f.method || 'get').toUpperCase(), enctype: f.enctype || '', field_count: f.elements.length })),
    controls: Array.from(document.querySelectorAll('input,select,textarea')).slice(0, 250).map(el => ({
      tag: el.tagName.toLowerCase(), type: el.type || '', name: el.getAttribute('name') || '', id: el.id || '',
      form_index: el.form ? forms.indexOf(el.form) : -1,
      label: ((el.labels && el.labels[0] && el.labels[0].innerText) || el.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim().slice(0, 100),
      placeholder: (el.getAttribute('placeholder') || '').slice(0, 100), autocomplete: el.getAttribute('autocomplete') || '',
      required: el.required === true, maxlength: el.getAttribute('maxlength') || '', minlength: el.getAttribute('minlength') || '',
      pattern: (el.getAttribute('pattern') || '').slice(0, 200), accept: el.getAttribute('accept') || '', visible: vis(el)
    }))
  };
}"""

INSPECT_SCRIPT = """([x, y]) => {
  const el = document.elementFromPoint(x, y);
  const t = el && el.closest ? el.closest('input,button,select,textarea,a,form,label') : null;
  if (!t) return null;
  const form = t.form || (t.tagName === 'FORM' ? t : null);
  const r = t.getBoundingClientRect();
  return { tag: t.tagName.toLowerCase(), type: t.type || '', name: t.getAttribute('name') || '', id: t.id || '',
    label: ((t.labels && t.labels[0] && t.labels[0].innerText) || t.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim().slice(0, 100),
    autocomplete: t.getAttribute('autocomplete') || '', required: t.required === true,
    form_method: form ? (form.method || 'get').toUpperCase() : '', form_action: form ? form.action : '',
    bounds: { x: r.x, y: r.y, width: r.width, height: r.height } };
}"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


finished_captures: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
MAX_FINISHED_CAPTURES = 50


async def candidate_source_dict(session: dict[str, Any], redacted_route_template: Callable[[str], str]) -> dict[str, Any]:
    requests: list[dict[str, Any]] = []
    for item in session["network"]:
        parsed = urlparse(item["url"])
        shape = item.get("body_shape") or {}
        requests.append({
            "id": item["id"], "evidence_ref": f"runtime:{session['id']}:request:{item['id']}", "evidence_class": "browser_observation", "method": item["method"], "path_template": redacted_route_template(item["url"]),
            "scheme": parsed.scheme.lower(), "authentication": "unknown", "resource_type": item["resource_type"],
            "status_code": item["status_code"],
            "query_names": sorted({n[:256] for n, _ in parse_qsl(parsed.query, keep_blank_values=False) if n and len(n) <= 256}),
            "request_header_names": item["request_header_names"], "cookie_header_present": "cookie" in item["request_header_names"],
            "response_header_names": item["response_header_names"], "response_content_type": item["response_content_type"],
            "body_format": shape.get("format", ""), "body_fields": shape.get("fields", []),
            "observed_at": item["observed_at"],
        })
    cookies = []
    try:
        for cookie in await session["context"].cookies():
            domain = str(cookie.get("domain", "")).lstrip(".").lower()
            if session["hostname"] == domain or session["hostname"].endswith("." + domain):
                cookies.append({"name": str(cookie.get("name", ""))[:256], "domain": domain[:253], "path": str(cookie.get("path", "/"))[:2048],
                                "secure": bool(cookie.get("secure")), "http_only": bool(cookie.get("httpOnly")),
                                "same_site": str(cookie.get("sameSite", ""))[:32], "session": float(cookie.get("expires", -1)) <= 0})
    except Exception:
        pass
    return {"session_id": session["id"], "hostname": session["hostname"], "mode": session["mode"], "requests": requests,
            "interaction_events": list(session["events"]), "cookie_metadata": cookies, "auth_state": "unknown",
            "evidence_source": "guided_browser", "values_captured": False}


def _coverage(session: dict[str, Any]) -> dict[str, Any]:
    return build_coverage(
        list(session["network"]), load_error=session.get("load_error", ""), blocked_hosts=dict(session["blocked_hosts"]),
        permission_events=list(session["permission_events"]), budget_exhausted=session.get("budget_exhausted", False),
    )


async def build_capture(session: dict[str, Any]) -> dict[str, Any]:
    """Metadata-only record of a browsing session (no values, bodies, cookies' values or frames)."""
    from app.main import redacted_route_template  # late import: main imports this module

    snapshot = await _snapshot(session)
    started = session.get("started_at") or _now()
    ended = _now()
    return {
        "id": session["id"], "hostname": session["hostname"], "mode": session["mode"], "allowed_paths": session["allowed_paths"],
        "started_at": started, "ended_at": ended, "duration_seconds": int(time.monotonic() - session["created"]),
        "final_url": snapshot.get("url", ""), "title": snapshot.get("title", ""),
        "load_error": session.get("load_error", ""), "blocked_requests": session["blocked"], "blocked_hosts": dict(list(session["blocked_hosts"].items())[:20]),
        "forms": snapshot.get("forms", []), "controls": snapshot.get("controls", []),
        "network": [{k: v for k, v in item.items() if k in {"method", "url", "resource_type", "status_code", "response_content_type", "body_shape", "observed_at"}} for item in session["network"]],
        "events": list(session["events"]),
        "candidate_source": await candidate_source_dict(session, redacted_route_template),
        "policy": session["policy"], "policy_fingerprint": session["policy_fingerprint"],
        "permission_counts": dict(session["permission_counts"]), "permission_events": list(session["permission_events"]),
        "budget": session["budget"].snapshot(),
        "coverage": _coverage(session),
        "privacy": {"values_captured": False, "bodies_captured": False, "frames_stored": False},
    }


async def close_session(session_id: str) -> dict[str, Any] | None:
    """Close a session; its metadata capture is kept in memory for the control plane to collect."""
    session = live_sessions.get(session_id)
    if not session:
        return finished_captures.get(session_id)
    capture: dict[str, Any] | None = None
    try:
        capture = await build_capture(session)
    except Exception as exc:
        logging.getLogger("waf.live").warning("capture could not be built: %s", type(exc).__name__)
    live_sessions.pop(session_id, None)
    session["closed"] = True
    if capture:
        finished_captures[session_id] = capture
        while len(finished_captures) > MAX_FINISHED_CAPTURES:
            finished_captures.popitem(last=False)
    for task in session.get("tasks", []):
        if task is not asyncio.current_task():
            task.cancel()
    try:
        await session["cdp"].send("Page.stopScreencast")
    except Exception:
        pass
    try:
        await session["context"].close()
    except Exception:
        pass
    return capture


async def _reap_loop() -> None:
    while True:
        await asyncio.sleep(15)
        now = time.monotonic()
        for session_id, session in list(live_sessions.items()):
            idle = now - session["touched"] > IDLE_TTL_SECONDS
            too_long = now - session["created"] > MAX_DURATION_SECONDS
            unclaimed = not session["ws_connected"] and now - session["created"] > UNCLAIMED_TTL_SECONDS and not session["ever_connected"]
            if idle or too_long or unclaimed:
                await _notify(session, {"type": "status", "state": "expired", "reason": "idle" if idle else "max-duration" if too_long else "unclaimed"})
                await close_session(session_id)


async def _notify(session: dict[str, Any], message: dict[str, Any]) -> None:
    ws = session.get("ws")
    if ws is not None:
        try:
            await ws.send_json(message)
        except Exception:
            pass


async def _attach_page(session: dict[str, Any], page: Any) -> None:
    previous = session.get("cdp")
    if previous is not None:
        try:
            await previous.send("Page.stopScreencast")
        except Exception:
            pass
    cdp = await session["context"].new_cdp_session(page)
    session["cdp"], session["page"] = cdp, page

    async def on_frame(params: dict[str, Any]) -> None:
        try:
            await cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]})
            meta = params.get("metadata", {})
            frame = {"type": "frame", "data": params["data"], "w": meta.get("deviceWidth"), "h": meta.get("deviceHeight"), "scroll_y": meta.get("scrollOffsetY", 0)}
            queue: asyncio.Queue[dict[str, Any]] = session["queue"]
            if queue.full():
                try:
                    queue.get_nowait()  # drop the oldest frame; never build a backlog
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(frame)
        except Exception as exc:  # a failed frame must never break the session
            logging.getLogger("waf.live").warning("screencast frame dropped: %s", type(exc).__name__)

    cdp.on("Page.screencastFrame", lambda params: asyncio.create_task(on_frame(params)))
    width, height = session["viewport"]
    await cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False})
    await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 60, "maxWidth": width, "maxHeight": height, "everyNthFrame": 1})

    def on_close() -> None:
        remaining = [p for p in session["context"].pages if not p.is_closed()]
        if remaining and not session.get("closed"):
            asyncio.create_task(_attach_page(session, remaining[-1]))

    page.on("close", lambda _page: on_close())
    page.on("dialog", lambda dialog: asyncio.create_task(_dismiss(session, dialog)))


async def push_still_frame(session: dict[str, Any]) -> None:
    """Screencast only emits on repaint, so send one still frame when a viewer connects."""
    try:
        shot = await session["cdp"].send("Page.captureScreenshot", {"format": "jpeg", "quality": 60})
        queue: asyncio.Queue[dict[str, Any]] = session["queue"]
        if queue.full():
            queue.get_nowait()
        width, height = session["viewport"]
        queue.put_nowait({"type": "frame", "data": shot["data"], "w": width, "h": height, "scroll_y": 0})
    except Exception:
        pass


async def _dismiss(session: dict[str, Any], dialog: Any) -> None:
    session["events"].append({"type": "dialog", "dialog_type": dialog.type, "observed_at": _now()})
    try:
        await dialog.dismiss()
    except Exception:
        pass


def _build_recorders(session: dict[str, Any]) -> tuple[Callable[[Any], None], Callable[[Any], None]]:
    hostname, mode = session["hostname"], session["mode"]

    def on_request(request: Any) -> None:
        if (urlparse(request.url).hostname or "").lower() != hostname:
            return
        method = request.method.upper()
        item: dict[str, Any] = {
            "id": f"{len(session['network'])}-{int(time.monotonic() * 1000)}",
            "method": method, "url": redact_url(request.url), "resource_type": request.resource_type,
            "status_code": None, "observed_at": _now(),
            "request_header_names": sorted(str(n).lower()[:128] for n in request.headers.keys())[:100],
            "response_header_names": [], "response_content_type": "", "body_shape": None, "_key": id(request),
        }
        if mode == "free" and method not in {"GET", "HEAD", "OPTIONS"}:
            try:
                body = request.post_data  # parsed in memory, reduced to a shape, then dropped
            except Exception:
                body = None
            item["body_shape"] = post_body_shape(request.headers.get("content-type", ""), body)
            body = None
        session["network"].append(item)

    def on_response(response: Any) -> None:
        request = response.request
        for item in reversed(session["network"]):
            if item["_key"] == id(request):
                item["status_code"] = response.status
                item["response_content_type"] = response.headers.get("content-type", "").split(";", 1)[0][:128]
                item["response_header_names"] = sorted(str(n).lower()[:128] for n in response.headers.keys())[:100]
                break

    return on_request, on_response


async def create_session(browser: Any, request: LiveSessionRequest) -> dict[str, Any]:
    if request.mode not in MODES:
        raise HTTPException(status_code=422, detail="mode must be read_only or free")
    try:
        policy = build_policy(request.policy_preset or ("operator_free" if request.mode == "free" else "read_only"), request.policy_overrides)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid discovery policy: {exc}") from exc
    reason = scan_target_error(request.url)
    if reason:
        raise HTTPException(status_code=422, detail=f"Target refused: {reason}")
    if (urlparse(request.url).hostname or "").lower() != request.hostname.lower():
        raise HTTPException(status_code=422, detail="url host does not match hostname")
    global _reaper
    async with _create_lock:
        if len(live_sessions) >= MAX_LIVE_SESSIONS:
            raise HTTPException(status_code=429, detail="Live browser session limit reached")
        context = await browser.new_context(viewport={"width": VIEWPORT[0], "height": VIEWPORT[1]}, accept_downloads=False, service_workers="block", ignore_https_errors=request.ignore_https_errors)
        session_id = new_live_session_id()
        session: dict[str, Any] = {
            "id": session_id, "mode": request.mode, "hostname": request.hostname.lower(), "allowed_paths": request.allowed_paths or ["/"],
            "context": context, "page": None, "cdp": None, "viewport": VIEWPORT, "queue": asyncio.Queue(maxsize=2),
            "network": deque(maxlen=MAX_NETWORK), "events": deque(maxlen=MAX_EVENTS), "blocked": 0, "blocked_hosts": {}, "load_error": "", "tasks": [],
            "policy": policy, "policy_fingerprint": policy_fingerprint(policy), "budget": Budget(policy["budgets"]),
            "permission_events": [], "permission_counts": {}, "budget_exhausted": False,
            "ws": None, "ws_connected": False, "ever_connected": False, "closed": False,
            "created": time.monotonic(), "touched": time.monotonic(), "started_at": _now(),
        }
        live_sessions[session_id] = session
    try:
        async def route_handler(route: Any) -> None:
            r = route.request
            if live_request_allowed(session["mode"], r.method, r.url, r.resource_type, session["hostname"], session["allowed_paths"]) and apply_policy(
                session, r.method, r.url, r.resource_type, r.headers.get("content-type", "")
            ):
                await route.continue_()
            else:
                session["blocked"] += 1
                label = f"{r.method} {urlparse(r.url).netloc[:80]} ({r.resource_type})"
                if label in session["blocked_hosts"] or len(session["blocked_hosts"]) < 20:
                    session["blocked_hosts"][label] = session["blocked_hosts"].get(label, 0) + 1
                await route.abort("blockedbyclient")

        async def ws_handler(ws_route: Any) -> None:
            if session["mode"] == "free" and live_request_allowed("free", "GET", ws_route.url, "websocket", session["hostname"], session["allowed_paths"]) and apply_policy(session, "GET", ws_route.url, "websocket"):
                ws_route.connect_to_server()
            else:
                await ws_route.close(code=1008, reason="WebSocket not permitted in this mode")

        async def record_event(source: Any, event: dict[str, Any]) -> None:
            if event.get("type") not in {"focus", "click", "input", "change", "submit"}:
                return
            session["events"].append({
                "type": event["type"], "tag": str(event.get("tag", ""))[:32], "input_type": str(event.get("input_type", ""))[:32],
                "name": str(event.get("name", ""))[:256], "id_attribute": str(event.get("id", ""))[:256],
                "form_method": str(event.get("form_method", ""))[:16], "form_action": redact_url(str(event.get("form_action", ""))[:2048]),
                "length_bucket": str(event.get("length_bucket", ""))[:12], "observed_at": _now(),
            })

        await context.route("**/*", route_handler)
        await context.route_web_socket("**/*", ws_handler)
        await context.expose_binding("__wafLiveRecord", record_event)
        await context.add_init_script(f"({INIT_SCRIPT})()")
        on_request, on_response = _build_recorders(session)
        context.on("request", on_request)
        context.on("response", on_response)
        page = await context.new_page()
        await _attach_page(session, page)
        context.on("page", lambda new_page: asyncio.create_task(_attach_page(session, new_page)))  # popups / new tabs
        try:
            await page.goto(request.url, wait_until="domcontentloaded", timeout=20_000)
        except Exception as exc:
            # a slow or failing page still streams; keep the reason so the admin can see it
            session["load_error"] = str(exc).split("\n", 1)[0][:200]
    except Exception as exc:
        await close_session(session_id)
        raise HTTPException(status_code=502, detail=f"Live browser start failed: {type(exc).__name__}") from exc
    if _reaper is None or _reaper.done():
        _reaper = asyncio.create_task(_reap_loop())
    return {"id": session_id, "mode": request.mode, "viewport": {"width": VIEWPORT[0], "height": VIEWPORT[1]}, "idle_ttl_seconds": IDLE_TTL_SECONDS, "max_duration_seconds": MAX_DURATION_SECONDS}


async def _snapshot(session: dict[str, Any]) -> dict[str, Any]:
    try:
        dom = await session["page"].evaluate(SNAPSHOT_SCRIPT)
    except Exception:
        dom = {"url": "", "title": "", "forms": [], "controls": []}
    for form in dom.get("forms", []):
        form["action"] = redact_url(str(form.get("action", "")))
    for control in dom.get("controls", []):
        verdict = classify_field(control)
        control["role"] = verdict["role"] if verdict else "action"
        control["injection_prone"] = bool(verdict and verdict["injection_prone"])
    dom["url"] = redact_url(str(dom.get("url", "")))
    recent = [{k: v for k, v in item.items() if k in {"method", "url", "resource_type", "status_code"} or k == "body_shape"} for item in list(session["network"])[-60:]]
    return {"type": "snapshot", **dom, "network": recent, "blocked_requests": session["blocked"], "blocked_hosts": dict(list(session["blocked_hosts"].items())[:10]), "load_error": session["load_error"], "event_count": len(session["events"]),
            "coverage": {k: v for k, v in _coverage(session).items() if k in {"status", "explored", "failure_counts"}}, "pending_classification": sum(1 for e in session["permission_events"] if e["action"] == "pause")}


async def _sender(session: dict[str, Any], ws: WebSocket) -> None:
    while True:
        await ws.send_json(await session["queue"].get())


async def _snapshots(session: dict[str, Any], ws: WebSocket) -> None:
    while True:
        await ws.send_json(await _snapshot(session))
        await asyncio.sleep(SNAPSHOT_INTERVAL_SECONDS)


async def _handle(session: dict[str, Any], message: dict[str, Any], ws: WebSocket) -> None:
    kind = message.get("type")
    cdp, page = session["cdp"], session["page"]
    if kind in {"mouse", "key", "text", "nav", "viewport"}:
        session["touched"] = time.monotonic()
    if kind == "mouse":
        params = mouse_to_cdp(message)
        if params:
            await cdp.send("Input.dispatchMouseEvent", params)
    elif kind == "key":
        params = key_to_cdp(message)
        if params:
            await cdp.send("Input.dispatchKeyEvent", params)
    elif kind == "text":
        await cdp.send("Input.insertText", {"text": str(message.get("text", ""))[:1000]})
    elif kind == "nav":
        action = message.get("action")
        if action == "back":
            await page.go_back(wait_until="domcontentloaded")
        elif action == "forward":
            await page.go_forward(wait_until="domcontentloaded")
        elif action == "reload":
            await page.reload(wait_until="domcontentloaded")
        elif action == "goto":
            url = str(message.get("url", ""))[:2048]
            if not live_request_allowed(session["mode"], "GET", url, "document", session["hostname"], session["allowed_paths"]):
                await ws.send_json({"type": "error", "message": "That URL is outside the approved host/path scope"})
            elif not session["budget"].charge_action():
                session["budget_exhausted"] = True
                await ws.send_json({"type": "error", "message": "Action budget for this run is exhausted"})
            else:
                await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
    elif kind == "viewport":
        width = int(max(640, min(1920, float(message.get("width", VIEWPORT[0])))))
        height = int(max(400, min(1200, float(message.get("height", VIEWPORT[1])))))
        session["viewport"] = (width, height)
        await _attach_page(session, page)
    elif kind == "inspect":
        info = await page.evaluate(INSPECT_SCRIPT, [float(message.get("x", 0)), float(message.get("y", 0))])
        if info:
            info["form_action"] = redact_url(str(info.get("form_action", "")))
        await ws.send_json({"type": "inspected", "element": info})
    elif kind == "snapshot":
        await ws.send_json(await _snapshot(session))


def build_live_router(ensure_browser: Callable[[], Awaitable[Any]], redacted_route_template: Callable[[str], str]) -> APIRouter:
    router = APIRouter(prefix="/live")

    @router.post("/sessions", status_code=201)
    async def start(request: LiveSessionRequest) -> dict[str, Any]:
        return await create_session(await ensure_browser(), request)

    @router.delete("/sessions/{session_id}")
    async def stop(session_id: str) -> dict[str, Any]:
        existed = session_id in live_sessions
        capture = await close_session(session_id)
        return {"closed": existed, "capture": capture}

    @router.get("/captures/{session_id}")
    async def finished(session_id: str) -> dict[str, Any]:
        capture = finished_captures.get(session_id)
        if not capture:
            raise HTTPException(status_code=404, detail="Capture not found")
        return capture

    @router.get("/sessions/{session_id}/candidate-source")
    async def candidate_source(session_id: str) -> dict[str, Any]:
        session = live_sessions.get(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Live browser session not found or expired")
        return await candidate_source_dict(session, redacted_route_template)

    @router.websocket("/sessions/{session_id}/ws")
    async def stream(ws: WebSocket, session_id: str) -> None:
        session = live_sessions.get(session_id)
        if not session or session["ws_connected"]:
            await ws.close(code=4404 if not session else 4409)
            return
        await ws.accept()
        session.update(ws=ws, ws_connected=True, ever_connected=True, touched=time.monotonic())
        tasks = [asyncio.create_task(_sender(session, ws)), asyncio.create_task(_snapshots(session, ws))]
        session["tasks"].extend(tasks)
        try:
            await ws.send_json({"type": "status", "state": "live", "mode": session["mode"], "viewport": list(session["viewport"])})
            await push_still_frame(session)
            while True:
                message = await ws.receive_json()
                if isinstance(message, dict):
                    try:
                        await _handle(session, message, ws)
                    except WebSocketDisconnect:
                        raise
                    except Exception as exc:  # keep the stream alive on a bad input event
                        await ws.send_json({"type": "error", "message": type(exc).__name__})
        except WebSocketDisconnect:
            pass
        finally:
            session["ws_connected"] = False
            await close_session(session_id)

    return router
