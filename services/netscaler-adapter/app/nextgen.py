"""Small, contract-shaped client for the supplied NetScaler Next-Gen OAS.

The OAS uses cookie authentication: POST /login creates a sessionid cookie and
all subsequent calls reuse that cookie. This module deliberately has no legacy
API URL, header, or resource fallback.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx


OAS_VERSION = "0.1.10"
OAS_BASE_PATH = "/mgmt/api/nextgen/v1"
OAS_CONTRACT = "NetScaler Next-Gen API"


def read_secret() -> str:
    path = os.getenv("NETSCALER_PASSWORD_FILE", "")
    if not path or not Path(path).is_file():
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def secret_present() -> bool:
    return bool(read_secret())


def write_enabled() -> bool:
    return os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true"


def base_url(host: str | None = None) -> str:
    configured = os.getenv("NETSCALER_NEXTGEN_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    scheme = os.getenv("NETSCALER_NEXTGEN_SCHEME", "https").strip().lower() or "https"
    target = host or os.getenv("NETSCALER_HOST", "")
    return f"{scheme}://{target}{OAS_BASE_PATH}"


def unsupported_appfw(resource: str) -> dict[str, Any]:
    return {
        "provider": "netscaler-nextgen",
        "status": "unsupported-by-oas",
        "resource": resource,
        "records": [],
        "reason": (
            "The supplied NetScaler Next-Gen OAS does not define AppFW profiles, "
            "AppFW policies, or signature catalog operations. No legacy API fallback is allowed."
        ),
        "automatic_apply_allowed": False,
    }


def _json_or_error(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {
            "provider": "netscaler-nextgen",
            "status": "non-json-response",
            "http_status": response.status_code,
            "reason": "The Next-Gen API returned a non-JSON response.",
        }


async def request(
    method: str,
    path: str,
    *,
    host: str | None = None,
    username: str | None = None,
    password: str | None = None,
    params: dict[str, Any] | None = None,
    json: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    username = username or os.getenv("NETSCALER_USERNAME", "")
    password = password or read_secret()
    target = host or os.getenv("NETSCALER_HOST", "")
    if not target or not username or not password:
        return 503, {"provider": "netscaler-nextgen", "status": "credential-not-configured"}

    timeout = float(os.getenv("NETSCALER_NEXTGEN_TIMEOUT_SECONDS", "15"))
    async with httpx.AsyncClient(base_url=base_url(target), verify=False, timeout=timeout) as client:
        login = await client.post(
            "/login",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={
                "login": {
                    "username": username,
                    "password": password,
                    "timeout": os.getenv("NETSCALER_NEXTGEN_SESSION_TIMEOUT", "30min"),
                }
            },
        )
        if login.status_code >= 300:
            return login.status_code, {
                "provider": "netscaler-nextgen",
                "status": "login-failed",
                "http_status": login.status_code,
                "reason": "Next-Gen API login failed; response body was intentionally omitted.",
            }

        response = await client.request(
            method,
            path,
            params=params,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json=json,
        )
        return response.status_code, _json_or_error(response)


async def get(path: str, **kwargs: Any) -> tuple[int, Any]:
    return await request("GET", path, **kwargs)


def _unwrap(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get("application"), dict):
        return value["application"]
    return value if isinstance(value, dict) else {}


def application_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("applications"), list):
        return [_unwrap(item) for item in payload["applications"] if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get("application"), dict):
        return [_unwrap(payload)]
    return []


def _list(value: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get(key), list):
        return [item for item in value[key] if isinstance(item, dict)]
    return []


def normalize_lbvservers(payload: Any) -> list[dict[str, Any]]:
    """Map Next-Gen applications/frontends to the legacy UI-neutral LB shape."""
    result: list[dict[str, Any]] = []
    for app in application_items(payload):
        app_name = str(app.get("name", ""))
        frontends = _list(app, "frontends")
        if not frontends:
            frontends = [app]
        for frontend in frontends:
            frontend_name = str(frontend.get("name", "_default"))
            listeners = _list(frontend, "listeners") or [frontend]
            for listener in listeners:
                name = app_name if frontend_name == "_default" else f"{app_name}-{frontend_name}"
                if len(listeners) > 1 and listener is not frontend:
                    name = f"{name}-{listener.get('name', 'listener')}"
                result.append(
                    {
                        "name": name,
                        "application": app_name,
                        "frontend": frontend_name,
                        "ipv46": listener.get("virtual_ip", frontend.get("virtual_ip", app.get("virtual_ip"))),
                        "ip": listener.get("virtual_ip", frontend.get("virtual_ip", app.get("virtual_ip"))),
                        "port": listener.get("port", frontend.get("port", app.get("port"))),
                        "protocol": listener.get("protocol", frontend.get("protocol", app.get("protocol"))),
                        "servicetype": listener.get("protocol", frontend.get("protocol", app.get("protocol"))),
                        "curstate": app.get("operational_state", app.get("operational_state")),
                        "state": app.get("configured_state", frontend.get("configured_state")),
                        "provider": "netscaler-nextgen",
                    }
                )
    return result


def normalize_services(payload: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for app in application_items(payload):
        app_name = str(app.get("name", ""))
        backends = _list(app, "backends")
        if not backends and app.get("servers") is not None:
            backends = [app]
        for backend in backends:
            backend_name = str(backend.get("name", "_default"))
            servers = backend.get("servers", [])
            if not isinstance(servers, list):
                servers = []
            for server in servers:
                if isinstance(server, str):
                    server = {"ip": server}
                if not isinstance(server, dict):
                    continue
                result.append(
                    {
                        "name": f"{app_name}-{backend_name}-{server.get('ip', server.get('fqdn', 'server'))}",
                        "application": app_name,
                        "backend": backend_name,
                        "servername": server.get("ip", server.get("fqdn")),
                        "port": server.get("port", backend.get("servers_port", app.get("servers_port"))),
                        "svrstate": server.get("operational_state", "UNKNOWN"),
                        "provider": "netscaler-nextgen",
                    }
                )
    return result


def normalize_csvservers(payload: Any) -> list[dict[str, Any]]:
    return [item for item in normalize_lbvservers(payload) if str(item.get("protocol", "")).upper() == "HTTPS"]


def topology_payload(payload: Any) -> dict[str, Any]:
    return {
        "provider": "netscaler-nextgen",
        "api_contract": OAS_CONTRACT,
        "api_version": OAS_VERSION,
        "applications": application_items(payload),
        "lbvserver": normalize_lbvservers(payload),
        "csvserver": normalize_csvservers(payload),
        "service": normalize_services(payload),
        "servicegroup": [],
        "cspolicy": [],
        "nextgen_only": True,
    }


def application_path(name: str, suffix: str = "") -> str:
    return f"/applications/{quote(name, safe='')}{suffix}"
