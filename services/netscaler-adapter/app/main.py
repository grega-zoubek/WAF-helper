import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="NetScaler Adapter", version="0.1.0")


class ConnectionRequest(BaseModel):
    nsip: str = Field(min_length=3, max_length=64)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


class AppFwProfileSignatureWriteRequest(BaseModel):
    profile_name: str = Field(min_length=1, max_length=128)
    signature_name: str = Field(min_length=1, max_length=128)


class AppFwProfileDuplicateWriteRequest(BaseModel):
    destination_profile: str = Field(min_length=1, max_length=128)
    profile_type: list[str] | str | None = None
    signature_binding: str | None = Field(default=None, max_length=200)


class AppFwSignatureSetWriteRequest(BaseModel):
    destination_profile: str = Field(min_length=1, max_length=128)
    profile_type: list[str] | str | None = None
    signature_name: str = Field(min_length=1, max_length=200)
    enable: bool = True


def read_secret() -> str:
    path = os.getenv("NETSCALER_PASSWORD_FILE", "")
    if not path or not Path(path).is_file():
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def secret_present() -> bool:
    return bool(read_secret())


def write_enabled() -> bool:
    return os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true"


def adc_base_url(host: str | None = None) -> str:
    return f"https://{host or os.getenv('NETSCALER_HOST', '')}/nitro/v1/config"


async def nitro_get(resource: str, host: str | None = None, username: str | None = None, password: str | None = None) -> tuple[int, Any]:
    allowed = {
        "nsversion",
        "lbvserver",
        "csvserver",
        "cspolicy",
        "csaction",
        "service",
        "servicegroup",
        "appfwprofile",
        "appfwpolicy",
        "appfwsignatures",
        "hanode",
        "nshaconfig",
    }
    if resource not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported read-only resource")
    password = password or read_secret()
    username = username or os.getenv("NETSCALER_USERNAME", "")
    if not password or not username or not (host or os.getenv("NETSCALER_HOST", "")):
        raise HTTPException(status_code=503, detail="ADC credential is not configured")
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        response = await client.get(
            f"{adc_base_url(host)}/{resource}",
            headers={
                "X-NITRO-USER": username,
                "X-NITRO-PASS": password,
                "Accept": "application/json",
            },
        )
        try:
            data = response.json()
        except ValueError:
            data = {"raw": "non-json response omitted"}
        return response.status_code, data


async def nitro_put(resource: str, payload: dict[str, Any]) -> tuple[int, Any]:
    if not write_enabled():
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if resource != "appfwprofile":
        raise HTTPException(status_code=400, detail="Unsupported write resource")
    password = read_secret()
    username = os.getenv("NETSCALER_USERNAME", "")
    host = os.getenv("NETSCALER_HOST", "")
    if not password or not username or not host:
        raise HTTPException(status_code=503, detail="ADC write credential is not configured")
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        response = await client.put(
            f"{adc_base_url(host)}/{resource}",
            headers={"X-NITRO-USER": username, "X-NITRO-PASS": password, "Accept": "application/json", "Content-Type": "application/json"},
            json=payload,
        )
        try:
            data = response.json()
        except ValueError:
            data = {"message": "non-json ADC response"}
        return response.status_code, data


async def nitro_post(resource: str, payload: dict[str, Any]) -> tuple[int, Any]:
    if not write_enabled():
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if resource != "appfwprofile":
        raise HTTPException(status_code=400, detail="Unsupported write resource")
    password = read_secret()
    username = os.getenv("NETSCALER_USERNAME", "")
    host = os.getenv("NETSCALER_HOST", "")
    if not password or not username or not host:
        raise HTTPException(status_code=503, detail="ADC write credential is not configured")
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        response = await client.post(
            f"{adc_base_url(host)}/{resource}",
            headers={"X-NITRO-USER": username, "X-NITRO-PASS": password, "Accept": "application/json", "Content-Type": "application/json"},
            json=payload,
        )
        try:
            data = response.json()
        except ValueError:
            data = {"message": "non-json ADC response"}
        return response.status_code, data


async def nitro_delete(resource: str, name: str) -> tuple[int, Any]:
    if not write_enabled():
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if resource != "appfwprofile":
        raise HTTPException(status_code=400, detail="Unsupported write resource")
    password = read_secret()
    username = os.getenv("NETSCALER_USERNAME", "")
    host = os.getenv("NETSCALER_HOST", "")
    if not password or not username or not host:
        raise HTTPException(status_code=503, detail="ADC write credential is not configured")
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        response = await client.delete(
            f"{adc_base_url(host)}/{resource}/{quote(name, safe='')}",
            headers={"X-NITRO-USER": username, "X-NITRO-PASS": password, "Accept": "application/json"},
        )
        try:
            data = response.json()
        except ValueError:
            data = {"message": "non-json ADC response"}
        return response.status_code, data


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    host = os.getenv("NETSCALER_HOST", "")
    result: dict[str, Any] = {
        "status": "ok",
        "service": "netscaler-adapter",
        "target": host,
        "credential_configured": secret_present(),
        "mode": "read-only",
    }
    try:
        status, data = await nitro_get("nsversion")
        result["adc_http_status"] = status
        result["authenticated"] = status < 300
        result["reachable"] = True
        result["version_data_present"] = bool(data)
        if isinstance(data, dict):
            result["nitro_error_code"] = data.get("errorcode")
            result["nitro_message"] = data.get("message")
    except (httpx.HTTPError, HTTPException) as exc:
        result["reachable"] = False
        result["authenticated"] = False
        result["error_type"] = type(exc).__name__
        if isinstance(exc, HTTPException):
            result["error_status"] = exc.status_code
    return result


@app.get("/api/adc/target")
async def target() -> dict[str, str]:
    return {"host": os.getenv("NETSCALER_HOST", ""), "username": os.getenv("NETSCALER_USERNAME", "")}


@app.get("/api/adc/version")
async def version() -> Any:
    return (await nitro_get("nsversion"))[1]


def extract_version(data: Any) -> str:
    if isinstance(data, dict):
        records = data.get("nsversion")
        if isinstance(records, dict):
            for key in ("version", "installedversion", "build"):
                if records.get(key) and key == "version":
                    return str(records[key])[:500]
        if isinstance(records, list) and records and isinstance(records[0], dict):
            for key in ("version", "versionnumber", "build"):
                if records[0].get(key):
                    return str(records[0][key])[:500]
    return "unknown"


@app.post("/api/adc/connect")
async def connect(request: ConnectionRequest) -> dict[str, str]:
    status, data = await nitro_get("nsversion", request.nsip, request.username, request.password)
    if status >= 300:
        raise HTTPException(status_code=401, detail="NetScaler authentication or connection failed")
    return {"nsip": request.nsip, "version": extract_version(data)}


@app.get("/api/adc/appfw/profiles")
async def appfw_profiles() -> Any:
    return (await nitro_get("appfwprofile"))[1]


@app.get("/api/adc/appfw/policies")
async def appfw_policies() -> Any:
    return (await nitro_get("appfwpolicy"))[1]


@app.get("/api/adc/signatures")
async def signatures() -> Any:
    return (await nitro_get("appfwsignatures"))[1]


@app.post("/api/adc/writes/appfw-profile-signature")
async def write_appfw_profile_signature(request: AppFwProfileSignatureWriteRequest) -> dict[str, Any]:
    status, data = await nitro_put("appfwprofile", {"appfwprofile": {"name": request.profile_name, "signatures": request.signature_name}})
    if status >= 300:
        raise HTTPException(status_code=502, detail="NetScaler AppFW profile update failed")
    return {"changes_applied": True, "resource": "appfwprofile", "profile_name": request.profile_name, "signature_name": request.signature_name, "adc_status": status, "adc_result": data}


@app.post("/api/adc/writes/appfw-profile-duplicate")
async def write_appfw_profile_duplicate(request: AppFwProfileDuplicateWriteRequest) -> dict[str, Any]:
    profile: dict[str, Any] = {"name": request.destination_profile}
    if request.profile_type:
        profile["type"] = request.profile_type
    if request.signature_binding and request.signature_binding.strip():
        profile["signatures"] = request.signature_binding.strip()
    status, data = await nitro_post("appfwprofile", {"appfwprofile": profile})
    if status >= 300:
        raise HTTPException(status_code=502, detail="NetScaler AppFW profile duplication failed")
    return {"changes_applied": True, "resource": "appfwprofile", "destination_profile": request.destination_profile, "adc_status": status, "adc_result": data}


@app.post("/api/adc/writes/signature-set")
async def write_signature_set(request: AppFwSignatureSetWriteRequest) -> dict[str, Any]:
    profile: dict[str, Any] = {"name": request.destination_profile, "signatures": request.signature_name}
    if request.profile_type:
        profile["type"] = request.profile_type
    create_status, create_data = await nitro_post("appfwprofile", {"appfwprofile": profile})
    if create_status >= 300:
        raise HTTPException(status_code=502, detail="NetScaler signature profile creation failed")
    enable_status = None
    enable_data: Any = None
    if request.enable:
        enable_status, enable_data = await nitro_put("appfwprofile", {"appfwprofile": {"name": request.destination_profile, "state": "ENABLED"}})
        if enable_status >= 300:
            try:
                await nitro_delete("appfwprofile", request.destination_profile)
            except HTTPException:
                pass
            raise HTTPException(status_code=502, detail="NetScaler signature profile was created but could not be enabled; rollback was attempted")
    return {"changes_applied": True, "resource": "appfwprofile", "destination_profile": request.destination_profile, "signature_name": request.signature_name, "enabled": request.enable, "create_status": create_status, "create_result": create_data, "enable_status": enable_status, "enable_result": enable_data}


@app.delete("/api/adc/writes/appfw-profile-duplicate/{profile_name}")
async def delete_appfw_profile_duplicate(profile_name: str) -> dict[str, Any]:
    status, data = await nitro_delete("appfwprofile", profile_name)
    if status >= 300:
        raise HTTPException(status_code=502, detail="NetScaler AppFW duplicate profile rollback failed")
    return {"changes_applied": True, "resource": "appfwprofile", "deleted_profile": profile_name, "adc_status": status, "adc_result": data}


@app.get("/api/adc/lbvservers")
async def lbvservers() -> Any:
    return (await nitro_get("lbvserver"))[1]


@app.get("/api/adc/csvservers")
async def csvservers() -> Any:
    return (await nitro_get("csvserver"))[1]


@app.get("/api/adc/cspolicies")
async def cspolicies() -> Any:
    return (await nitro_get("cspolicy"))[1]


@app.get("/api/adc/services")
async def services() -> Any:
    return (await nitro_get("service"))[1]


@app.get("/api/adc/servicegroups")
async def servicegroups() -> Any:
    return (await nitro_get("servicegroup"))[1]


@app.get("/api/adc/ha/nodes")
async def ha_nodes() -> Any:
    return (await nitro_get("hanode"))[1]
