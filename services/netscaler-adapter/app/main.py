import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.nextgen import (
    OAS_CONTRACT,
    OAS_VERSION,
    application_path,
    base_url,
    get,
    normalize_csvservers,
    normalize_lbvservers,
    normalize_services,
    secret_present,
    topology_payload,
    unsupported_appfw,
    write_enabled,
)
from app.rule_catalog import load_rule_catalog


app = FastAPI(title="NetScaler Next-Gen Adapter", version="0.2.0")


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


def _raise_upstream(status: int, data: Any) -> None:
    if status >= 300:
        reason = data.get("reason", "Next-Gen API request failed") if isinstance(data, dict) else "Next-Gen API request failed"
        raise HTTPException(status_code=502 if status >= 500 else status, detail=reason)


def _unsupported_write(resource: str) -> None:
    raise HTTPException(
        status_code=501,
        detail={
            "status": "unsupported-by-oas",
            "provider": "netscaler-nextgen",
            "resource": resource,
            "reason": "The supplied OAS has no AppFW/signature operation and no fallback API is permitted.",
            "write_enabled": write_enabled(),
        },
    )


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    host = os.getenv("NETSCALER_HOST", "")
    result: dict[str, Any] = {
        "status": "ok",
        "service": "netscaler-adapter",
        "provider": "netscaler-nextgen",
        "api_contract": OAS_CONTRACT,
        "api_version": OAS_VERSION,
        "target": host,
        "credential_configured": secret_present(),
        "mode": "read-only" if not write_enabled() else "write-enabled-but-waf-write-unsupported",
        "base_url": base_url(host),
    }
    try:
        status, data = await get("/applications")
        result["nextgen_http_status"] = status
        result["authenticated"] = status < 300
        result["reachable"] = True
        result["applications_data_present"] = bool(data)
        if isinstance(data, dict) and status >= 300:
            result["error_status"] = data.get("http_status", status)
            result["error_reason"] = data.get("reason")
    except Exception as exc:  # healthz must remain diagnostic and non-fatal
        result["reachable"] = False
        result["authenticated"] = False
        result["error_type"] = type(exc).__name__
    return result


@app.get("/api/adc/target")
async def target() -> dict[str, str]:
    return {
        "host": os.getenv("NETSCALER_HOST", ""),
        "username": os.getenv("NETSCALER_USERNAME", ""),
        "provider": "netscaler-nextgen",
        "api_contract": OAS_CONTRACT,
        "api_version": OAS_VERSION,
    }


@app.get("/api/adc/version")
async def version() -> dict[str, Any]:
    return {
        "provider": "netscaler-nextgen",
        "status": "not-exposed-by-oas",
        "api_contract": OAS_CONTRACT,
        "api_version": OAS_VERSION,
        "reason": "The supplied OAS has no ADC software-version operation.",
    }


@app.post("/api/adc/connect")
async def connect(request: ConnectionRequest) -> dict[str, Any]:
    status, data = await get("/applications", host=request.nsip, username=request.username, password=request.password)
    if status >= 300:
        raise HTTPException(status_code=401 if status in {401, 403} else 502, detail="NetScaler Next-Gen API authentication or connection failed")
    return {"nsip": request.nsip, "provider": "netscaler-nextgen", "api_version": OAS_VERSION, "version": "unknown", "applications": len(data.get("applications", [])) if isinstance(data, dict) else 0}


async def _applications() -> tuple[int, Any]:
    return await get("/applications")


@app.get("/api/adc/applications")
async def applications() -> Any:
    status, data = await _applications()
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/applications/{application_name}/frontends")
async def application_frontends(application_name: str) -> Any:
    status, data = await get(application_path(application_name, "/frontends"), params={"expanded": "true"})
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/applications/{application_name}/backends")
async def application_backends(application_name: str) -> Any:
    status, data = await get(application_path(application_name, "/backends"), params={"expanded": "true"})
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/applications/{application_name}/routes")
async def application_routes(application_name: str) -> Any:
    status, data = await get(application_path(application_name, "/routes"), params={"expanded": "true"})
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/applications/{application_name}/health")
async def application_health(application_name: str) -> Any:
    status, data = await get(application_path(application_name, "/health"), params={"expanded": "true"})
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/applications/{application_name}/statistics")
async def application_statistics(application_name: str) -> Any:
    status, data = await get(application_path(application_name, "/statistics"), params={"expanded": "true"})
    _raise_upstream(status, data)
    return data


@app.get("/api/adc/appfw/profiles")
async def appfw_profiles() -> Any:
    return {"appfwprofile": [], **unsupported_appfw("appfwprofile")}


@app.get("/api/adc/appfw/policies")
async def appfw_policies() -> Any:
    return {"appfwpolicy": [], **unsupported_appfw("appfwpolicy")}


@app.get("/api/adc/signatures")
async def signatures() -> Any:
    return {"appfwsignatures": [], **unsupported_appfw("appfwsignatures")}


@app.get("/api/adc/signatures/rules")
async def signature_rules() -> dict[str, Any]:
    """Read normalized rule metadata from a read-only administrator-mounted export."""
    return load_rule_catalog(os.getenv("NETSCALER_SIGNATURE_RULE_CATALOG_FILE", ""))


@app.post("/api/adc/writes/appfw-profile-signature")
async def write_appfw_profile_signature(request: AppFwProfileSignatureWriteRequest) -> dict[str, Any]:
    _unsupported_write("appfwprofile")
    return {}


@app.post("/api/adc/writes/appfw-profile-duplicate")
async def write_appfw_profile_duplicate(request: AppFwProfileDuplicateWriteRequest) -> dict[str, Any]:
    _unsupported_write("appfwprofile")
    return {}


@app.post("/api/adc/writes/signature-set")
async def write_signature_set(request: AppFwSignatureSetWriteRequest) -> dict[str, Any]:
    _unsupported_write("appfwsignatures")
    return {}


@app.delete("/api/adc/writes/appfw-profile-duplicate/{profile_name}")
async def delete_appfw_profile_duplicate(profile_name: str) -> dict[str, Any]:
    _unsupported_write("appfwprofile")
    return {}


@app.get("/api/adc/lbvservers")
async def lbvservers() -> Any:
    status, data = await _applications()
    _raise_upstream(status, data)
    return {"lbvserver": normalize_lbvservers(data), "provider": "netscaler-nextgen", "applications": data.get("applications", []) if isinstance(data, dict) else []}


@app.get("/api/adc/csvservers")
async def csvservers() -> Any:
    status, data = await _applications()
    _raise_upstream(status, data)
    return {"csvserver": normalize_csvservers(data), "provider": "netscaler-nextgen"}


@app.get("/api/adc/cspolicies")
async def cspolicies() -> Any:
    return {"cspolicy": [], "provider": "netscaler-nextgen", "status": "not-exposed-by-oas", "reason": "Next-Gen routes are not classic CS policies."}


@app.get("/api/adc/services")
async def services() -> Any:
    status, data = await _applications()
    _raise_upstream(status, data)
    return {"service": normalize_services(data), "provider": "netscaler-nextgen"}


@app.get("/api/adc/servicegroups")
async def servicegroups() -> Any:
    return {"servicegroup": [], "provider": "netscaler-nextgen", "status": "not-exposed-by-oas"}


@app.get("/api/adc/ha/nodes")
async def ha_nodes() -> Any:
    return {"hanode": [], "provider": "netscaler-nextgen", "status": "not-exposed-by-oas", "reason": "The supplied OAS has no HA node operation."}


@app.get("/api/adc/topology")
async def topology() -> Any:
    status, data = await _applications()
    _raise_upstream(status, data)
    return topology_payload(data)
