import asyncio
import copy
import io
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
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
from app.ssh_inventory import collect_waf_inventory, execute_cli_commands


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


class CustomSignatureSetWriteRequest(BaseModel):
    signature_object_name: str = Field(min_length=1, max_length=31)
    rule_ids: list[str] = Field(min_length=1, max_length=5000)
    action: str = Field(default="LOG", max_length=16)


class CustomSignatureSetRollbackRequest(BaseModel):
    signature_object_name: str = Field(min_length=1, max_length=31)


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


def _signature_source_file() -> Path:
    configured = os.getenv("NETSCALER_SIGNATURE_SOURCE_FILE", "").strip()
    if configured and Path(configured).is_file():
        return Path(configured)
    candidates = sorted(Path("/run/upstream-signatures/raw").glob("*.xml"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not candidates:
        raise RuntimeError("Verified upstream signature XML is not mounted")
    return candidates[0]


def _filtered_signature_xml(rule_ids: list[str], action: str) -> bytes:
    root = ET.parse(_signature_source_file()).getroot()
    selected = set(rule_ids)
    found: set[str] = set()
    output_root = ET.Element(root.tag, root.attrib)
    for child in root:
        if child.tag.rsplit("}", 1)[-1] != "Signatures":
            output_root.append(copy.deepcopy(child))
            continue
        signatures = ET.SubElement(output_root, child.tag, child.attrib)
        for rule in child:
            if rule.tag.rsplit("}", 1)[-1] != "SignatureRule":
                continue
            rule_id = str(rule.attrib.get("id", ""))
            if rule_id not in selected:
                continue
            cloned = copy.deepcopy(rule)
            cloned.set("enabled", "ON")
            cloned.set("actions", action.lower())
            signatures.append(cloned)
            found.add(rule_id)
    missing = sorted(selected - found, key=lambda value: int(value) if value.isdigit() else value)
    if missing:
        raise ValueError(f"Verified upstream signature XML is missing rule IDs: {', '.join(missing[:20])}")
    buffer = io.BytesIO()
    ET.ElementTree(output_root).write(buffer, encoding="utf-8", xml_declaration=True)
    return buffer.getvalue()


def _remote_signature_path(signature_object_name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", signature_object_name)[:31]
    return f"/var/tmp/waf-scanner-{safe}.xml"


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


@app.get("/api/adc/inventory")
async def inventory() -> dict[str, Any]:
    """Return an explicit capability-aware inventory for the supplied OAS.

    AppFW profiles, policies, and signature catalogs are intentionally not
    represented as empty provider inventories: the supplied Next-Gen OAS does
    not expose those operations. This distinction prevents callers from
    confusing "not exposed" with "enumerated and empty".
    """
    status, data = await _applications()
    _raise_upstream(status, data)
    application_records = data.get("applications", []) if isinstance(data, dict) else []
    if not isinstance(application_records, list):
        application_records = []
    unsupported_reason = (
        "The supplied NetScaler Next-Gen OAS does not define AppFW profile, "
        "AppFW policy, or signature catalog operations. No legacy API fallback is allowed."
    )
    cli_waf = await asyncio.to_thread(collect_waf_inventory)
    cli_status = str(cli_waf.get("status", "unavailable")) if isinstance(cli_waf, dict) else "unavailable"
    if cli_status in {"enumerated", "feature-disabled", "not-reported"}:
        waf_resources = {
            "appfw_profiles": cli_waf.get("profiles", {}),
            "appfw_policies": cli_waf.get("policies", {}),
            "signature_catalog": cli_waf.get("signatures", {}),
        }
        waf = {
            "status": cli_status,
            "available": True,
            "record_count": sum(int(item.get("record_count", 0)) for item in waf_resources.values() if isinstance(item, dict)),
            "resources": waf_resources,
            "feature": cli_waf.get("feature"),
            "settings": cli_waf.get("settings"),
            "provider": "netscaler-cli-over-ssh",
            "reason": "WAF inventory was read from the ADC CLI over SSH; the Next-Gen OAS has no dedicated AppFW resources.",
            "automatic_apply_allowed": False,
        }
    else:
        waf_resources = {
            resource: {
                "status": "unsupported-by-oas",
                "available": False,
                "record_count": 0,
                "records": [],
                "reason": unsupported_reason,
            }
            for resource in ("appfw_profiles", "appfw_policies", "signature_catalog")
        }
        waf = {
            "status": cli_status if cli_status not in {"not-configured"} else "unsupported-by-oas",
            "available": False,
            "record_count": 0,
            "resources": waf_resources,
            "provider": "netscaler-nextgen",
            "reason": cli_waf.get("reason", unsupported_reason) if isinstance(cli_waf, dict) else unsupported_reason,
            "automatic_apply_allowed": False,
        }
    return {
        "provider": "netscaler-nextgen",
        "api_contract": OAS_CONTRACT,
        "api_version": OAS_VERSION,
        "applications": {
            "status": "enumerated",
            "record_count": len(application_records),
            "records": application_records,
        },
        "waf": waf,
        "classic": cli_waf.get("classic", {"status": cli_status, "automatic_apply_allowed": False}),
        "rule_catalog": load_rule_catalog(os.getenv("NETSCALER_SIGNATURE_RULE_CATALOG_FILE", "")),
        "capabilities": {
            "applications": True,
            "appfw_profiles": cli_status == "enumerated",
            "appfw_policies": cli_status == "enumerated",
            "signature_catalog": cli_status == "enumerated",
            "waf_cli_inventory": cli_status in {"enumerated", "feature-disabled", "not-reported"},
            "rule_level_catalog_import": True,
            "writes": False,
        },
        "write_enabled": write_enabled(),
    }


@app.get("/api/adc/classic-inventory")
async def classic_inventory() -> dict[str, Any]:
    inventory_payload = await asyncio.to_thread(collect_waf_inventory)
    classic = inventory_payload.get("classic", {}) if isinstance(inventory_payload, dict) else {}
    return {
        "provider": classic.get("provider", inventory_payload.get("provider", "netscaler-cli-over-ssh")),
        "status": classic.get("status", inventory_payload.get("status", "unavailable")),
        "classic": classic,
        "waf": {
            "status": inventory_payload.get("status"),
            "feature": inventory_payload.get("feature"),
            "profiles": inventory_payload.get("profiles"),
            "policies": inventory_payload.get("policies"),
            "policy_labels": inventory_payload.get("policy_labels"),
            "signatures": inventory_payload.get("signatures"),
            "settings": inventory_payload.get("settings"),
        },
        "automatic_apply_allowed": False,
    }


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
    inventory_payload = await asyncio.to_thread(collect_waf_inventory)
    profiles = inventory_payload.get("profiles", {}) if isinstance(inventory_payload, dict) else {}
    return {"appfwprofile": profiles.get("records", []), "provider": inventory_payload.get("provider"), "status": profiles.get("status", inventory_payload.get("status")), "source": "cli-over-ssh", "automatic_apply_allowed": False}


@app.get("/api/adc/appfw/policies")
async def appfw_policies() -> Any:
    inventory_payload = await asyncio.to_thread(collect_waf_inventory)
    policies = inventory_payload.get("policies", {}) if isinstance(inventory_payload, dict) else {}
    return {"appfwpolicy": policies.get("records", []), "provider": inventory_payload.get("provider"), "status": policies.get("status", inventory_payload.get("status")), "source": "cli-over-ssh", "automatic_apply_allowed": False}


@app.get("/api/adc/signatures")
async def signatures() -> Any:
    inventory_payload = await asyncio.to_thread(collect_waf_inventory)
    signatures_payload = inventory_payload.get("signatures", {}) if isinstance(inventory_payload, dict) else {}
    return {"appfwsignatures": signatures_payload.get("records", []), "provider": inventory_payload.get("provider"), "status": signatures_payload.get("status", inventory_payload.get("status")), "source": "cli-over-ssh", "automatic_apply_allowed": False}


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


@app.post("/api/adc/writes/custom-signature-set")
async def write_custom_signature_set(request: CustomSignatureSetWriteRequest) -> dict[str, Any]:
    if not write_enabled():
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if not re.fullmatch(r"[A-Za-z0-9_.# @=-]{1,31}", request.signature_object_name):
        raise HTTPException(status_code=422, detail="Invalid NetScaler signature object name")
    action = request.action.upper()
    if action not in {"LOG", "BLOCK"}:
        raise HTTPException(status_code=422, detail="Action must be LOG or BLOCK")
    if any(not re.fullmatch(r"[0-9]{1,10}", str(rule_id)) for rule_id in request.rule_ids):
        raise HTTPException(status_code=422, detail="Rule IDs must be numeric")
    rule_ids = [str(int(rule_id)) for rule_id in request.rule_ids]
    if len(set(rule_ids)) != len(rule_ids):
        raise HTTPException(status_code=422, detail="Rule IDs must be unique")
    remote_path = _remote_signature_path(request.signature_object_name)
    try:
        signature_xml = _filtered_signature_xml(rule_ids, action)
    except (OSError, ET.ParseError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Unable to prepare verified native signature XML: {exc}") from exc
    commands = [
        f"import appfw signatures local:{remote_path} {request.signature_object_name} -autoEnableNewSignatures OFF",
        "save ns config",
    ]
    try:
        result = await asyncio.to_thread(execute_cli_commands, commands, [(remote_path, signature_xml)])
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail="NetScaler CLI export failed") from exc
    return {"status": "applied", "signature_object_name": request.signature_object_name, "action": action, "rule_count": len(rule_ids), "command_count": len(commands), "changes_applied": True, "result": result}


@app.post("/api/adc/writes/custom-signature-set/rollback")
async def rollback_custom_signature_set(request: CustomSignatureSetRollbackRequest) -> dict[str, Any]:
    if not write_enabled():
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if not re.fullmatch(r"[A-Za-z0-9_.# @=-]{1,31}", request.signature_object_name):
        raise HTTPException(status_code=422, detail="Invalid NetScaler signature object name")
    commands = [f"rm appfw signatures {request.signature_object_name}", "save ns config"]
    try:
        result = await asyncio.to_thread(execute_cli_commands, commands)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail="NetScaler CLI rollback failed") from exc
    return {"status": "rolled-back", "signature_object_name": request.signature_object_name, "changes_applied": True, "result": result}


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
