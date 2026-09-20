from __future__ import annotations

import base64
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import psycopg
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from psycopg.types.json import Jsonb

from app.rule_catalog import resolve_rule_catalog

app = FastAPI(title="WAF Intelligence Control API", version="0.1.0")
jobs: dict[str, dict[str, Any]] = {}
ADAPTER_URL = "http://netscaler-adapter:8092"
DISCOVERY_WORKER_URL = "http://discovery-worker:8091"
ANALYSIS_SERVICE_URL = "http://analysis-service:8093"
RUNTIME_INSPECTOR_URL = "http://runtime-inspector:8094"
DATABASE_URL = os.getenv("DATABASE_URL", "")
CREDENTIAL_KEY_FILE = os.getenv("CREDENTIAL_KEY_FILE", "/run/secrets/credential_encryption_key")
active_connections: dict[str, tuple[str, str, str]] = {}


class DiscoveryRequest(BaseModel):
    seed_url: str = Field(min_length=8, max_length=2048)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    rate_limit_per_second: float = Field(default=1.0, gt=0, le=10)
    max_pages: int = Field(default=25, gt=0, le=200)


class NetScalerConnectRequest(BaseModel):
    nsip: str = Field(min_length=3, max_length=64)
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)
    save_credentials: bool = False


class SignatureSelectionRequest(BaseModel):
    selected_catalog_urls: list[str] = Field(default_factory=list, max_length=100)


class SignatureWriteRequest(BaseModel):
    job_id: str | None = Field(default=None, max_length=128)
    approval_id: str | None = Field(default=None, max_length=128)
    plan_fingerprint: str | None = Field(default=None, max_length=128)
    preview_id: str | None = Field(default=None, max_length=128)
    profile_name: str = Field(min_length=1, max_length=128)
    signature_catalog_url: str = Field(min_length=1, max_length=300)
    expected_signature_binding: str | None = Field(default=None, max_length=200)
    confirmation_phrase: str = Field(min_length=1, max_length=64)


class PlanApprovalRequest(BaseModel):
    plan_fingerprint: str = Field(min_length=64, max_length=128)
    selected_catalog_urls: list[str] = Field(default_factory=list, max_length=100)
    approval_phrase: str = Field(min_length=1, max_length=64)


class PreflightRequest(BaseModel):
    approval_id: str = Field(min_length=1, max_length=128)
    plan_fingerprint: str = Field(min_length=64, max_length=128)


class ProfileDuplicateRequest(BaseModel):
    profile_name: str = Field(min_length=1, max_length=128)
    duplicate_name: str | None = Field(default=None, max_length=128)


class DuplicateProfileApprovalRequest(BaseModel):
    source_profile: str = Field(min_length=1, max_length=128)
    destination_profile: str = Field(min_length=1, max_length=128)
    plan_fingerprint: str = Field(min_length=64, max_length=128)
    approval_phrase: str = Field(min_length=1, max_length=64)


class DuplicateProfilePreflightRequest(BaseModel):
    source_profile: str = Field(min_length=1, max_length=128)
    destination_profile: str = Field(min_length=1, max_length=128)
    approval_id: str = Field(min_length=1, max_length=128)
    plan_fingerprint: str = Field(min_length=64, max_length=128)


class DuplicateProfileWriteRequest(DuplicateProfilePreflightRequest):
    preview_id: str = Field(min_length=1, max_length=128)
    confirmation_phrase: str = Field(min_length=1, max_length=64)


class SignatureSetPrepareRequest(BaseModel):
    job_id: str = Field(min_length=1, max_length=128)
    source_profile: str | None = Field(default=None, max_length=128)
    destination_profile: str | None = Field(default=None, max_length=128)


class SignatureSetEditRequest(BaseModel):
    selected_signature_urls: list[str] = Field(default_factory=list, max_length=100)
    destination_profile: str = Field(min_length=1, max_length=128)


class SignatureSetApprovalRequest(BaseModel):
    plan_fingerprint: str = Field(min_length=64, max_length=128)
    approval_phrase: str = Field(min_length=1, max_length=64)


class SignatureSetPreflightRequest(BaseModel):
    approval_id: str = Field(min_length=1, max_length=128)
    plan_fingerprint: str = Field(min_length=64, max_length=128)


class SignatureSetWriteRequest(SignatureSetPreflightRequest):
    preview_id: str = Field(min_length=1, max_length=128)
    confirmation_phrase: str = Field(min_length=1, max_length=64)


def nitro_records(payload: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    value = payload.get(key, [])
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _signature_entry_from_record(item: dict[str, Any]) -> dict[str, Any] | None:
    name = item.get("name") or item.get("signaturename")
    url = item.get("url") or item.get("signatureurl") or item.get("filename")
    if not name and not url:
        return None
    return {
        "name": str(name or url)[:200],
        "url": str(url or "")[:300],
        "creation_date": str(item.get("creationdate") or item.get("creation_date") or "")[:120] or None,
        "base_version": str(item.get("baseversion") or item.get("base_version") or "")[:80] or None,
        "size_bytes": item.get("size") if isinstance(item.get("size"), int) else None,
        "encrypted_version": str(item.get("encryptedversion") or item.get("encrypted_version") or "")[:80] or None,
    }


def parse_signature_catalog(payload: Any) -> dict[str, Any]:
    """Normalize structured or text-form Nitro signature inventory without retaining raw text."""
    resource = payload.get("appfwsignatures") if isinstance(payload, dict) else None
    entries: list[dict[str, Any]] = []
    source = "none"
    if isinstance(resource, list):
        source = "nitro-json"
        for item in resource:
            if isinstance(item, dict):
                entry = _signature_entry_from_record(item)
                if entry:
                    entries.append(entry)
    elif isinstance(resource, dict):
        source = "nitro-json"
        direct_entry = _signature_entry_from_record(resource)
        if direct_entry:
            entries.append(direct_entry)
        response_text = resource.get("response")
        if isinstance(response_text, str):
            source = "nitro-response-text"
            pattern = re.compile(r"(?ms)^\s*(?P<index>\d+)\)\s+Url:\s*(?P<url>\S+)\s+Name:\s*\"(?P<name>[^\"]+)\"(?P<body>.*?)(?=^\s*\d+\)\s+Url:|\Z)")
            for match in pattern.finditer(response_text):
                body = match.group("body")
                size_match = re.search(r"\bSize:\s*(\d+)\s+bytes", body)
                entry = {
                    "name": match.group("name")[:200],
                    "url": match.group("url")[:300],
                    "creation_date": (re.search(r"^\s*Creation Date:\s*(.+)$", body, re.M).group(1).strip()[:120] if re.search(r"^\s*Creation Date:\s*(.+)$", body, re.M) else None),
                    "base_version": (re.search(r'\bBase Version:\s*"?([^"\s]+)', body).group(1)[:80] if re.search(r'\bBase Version:\s*"?([^"\s]+)', body) else None),
                    "size_bytes": int(size_match.group(1)) if size_match else None,
                    "encrypted_version": (re.search(r'\bEncrypted Version:\s*"?([^"\s]+)', body).group(1)[:80] if re.search(r'\bEncrypted Version:\s*"?([^"\s]+)', body) else None),
                }
                entries.append(entry)
    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        key = (entry.get("url", ""), entry.get("name", ""))
        if key not in seen:
            seen.add(key)
            deduplicated.append(entry)
    return {
        "status": "enumerated" if deduplicated else "not-available",
        "source": source,
        "entry_count": len(deduplicated),
        "entries": deduplicated[:200],
        "raw_payload_retained": False,
    }


def signature_inventory_summary(payload: Any, selected_catalog_urls: list[str] | None = None) -> dict[str, Any]:
    catalog = parse_signature_catalog(payload)
    selected_urls = {str(value)[:300] for value in (selected_catalog_urls or []) if value}
    selected = [entry for entry in catalog["entries"] if entry.get("url") in selected_urls]
    status = catalog["status"]
    return {
        "status": status,
        "source": catalog["source"],
        "entry_count": catalog["entry_count"],
        "record_count": catalog["entry_count"],
        "named_signature_count": catalog["entry_count"],
        "names": [entry["name"] for entry in catalog["entries"]],
        "entries": catalog["entries"],
        "selected_entries": selected,
        "selected_count": len(selected),
        "raw_payload_retained": False,
        "note": "Signature catalogs were parsed from the ADC response and raw response text was not retained." if status == "enumerated" else "No enumerable signature catalogs were returned by the ADC.",
    }


def adc_version_value(payload: Any) -> str:
    records = nitro_records(payload, "nsversion")
    if records:
        return str(records[0].get("version") or records[0].get("versionnumber") or records[0].get("build") or "unknown")[:200]
    return "unknown"


def match_protection_plan_to_adc(protection_plan: dict[str, Any], profiles_payload: Any, signatures_payload: Any, version_payload: Any, selected_catalog_urls: list[str] | None = None) -> dict[str, Any]:
    profiles = nitro_records(profiles_payload, "appfwprofile")
    profile_view = []
    for item in profiles:
        name = str(item.get("name", ""))
        types = item.get("type", [])
        if isinstance(types, str):
            types = [types]
        signature_binding = str(item.get("signatures", "")).strip()
        profile_view.append({
            "name": name,
            "state": item.get("state"),
            "builtin": bool(item.get("builtin", False)),
            "types": [str(value) for value in types],
            "signature_binding_present": bool(signature_binding),
            "signature_binding": signature_binding[:200] if signature_binding else None,
        })
    preferred = [item for item in profile_view if "web" in item["name"].lower() and "default" in item["name"].lower()]
    if not preferred:
        preferred = [item for item in profile_view if "web" in item["name"].lower()]
    if not preferred:
        preferred = [item for item in profile_view if not item["builtin"]]
    selected_profile = preferred[0] if preferred else None
    signature_inventory = signature_inventory_summary(signatures_payload, selected_catalog_urls)
    version = adc_version_value(version_payload)
    matched_recommendations = []
    for item in protection_plan.get("signature_recommendations", []):
        entry = dict(item)
        entry["adc_profile_match"] = selected_profile["name"] if selected_profile else None
        entry["adc_profile_match_status"] = "matched" if selected_profile else "not-found"
        entry["adc_signature_match_status"] = "catalog-available" if signature_inventory["status"] == "enumerated" else "not-available"
        entry["deployment_ready"] = False
        matched_recommendations.append(entry)
    return {
        "status": "matched-profile-signature-catalog-available" if selected_profile and signature_inventory["status"] == "enumerated" else ("matched-profile-signature-resolution-pending" if selected_profile else "profile-not-found"),
        "adc_version": version,
        "profile_count": len(profile_view),
        "selected_profile": selected_profile,
        "profiles": profile_view,
        "signature_inventory": signature_inventory,
        "signature_catalog": signature_inventory.get("entries", []),
        "selected_signature_catalogs": signature_inventory.get("selected_entries", []),
        "signature_recommendations": matched_recommendations,
        "deployment_ready": False,
        "blocking_conditions": (["No suitable web AppFW profile was found"] if not selected_profile else []) + (["No signature catalog was returned by the ADC"] if signature_inventory["status"] != "enumerated" else []),
    }


def build_custom_signature_list(job: dict[str, Any], protection_plan: dict[str, Any], adc_match: dict[str, Any]) -> dict[str, Any]:
    selected = adc_match.get("selected_signature_catalogs", [])
    selected_catalogs: list[dict[str, Any]] = []
    seen_catalogs: set[str] = set()
    for entry in selected:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")[:300]
        name = str(entry.get("name") or url or "Unnamed catalog")[:200]
        catalog_key = re.sub(r"[^a-z0-9]+", "-", (url or name).lower()).strip("-")[:120] or "catalog"
        dedupe_key = url or name.lower()
        if dedupe_key in seen_catalogs:
            continue
        seen_catalogs.add(dedupe_key)
        selected_catalogs.append({
            "catalog_key": catalog_key,
            "name": name,
            "url": url,
            "base_version": entry.get("base_version"),
            "encrypted_version": entry.get("encrypted_version"),
            "creation_date": entry.get("creation_date"),
            "size_bytes": entry.get("size_bytes"),
        })
    routes: list[str] = []
    fields: list[str] = []
    for proposal in protection_plan.get("custom_signature_proposals", []):
        values = [str(value)[:200] for value in proposal.get("observed_values", []) if value]
        if proposal.get("kind") == "application-context":
            routes.extend(values)
        elif proposal.get("kind") == "field-context":
            fields.extend(values)
    list_name = "waf-scope-" + str(job.get("id", "proposal"))[:8]
    route_scope = sorted(set(routes))[:50]
    field_scope = sorted(set(fields))[:100]
    review_items = [
        {
            "check": "Catalog selection",
            "status": "ready" if selected_catalogs else "blocked",
            "detail": f"{len(selected_catalogs)} catalog(s) selected from the current ADC inventory.",
        },
        {
            "check": "Application scope",
            "status": "review-required" if route_scope or field_scope else "not-observed",
            "detail": f"{len(route_scope)} route(s) and {len(field_scope)} field name(s) are available for review.",
        },
        {
            "check": "Enforcement mode",
            "status": "Log",
            "detail": "No blocking action is proposed; promotion requires an explicit approved change plan.",
        },
    ]
    return {
        "name": list_name,
        "status": "ready-for-review" if selected_catalogs else "awaiting-catalog-selection",
        "deployment_mode": "Log",
        "source_catalogs": selected_catalogs,
        "catalog_keys": [item["catalog_key"] for item in selected_catalogs],
        "catalog_count": len(selected_catalogs),
        "application_scope": {"routes": route_scope, "field_names": field_scope, "route_count": len(route_scope), "field_count": len(field_scope)},
        "review_items": review_items,
        "proposal_count": len(protection_plan.get("custom_signature_proposals", [])),
        "requires_review": True,
        "changes_applied": False,
        "note": "Proposal only. It describes a named application-scoped signature object based on selected ADC catalogs and observed application context; it does not generate attack payloads.",
    }


def build_write_plan(job: dict[str, Any], protection_plan: dict[str, Any], adc_match: dict[str, Any], custom_signature_list: dict[str, Any], target: dict[str, Any] | None, header_plan: list[dict[str, Any]]) -> dict[str, Any]:
    target_name = target.get("name") if target else None
    selected_profile = adc_match.get("selected_profile") or {}
    signature_commands = []
    for catalog in adc_match.get("selected_signature_catalogs", []):
        signature_name = str(catalog.get("name") or "")[:200]
        profile_name = str(selected_profile.get("name") or "")[:128]
        if signature_name and profile_name:
            signature_commands.append({
                "nitro": {"method": "PUT", "path": "/nitro/v1/config/appfwprofile", "body": {"appfwprofile": {"name": profile_name, "signatures": signature_name}}},
                "cli_equivalent": f"set appfw profile {profile_name} -signatures {signature_name}",
                "note": "Credentials and session headers are intentionally omitted from the preview.",
            })
    operations = [
        {
            "operation_id": "waf-profile-selection",
            "resource": "appfwprofile",
            "action": "select-and-associate",
            "target_lb_vserver": target_name,
            "candidate_profile": selected_profile.get("name"),
            "expected_current_signature_binding": selected_profile.get("signature_binding"),
            "mode": "Log",
            "status": "blocked-until-approved",
            "requires_drift_check": True,
        },
        {
            "operation_id": "signature-group-association",
            "resource": "appfwsignatures",
            "action": "associate-selected-catalogs",
            "signature_groups": custom_signature_list.get("catalog_keys", []) or [item.get("catalog_key") for item in protection_plan.get("signature_recommendations", [])],
            "selected_signature_catalogs": adc_match.get("selected_signature_catalogs", []),
            "apply_endpoint": "/api/adc/writes/appfw-profile-signature",
            "commands": signature_commands,
            "mode": "Log",
            "status": "blocked-until-signature-selection" if not adc_match.get("selected_signature_catalogs") else "blocked-until-approved",
            "requires_drift_check": True,
        },
        {
            "operation_id": "custom-signature-review",
            "resource": "appfwsignatures",
            "action": "review-custom-signature-list",
            "custom_signature_list": custom_signature_list,
            "proposal_count": len(protection_plan.get("custom_signature_proposals", [])),
            "mode": "Log",
            "status": "blocked-until-catalog-selection" if not custom_signature_list.get("source_catalogs") else "manual-review-required",
            "requires_drift_check": True,
        },
        {
            "operation_id": "response-headers-report-only",
            "resource": "rewrite-policy",
            "action": "prepare-response-header-policy",
            "headers": header_plan,
            "commands": {"status": "preview-only", "nitro": None, "cli_equivalent": None, "note": "Response-rewrite write commands are not enabled until the rewrite-policy adapter and binding model are explicitly approved."},
            "mode": "CSP-Report-Only",
            "status": "blocked-until-approved",
            "requires_drift_check": True,
        },
    ]
    return {
        "plan_status": "prepared-disabled",
        "approval_required": True,
        "write_enabled": False,
        "changes_applied": False,
        "confirmation_phrase": "ENABLE WRITE",
        "target": {"vip": job.get("scope", {}).get("hostname"), "lb_vserver": target_name},
        "operations": operations,
        "preconditions": [
            "ADC configuration fingerprint must be captured immediately before apply.",
            "The target and signature catalog must not drift after approval.",
            "All operations must be reviewed and explicitly approved.",
            "Apply must start in Log mode; CSP must start as Report-Only.",
        ],
        "rollback": [
            "Restore the captured pre-change configuration or remove only objects created by this plan.",
            "Unbind the generated rewrite policy if response headers were applied.",
            "Verify the VIP and application behavior after rollback.",
        ],
        "apply_endpoint": "/api/adc/writes/appfw-profile-signature",
        "note": "Write operations are prepared as an approval-gated plan only. No ADC write request was sent.",
    }


def plan_fingerprint(plan: dict[str, Any]) -> str:
    fingerprint_input = {key: value for key, value in plan.items() if key not in {"plan_fingerprint", "approval"}}
    canonical = json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def configuration_fingerprint(plan: dict[str, Any]) -> str:
    catalog = plan.get("adc_catalog_match", {})
    selected_profile = catalog.get("selected_profile") or {}
    state = {
        "adc_version": catalog.get("adc_version"),
        "target": plan.get("target"),
        "profile": {
            "name": selected_profile.get("name"),
            "state": selected_profile.get("state"),
            "signature_binding": selected_profile.get("signature_binding"),
        },
        "selected_catalogs": [
            {"name": item.get("name"), "url": item.get("url"), "base_version": item.get("base_version"), "encrypted_version": item.get("encrypted_version")}
            for item in (catalog.get("selected_signature_catalogs") or [])
        ],
    }
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def db_connect() -> psycopg.Connection[Any]:
    return psycopg.connect(DATABASE_URL)


def init_db_sync() -> None:
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_connections (id TEXT PRIMARY KEY, nsip TEXT NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL, password_ciphertext TEXT NOT NULL, version TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, last_verified_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_signature_inventory (id TEXT PRIMARY KEY, nsip TEXT NOT NULL, adc_version TEXT NOT NULL, inventory_status TEXT NOT NULL, entry_count INTEGER NOT NULL, entries JSONB NOT NULL, fetched_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS idx_netscaler_signature_inventory_lookup ON netscaler_signature_inventory (nsip, fetched_at DESC)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_write_audit (id TEXT PRIMARY KEY, operation TEXT NOT NULL, nsip TEXT NOT NULL, profile_name TEXT NOT NULL, signature_name TEXT NOT NULL, result TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_plan_approvals (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, plan_fingerprint TEXT NOT NULL, status TEXT NOT NULL, selected_catalog_urls JSONB NOT NULL, plan_snapshot JSONB NOT NULL, approved_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_netscaler_plan_approvals_job ON netscaler_plan_approvals (job_id, approved_at DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_change_previews (id TEXT PRIMARY KEY, approval_id TEXT NOT NULL, job_id TEXT NOT NULL, plan_fingerprint TEXT NOT NULL, status TEXT NOT NULL, expected_configuration_fingerprint TEXT NOT NULL, current_configuration_fingerprint TEXT NOT NULL, checks JSONB NOT NULL, rollback_snapshot JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_netscaler_change_previews_job ON netscaler_change_previews (job_id, created_at DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS csp_reports (id TEXT PRIMARY KEY, document_uri TEXT NOT NULL, blocked_uri TEXT NOT NULL, violated_directive TEXT NOT NULL, effective_directive TEXT NOT NULL, disposition TEXT NOT NULL, report JSONB NOT NULL, received_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_csp_reports_received_at ON csp_reports (received_at DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS netscaler_signature_sets (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, nsip TEXT NOT NULL, source_profile TEXT NOT NULL, destination_profile TEXT NOT NULL, status TEXT NOT NULL, plan_fingerprint TEXT NOT NULL, source_snapshot JSONB NOT NULL, technology_context JSONB NOT NULL, available_signatures JSONB NOT NULL, selected_signature_urls JSONB NOT NULL, added_signature_urls JSONB NOT NULL, removed_signature_urls JSONB NOT NULL, approval_id TEXT, approved_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, preview_id TEXT, preflight_status TEXT, changes_applied BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_netscaler_signature_sets_job ON netscaler_signature_sets (job_id, updated_at DESC)")
        conn.commit()


def encryption_key() -> bytes:
    key = Path(CREDENTIAL_KEY_FILE).read_bytes().strip()
    Fernet(key)
    return key


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16_384, r=8, p=1)
    return "$scrypt$16384$8$1$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def save_connection_sync(connection_id: str, request: NetScalerConnectRequest, version: str) -> None:
    key = encryption_key()
    timestamp = datetime.now(timezone.utc)
    ciphertext = Fernet(key).encrypt(request.password.encode()).decode()
    with db_connect() as conn:
        conn.execute("""INSERT INTO netscaler_connections (id, nsip, username, password_hash, password_ciphertext, version, created_at, last_verified_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET nsip=EXCLUDED.nsip, username=EXCLUDED.username, password_hash=EXCLUDED.password_hash, password_ciphertext=EXCLUDED.password_ciphertext, version=EXCLUDED.version, last_verified_at=EXCLUDED.last_verified_at""", (connection_id, request.nsip, request.username, password_hash(request.password), ciphertext, version, timestamp, timestamp))
        conn.commit()


def list_connections_sync() -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute("SELECT id, nsip, version, created_at, last_verified_at FROM netscaler_connections ORDER BY last_verified_at DESC").fetchall()
    columns = ["id", "nsip", "version", "created_at", "last_verified_at"]
    return [dict(zip(columns, row)) for row in rows]


def load_connection_sync(connection_id: str) -> tuple[str, str, str] | None:
    with db_connect() as conn:
        row = conn.execute("SELECT nsip, username, password_ciphertext FROM netscaler_connections WHERE id = %s", (connection_id,)).fetchone()
    if not row:
        return None
    nsip, username, ciphertext = row
    password = Fernet(encryption_key()).decrypt(ciphertext.encode()).decode()
    return str(nsip), str(username), password


def update_connection_sync(connection_id: str, version: str) -> None:
    with db_connect() as conn:
        conn.execute("UPDATE netscaler_connections SET version = %s, last_verified_at = %s WHERE id = %s", (version, datetime.now(timezone.utc), connection_id))
        conn.commit()


def save_signature_inventory_sync(nsip: str, adc_version: str, catalog: dict[str, Any]) -> None:
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO netscaler_signature_inventory (id, nsip, adc_version, inventory_status, entry_count, entries, fetched_at) VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                str(uuid4()),
                nsip[:64],
                adc_version[:200],
                str(catalog.get("status", "not-available"))[:64],
                int(catalog.get("entry_count", 0)),
                Jsonb(catalog.get("entries", [])),
                datetime.now(timezone.utc),
            ),
        )
        conn.commit()


def save_write_audit_sync(operation: str, nsip: str, profile_name: str, signature_name: str, result: str, details: dict[str, Any]) -> None:
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO netscaler_write_audit (id, operation, nsip, profile_name, signature_name, result, details, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (str(uuid4()), operation[:100], nsip[:64], profile_name[:128], signature_name[:128], result[:64], Jsonb(details), datetime.now(timezone.utc)),
        )
        conn.commit()


def save_plan_approval_sync(job_id: str, fingerprint: str, selected_catalog_urls: list[str], plan: dict[str, Any]) -> tuple[str, datetime]:
    approval_id = str(uuid4())
    approved_at = datetime.now(timezone.utc)
    expires_at = approved_at + timedelta(minutes=30)
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO netscaler_plan_approvals (id, job_id, plan_fingerprint, status, selected_catalog_urls, plan_snapshot, approved_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (approval_id, job_id[:128], fingerprint[:128], "approved", Jsonb(selected_catalog_urls), Jsonb(plan), approved_at, expires_at),
        )
        conn.commit()
    return approval_id, expires_at


def load_plan_approval_sync(approval_id: str) -> dict[str, Any] | None:
    with db_connect() as conn:
        row = conn.execute("SELECT id, job_id, plan_fingerprint, status, selected_catalog_urls, plan_snapshot, approved_at, expires_at FROM netscaler_plan_approvals WHERE id = %s", (approval_id,)).fetchone()
    if not row:
        return None
    columns = ["id", "job_id", "plan_fingerprint", "status", "selected_catalog_urls", "plan_snapshot", "approved_at", "expires_at"]
    return dict(zip(columns, row))


def save_change_preview_sync(approval_id: str, job_id: str, fingerprint: str, status: str, expected_fingerprint: str, current_fingerprint: str, checks: list[dict[str, Any]], rollback_snapshot: dict[str, Any]) -> str:
    preview_id = str(uuid4())
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO netscaler_change_previews (id, approval_id, job_id, plan_fingerprint, status, expected_configuration_fingerprint, current_configuration_fingerprint, checks, rollback_snapshot, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (preview_id, approval_id, job_id[:128], fingerprint[:128], status[:64], expected_fingerprint, current_fingerprint, Jsonb(checks), Jsonb(rollback_snapshot), datetime.now(timezone.utc)),
        )
        conn.commit()
    return preview_id


def load_change_preview_sync(preview_id: str) -> dict[str, Any] | None:
    with db_connect() as conn:
        row = conn.execute("SELECT id, approval_id, job_id, plan_fingerprint, status, expected_configuration_fingerprint, current_configuration_fingerprint, checks, rollback_snapshot, created_at FROM netscaler_change_previews WHERE id = %s", (preview_id,)).fetchone()
    if not row:
        return None
    columns = ["id", "approval_id", "job_id", "plan_fingerprint", "status", "expected_configuration_fingerprint", "current_configuration_fingerprint", "checks", "rollback_snapshot", "created_at"]
    return dict(zip(columns, row))


def save_signature_set_sync(signature_set: dict[str, Any]) -> str:
    set_id = str(uuid4())
    now = datetime.now(timezone.utc)
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO netscaler_signature_sets (id, job_id, nsip, source_profile, destination_profile, status, plan_fingerprint, source_snapshot, technology_context, available_signatures, selected_signature_urls, added_signature_urls, removed_signature_urls, approval_id, approved_at, expires_at, preview_id, preflight_status, changes_applied, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL, NULL, NULL, FALSE, %s, %s)""",
            (set_id, signature_set["job_id"], signature_set["nsip"], signature_set["source_profile"], signature_set["destination_profile"], signature_set["status"], signature_set["plan_fingerprint"], Jsonb(signature_set["source_snapshot"]), Jsonb(signature_set["technology_context"]), Jsonb(signature_set["available_signatures"]), Jsonb(signature_set["selected_signature_urls"]), Jsonb(signature_set["added_signature_urls"]), Jsonb(signature_set["removed_signature_urls"]), now, now),
        )
        conn.commit()
    return set_id


def load_signature_set_sync(set_id: str) -> dict[str, Any] | None:
    with db_connect() as conn:
        row = conn.execute("SELECT id, job_id, nsip, source_profile, destination_profile, status, plan_fingerprint, source_snapshot, technology_context, available_signatures, selected_signature_urls, added_signature_urls, removed_signature_urls, approval_id, approved_at, expires_at, preview_id, preflight_status, changes_applied, created_at, updated_at FROM netscaler_signature_sets WHERE id = %s", (set_id,)).fetchone()
    if not row:
        return None
    columns = ["id", "job_id", "nsip", "source_profile", "destination_profile", "status", "plan_fingerprint", "source_snapshot", "technology_context", "available_signatures", "selected_signature_urls", "added_signature_urls", "removed_signature_urls", "approval_id", "approved_at", "expires_at", "preview_id", "preflight_status", "changes_applied", "created_at", "updated_at"]
    return dict(zip(columns, row))


def list_signature_sets_sync(job_id: str | None = None) -> list[dict[str, Any]]:
    with db_connect() as conn:
        if job_id:
            rows = conn.execute("SELECT id, job_id, nsip, source_profile, destination_profile, status, plan_fingerprint, selected_signature_urls, approval_id, expires_at, preflight_status, changes_applied, created_at, updated_at FROM netscaler_signature_sets WHERE job_id = %s ORDER BY updated_at DESC", (job_id,)).fetchall()
        else:
            rows = conn.execute("SELECT id, job_id, nsip, source_profile, destination_profile, status, plan_fingerprint, selected_signature_urls, approval_id, expires_at, preflight_status, changes_applied, created_at, updated_at FROM netscaler_signature_sets ORDER BY updated_at DESC LIMIT 100").fetchall()
    columns = ["signature_set_id", "job_id", "nsip", "source_profile", "destination_profile", "status", "plan_fingerprint", "selected_signature_urls", "approval_id", "expires_at", "preflight_status", "changes_applied", "created_at", "updated_at"]
    return [dict(zip(columns, row)) for row in rows]


def update_signature_set_sync(set_id: str, values: dict[str, Any]) -> None:
    allowed = {"destination_profile", "status", "plan_fingerprint", "available_signatures", "selected_signature_urls", "added_signature_urls", "removed_signature_urls", "approval_id", "approved_at", "expires_at", "preview_id", "preflight_status", "changes_applied"}
    fields = [key for key in values if key in allowed]
    if not fields:
        return
    assignments = ", ".join(f"{key} = %s" for key in fields) + ", updated_at = %s"
    params = []
    for key in fields:
        value = values[key]
        if key in {"available_signatures", "selected_signature_urls", "added_signature_urls", "removed_signature_urls"}:
            value = Jsonb(value)
        params.append(value)
    params.append(datetime.now(timezone.utc))
    params.append(set_id)
    with db_connect() as conn:
        conn.execute(f"UPDATE netscaler_signature_sets SET {assignments} WHERE id = %s", params)
        conn.commit()


def save_csp_report_sync(report: dict[str, Any]) -> str:
    report_id = str(uuid4())
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO csp_reports (id, document_uri, blocked_uri, violated_directive, effective_directive, disposition, report, received_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                report_id,
                str(report.get("document_uri", ""))[:2048],
                str(report.get("blocked_uri", ""))[:2048],
                str(report.get("violated_directive", ""))[:512],
                str(report.get("effective_directive", ""))[:512],
                str(report.get("disposition", ""))[:64],
                Jsonb(report),
                datetime.now(timezone.utc),
            ),
        )
        conn.commit()
    return report_id


def list_csp_reports_sync(limit: int) -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, document_uri, blocked_uri, violated_directive, effective_directive, disposition, report, received_at FROM csp_reports ORDER BY received_at DESC LIMIT %s",
            (limit,),
        ).fetchall()
    columns = ["id", "document_uri", "blocked_uri", "violated_directive", "effective_directive", "disposition", "report", "received_at"]
    return [dict(zip(columns, row)) for row in rows]


def sanitize_csp_report(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("csp-report") if isinstance(payload.get("csp-report"), dict) else payload
    allowed = (
        "document-uri", "referrer", "blocked-uri", "violated-directive", "effective-directive",
        "original-policy", "source-file", "line-number", "column-number", "status-code", "disposition",
        "script-sample",
    )
    normalized: dict[str, Any] = {}
    for key in allowed:
        value = source.get(key)
        if value is None:
            continue
        target_key = key.replace("-", "_")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            normalized[target_key] = value
        elif isinstance(value, str):
            normalized[target_key] = value[:2048 if key in {"document-uri", "referrer", "blocked-uri", "source-file"} else 512]
    return normalized


def save_runtime_evidence_sync(job_id: str, pages: list[dict[str, Any]]) -> None:
    with db_connect() as conn:
        conn.execute("DELETE FROM discovery_evidence WHERE run_id = %s AND evidence_type = 'runtime_inspection'", (job_id,))
        rows = []
        timestamp = datetime.now(timezone.utc)
        for page in pages:
            controls = page.get("controls", [])[:200]
            search_surfaces = page.get("search_surfaces", [])[:50]
            rows.append({
                "run_id": job_id,
                "evidence_type": "runtime_inspection",
                "source_url": page.get("source_url", "")[:2048],
                "request_method": "BROWSER_GET",
                "status_code": page.get("status_code"),
                "technology": None,
                "signal": "Runtime DOM form and control surface observed",
                "confidence": "high" if controls or search_surfaces else "low",
                "confidence_score": 0.90 if controls or search_surfaces else 0.30,
                "observed_at": timestamp,
                "metadata": Jsonb({
                    "inspection_mode": "render-and-inspect-only",
                    "final_url": page.get("final_url", ""),
                    "forms": page.get("forms", [])[:50],
                    "controls": controls,
                    "search_surface_count": len(search_surfaces),
                    "search_surfaces": search_surfaces,
                    "values_submitted": False,
                    "error_type": page.get("error_type"),
                }),
            })
        if rows:
            with conn.cursor() as cursor:
                cursor.executemany("INSERT INTO discovery_evidence (run_id, evidence_type, source_url, request_method, status_code, technology, signal, confidence, confidence_score, observed_at, metadata) VALUES (%(run_id)s, %(evidence_type)s, %(source_url)s, %(request_method)s, %(status_code)s, %(technology)s, %(signal)s, %(confidence)s, %(confidence_score)s, %(observed_at)s, %(metadata)s)", rows)
        conn.commit()


def nsip_value(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="NSIP must be a valid IP address") from exc


@app.on_event("startup")
async def startup() -> None:
    await asyncio.to_thread(init_db_sync)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "control-api"}


@app.post("/api/csp/report", status_code=202)
async def receive_csp_report(request: Request) -> dict[str, Any]:
    """Receive bounded CSP Report-Only telemetry without retaining raw request bodies."""
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > 65536:
        raise HTTPException(status_code=413, detail="CSP report payload is too large")
    body = await request.body()
    if len(body) > 65536:
        raise HTTPException(status_code=413, detail="CSP report payload is too large")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="CSP report must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="CSP report must be a JSON object")
    report = sanitize_csp_report(payload)
    if not report.get("document_uri") and not report.get("blocked_uri") and not report.get("violated_directive"):
        raise HTTPException(status_code=422, detail="CSP report does not contain recognizable report fields")
    try:
        report_id = await asyncio.to_thread(save_csp_report_sync, report)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="CSP report database unavailable") from exc
    return {"accepted": True, "report_id": report_id, "stored_fields": sorted(report), "raw_payload_retained": False}


@app.get("/api/csp/reports")
async def list_csp_reports(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
    try:
        reports = await asyncio.to_thread(list_csp_reports_sync, limit)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="CSP report database unavailable") from exc
    return {"count": len(reports), "reports": reports, "raw_payload_retained": False}


@app.get("/api/platform")
async def platform() -> dict[str, Any]:
    return {
        "status": "mvp-foundation",
        "mode": "read-only",
        "services": {
            "discovery": "http://discovery-worker:8091",
            "netscaler_adapter": "http://netscaler-adapter:8092",
        },
    }


@app.post("/api/discovery/jobs", status_code=202)
async def create_discovery_job(request: DiscoveryRequest) -> dict[str, Any]:
    from urllib.parse import urlparse

    parsed = urlparse(request.seed_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="seed_url must contain an http or https hostname")
    job_id = str(uuid4())
    job = {
        "id": job_id,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": {**request.model_dump(), "hostname": parsed.hostname},
    }
    jobs[job_id] = job
    worker_url = f"{DISCOVERY_WORKER_URL}/jobs"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(worker_url, json=job)
            response.raise_for_status()
    except httpx.HTTPError as exc:
        job["status"] = "worker-unavailable"
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc
    return job


@app.post("/api/netscalers/connect")
async def connect_netscaler(request: NetScalerConnectRequest) -> dict[str, Any]:
    request.nsip = nsip_value(request.nsip)
    connection_id = str(uuid4())
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(f"{ADAPTER_URL}/api/adc/connect", json={"nsip": request.nsip, "username": request.username, "password": request.password})
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=401, detail="NetScaler connection failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler adapter unavailable") from exc
    if request.save_credentials:
        try:
            await asyncio.to_thread(save_connection_sync, connection_id, request, str(result.get("version", "unknown")))
        except (OSError, ValueError, psycopg.Error) as exc:
            raise HTTPException(status_code=503, detail="Encrypted credential storage is not configured") from exc
    else:
        active_connections[connection_id] = (request.nsip, request.username, request.password)
    return {"connection_id": connection_id, "nsip": request.nsip, "version": result.get("version", "unknown"), "credentials_saved": request.save_credentials}


@app.get("/api/netscalers")
async def list_netscalers() -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(list_connections_sync)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Credential database unavailable") from exc


@app.post("/api/netscalers/{connection_id}/connect")
async def reconnect_netscaler(connection_id: str) -> dict[str, Any]:
    try:
        credentials = await asyncio.to_thread(load_connection_sync, connection_id)
    except (OSError, ValueError, psycopg.Error) as exc:
        raise HTTPException(status_code=503, detail="Encrypted credential storage is unavailable") from exc
    if not credentials:
        raise HTTPException(status_code=404, detail="Saved NetScaler connection not found")
    nsip, username, password = credentials
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(f"{ADAPTER_URL}/api/adc/connect", json={"nsip": nsip, "username": username, "password": password})
            response.raise_for_status()
            result = response.json()
        await asyncio.to_thread(update_connection_sync, connection_id, str(result.get("version", "unknown")))
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=401, detail="NetScaler connection failed") from exc
    except (httpx.HTTPError, psycopg.Error) as exc:
        raise HTTPException(status_code=503, detail="NetScaler connection service unavailable") from exc
    return {"connection_id": connection_id, "nsip": nsip, "version": result.get("version", "unknown"), "credentials_saved": True}


@app.post("/api/netscalers/{connection_id}/disconnect")
async def disconnect_netscaler(connection_id: str) -> dict[str, Any]:
    active_connections.pop(connection_id, None)
    return {"connection_id": connection_id, "disconnected": True, "saved_credentials_retained": True}


@app.get("/api/discovery/jobs")
async def list_discovery_jobs() -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.get("/api/discovery/jobs/{job_id}")
async def get_discovery_job(job_id: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404, detail="Discovery job not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.get("/api/discovery/jobs/{job_id}/evidence")
async def get_discovery_evidence(job_id: str) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/evidence")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404, detail="Discovery job not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.delete("/api/discovery/jobs/{job_id}", status_code=204)
async def delete_discovery_job(job_id: str) -> Response:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.delete(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}")
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 409:
            raise HTTPException(status_code=409, detail="Active discovery jobs cannot be deleted") from exc
        raise HTTPException(status_code=404, detail="Discovery job not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc
    return Response(status_code=204)


@app.post("/api/discovery/jobs/{job_id}/cancel")
async def cancel_discovery_job(job_id: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/cancel")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Discovery job not found") from exc
        raise HTTPException(status_code=502, detail="Unable to cancel discovery job") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.get("/api/discovery/jobs/{job_id}/observations")
async def get_discovery_observations(job_id: str) -> list[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/observations")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404, detail="Discovery job not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.post("/api/discovery/jobs/{job_id}/runtime-inspection")
async def runtime_inspection(job_id: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=180) as client:
            job_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}")
            job_response.raise_for_status()
            profile_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/profile")
            profile_response.raise_for_status()
            job = job_response.json()
            profile = profile_response.json()
            if job.get("status") != "completed":
                raise HTTPException(status_code=409, detail="Runtime inspection requires a completed discovery job")
            seed_url = job.get("scope", {}).get("seed_url", "")
            hostname = job.get("scope", {}).get("hostname", "") or urlparse(seed_url).hostname
            urls = [seed_url]
            for item in profile.get("route_inventory", []):
                if item.get("evidence_type") != "route_discovered":
                    continue
                candidate = item.get("source_url", "")
                if candidate and candidate not in urls:
                    urls.append(candidate)
                if len(urls) >= 50:
                    break
            inspection = await client.post(f"{RUNTIME_INSPECTOR_URL}/inspect", json={"urls": urls, "hostname": hostname, "allowed_paths": job.get("scope", {}).get("allowed_paths", ["/"])})
            inspection.raise_for_status()
            result = inspection.json()
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Discovery job not found") from exc
        raise HTTPException(status_code=502, detail="Runtime inspection failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Runtime inspector unavailable") from exc
    try:
        await asyncio.to_thread(save_runtime_evidence_sync, job_id, result.get("pages", []))
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Runtime evidence database unavailable") from exc
    return {"run_id": job_id, "mode": result.get("mode"), "values_submitted": False, "pages_inspected": len(result.get("pages", [])), "controls_observed": sum(len(page.get("controls", [])) for page in result.get("pages", [])), "search_surfaces_observed": sum(len(page.get("search_surfaces", [])) for page in result.get("pages", []))}


@app.get("/api/discovery/jobs/{job_id}/analysis")
async def get_discovery_analysis(job_id: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            profile = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/profile")
            profile.raise_for_status()
            observations = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/observations")
            observations.raise_for_status()
            analysis = await client.post(f"{ANALYSIS_SERVICE_URL}/analyze", json={"run_id": job_id, "profile": profile.json(), "observations": observations.json()})
            analysis.raise_for_status()
            return analysis.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="Discovery job not found") from exc
        raise HTTPException(status_code=502, detail="Discovery analysis failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery analysis service unavailable") from exc


@app.get("/api/discovery/jobs/{job_id}/adc-plan")
async def get_adc_plan(job_id: str, selected_catalog_url: list[str] | None = Query(default=None)) -> dict[str, Any]:
    selected_catalog_urls = [value[:300] for value in (selected_catalog_url or []) if value]
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            job_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}")
            job_response.raise_for_status()
            profile_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/profile")
            profile_response.raise_for_status()
            observations_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/observations")
            observations_response.raise_for_status()
            analysis_response = await client.post(f"{ANALYSIS_SERVICE_URL}/analyze", json={"run_id": job_id, "profile": profile_response.json(), "observations": observations_response.json()})
            analysis_response.raise_for_status()
            lb_response = await client.get(f"{ADAPTER_URL}/api/adc/lbvservers")
            lb_response.raise_for_status()
            appfw_profiles_response = await client.get(f"{ADAPTER_URL}/api/adc/appfw/profiles")
            appfw_profiles_response.raise_for_status()
            signatures_response = await client.get(f"{ADAPTER_URL}/api/adc/signatures")
            signatures_response.raise_for_status()
            version_response = await client.get(f"{ADAPTER_URL}/api/adc/version")
            version_response.raise_for_status()
            adapter_target_response = await client.get(f"{ADAPTER_URL}/api/adc/target")
            adapter_target_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404 if exc.response.status_code == 404 else 502, detail="Unable to build ADC change plan") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="ADC or discovery service unavailable") from exc

    job = job_response.json()
    profile = profile_response.json()
    analysis = analysis_response.json()
    signatures_payload = signatures_response.json()
    version_payload = version_response.json()
    adapter_target = adapter_target_response.json()
    signature_catalog = parse_signature_catalog(signatures_payload)
    try:
        await asyncio.to_thread(save_signature_inventory_sync, str(adapter_target.get("host", "unknown")), adc_version_value(version_payload), signature_catalog)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature inventory database unavailable") from exc
    seed_host = job.get("scope", {}).get("hostname") or urlparse(job.get("scope", {}).get("seed_url", "")).hostname
    lb_items = lb_response.json().get("lbvserver", [])
    matches = [item for item in lb_items if str(item.get("ipv46", item.get("ip", ""))).lower() == str(seed_host).lower()]
    target = matches[0] if matches else None
    observed_headers: set[str] = set()
    for row in profile.get("evidence", []):
        if row.get("evidence_type") != "route":
            continue
        observed_headers.update(str(key).lower() for key in row.get("metadata", {}).get("headers", {}))
    header_plan = []
    for header in ("CSP", "HSTS", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"):
        normalized = {"csp": "content-security-policy", "hsts": "strict-transport-security"}.get(header.lower(), header.lower())
        header_plan.append({"header": header, "observed": normalized in observed_headers, "action": "retain_and_validate" if normalized in observed_headers else "add_in_change_plan", "note": "CSP must start as Report-Only." if header == "CSP" else "Review application requirements before enforcement."})
    adc_match = match_protection_plan_to_adc(analysis.get("protection_plan", {}), appfw_profiles_response.json(), signatures_payload, version_payload, selected_catalog_urls)
    custom_signature_list = build_custom_signature_list(job, analysis.get("protection_plan", {}), adc_match)
    write_plan = build_write_plan(job, analysis.get("protection_plan", {}), adc_match, custom_signature_list, target, header_plan)
    plan = {
        "job_id": job_id,
        "plan_status": "proposal-only",
        "approval_required": True,
        "changes_applied": False,
        "target": {"vip": seed_host, "lb_vserver": target.get("name") if target else None, "port": target.get("port") if target else None, "service_type": target.get("servicetype") if target else None, "state": target.get("curstate") if target else None, "current_rewrite": target.get("rewrite") if target else None},
        "target_match": bool(target),
        "header_plan": header_plan,
        "csp_mode": "Report-Only",
        "implementation_outline": ["Create response-rewrite actions for approved headers", "Create a response-rewrite policy limited to the selected LB vServer", "Bind the policy and preserve the pre-change configuration fingerprint", "Validate headers and application behavior on the VIP"],
        "rollback_outline": ["Unbind the response-rewrite policy", "Remove only the newly created actions and policy", "Revalidate the VIP response and application behavior"],
        "blocking_conditions": ([] if target else ["No LB vServer matched the discovery hostname"]) + adc_match.get("blocking_conditions", []),
        "adc_catalog_match": adc_match,
        "custom_signature_list": custom_signature_list,
        "write_plan": write_plan,
    }
    plan["plan_fingerprint"] = plan_fingerprint(plan)
    plan["approval"] = {
        "status": "not-approved",
        "required_phrase": "APPROVE PLAN",
        "expires_in_minutes": 30,
        "note": "Approval authorizes this exact plan for a future write attempt; it does not change the ADC.",
    }
    return plan


@app.post("/api/discovery/jobs/{job_id}/adc-plan/approve")
async def approve_adc_plan(job_id: str, request: PlanApprovalRequest) -> dict[str, Any]:
    if request.approval_phrase != "APPROVE PLAN":
        raise HTTPException(status_code=400, detail="Exact approval phrase APPROVE PLAN is required")
    selected_catalog_urls = [value[:300] for value in request.selected_catalog_urls if value]
    plan = await get_adc_plan(job_id, selected_catalog_url=selected_catalog_urls)
    if plan.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Plan fingerprint changed; regenerate the plan before approving")
    if not plan.get("custom_signature_list", {}).get("catalog_count"):
        raise HTTPException(status_code=422, detail="At least one current ADC signature catalog must be selected")
    if plan.get("blocking_conditions"):
        raise HTTPException(status_code=409, detail="Plan has blocking conditions and cannot be approved")
    try:
        approval_id, expires_at = await asyncio.to_thread(save_plan_approval_sync, job_id, request.plan_fingerprint, selected_catalog_urls, plan)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Plan approval database unavailable") from exc
    return {
        "approval_id": approval_id,
        "job_id": job_id,
        "status": "approved",
        "plan_fingerprint": request.plan_fingerprint,
        "selected_catalog_count": plan["custom_signature_list"]["catalog_count"],
        "approved_at": datetime.now(timezone.utc),
        "expires_at": expires_at,
        "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true",
        "changes_applied": False,
        "note": "Approval recorded for this exact plan. No ADC change was applied.",
    }


@app.post("/api/discovery/jobs/{job_id}/adc-plan/preflight")
async def preflight_adc_plan(job_id: str, request: PreflightRequest) -> dict[str, Any]:
    approval = await asyncio.to_thread(load_plan_approval_sync, request.approval_id)
    if not approval or approval.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Valid approved plan not found")
    if approval.get("job_id") != job_id or approval.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Approval does not match the requested discovery plan")
    if approval.get("expires_at") and approval["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Plan approval has expired")
    selected_catalog_urls = [str(value)[:300] for value in (approval.get("selected_catalog_urls") or []) if value]
    current_plan = await get_adc_plan(job_id, selected_catalog_url=selected_catalog_urls)
    expected_plan = approval.get("plan_snapshot") or {}
    expected_configuration_fingerprint = configuration_fingerprint(expected_plan)
    current_configuration_fingerprint = configuration_fingerprint(current_plan)
    selected_profile = (current_plan.get("adc_catalog_match") or {}).get("selected_profile") or {}
    expected_profile = (expected_plan.get("adc_catalog_match") or {}).get("selected_profile") or {}
    current_catalogs = current_plan.get("custom_signature_list", {}).get("catalog_keys", [])
    expected_catalogs = expected_plan.get("custom_signature_list", {}).get("catalog_keys", [])
    checks = [
        {"name": "Approval validity", "status": "passed", "detail": "Approval exists and has not expired."},
        {"name": "Plan fingerprint", "status": "passed" if current_plan.get("plan_fingerprint") == request.plan_fingerprint else "failed", "detail": "The current plan matches the approved plan." if current_plan.get("plan_fingerprint") == request.plan_fingerprint else "The discovery or ADC read state changed."},
        {"name": "Configuration fingerprint", "status": "passed" if current_configuration_fingerprint == expected_configuration_fingerprint else "failed", "detail": "Profile, target, version, and selected catalog state match." if current_configuration_fingerprint == expected_configuration_fingerprint else "Current ADC state differs from the approved snapshot."},
        {"name": "AppFW profile", "status": "passed" if selected_profile.get("name") == expected_profile.get("name") and selected_profile.get("signature_binding") == expected_profile.get("signature_binding") else "failed", "detail": f"Profile {selected_profile.get('name') or 'not found'} and its previous signature binding were captured."},
        {"name": "Selected catalogs", "status": "passed" if current_catalogs == expected_catalogs else "failed", "detail": f"{len(current_catalogs)} selected catalog(s) are present in the current inventory."},
        {"name": "Rollback snapshot", "status": "passed" if selected_profile.get("name") else "failed", "detail": "The previous profile signature binding is available for exact restoration." if selected_profile.get("name") else "No target profile was available for rollback."},
    ]
    rollback_snapshot = {
        "status": "ready" if selected_profile.get("name") else "blocked",
        "restore_operations": [{
            "resource": "appfwprofile",
            "profile_name": selected_profile.get("name"),
            "previous_signature_binding": selected_profile.get("signature_binding"),
            "action": "restore-exact-binding",
        }] if selected_profile.get("name") else [],
        "verification": ["Read the profile after rollback and confirm the previous signature binding.", "Validate the application VIP response after rollback."],
    }
    drift_detected = any(item["status"] == "failed" for item in checks)
    status = "drift-detected" if drift_detected else ("blocked-write-disabled" if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true" else "ready-for-apply")
    try:
        preview_id = await asyncio.to_thread(save_change_preview_sync, request.approval_id, job_id, request.plan_fingerprint, status, expected_configuration_fingerprint, current_configuration_fingerprint, checks, rollback_snapshot)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Change preview database unavailable") from exc
    return {
        "preview_id": preview_id,
        "job_id": job_id,
        "approval_id": request.approval_id,
        "status": status,
        "plan_fingerprint": request.plan_fingerprint,
        "expected_configuration_fingerprint": expected_configuration_fingerprint,
        "current_configuration_fingerprint": current_configuration_fingerprint,
        "checks": checks,
        "rollback_snapshot": rollback_snapshot,
        "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true",
        "changes_applied": False,
    }


@app.get("/api/discovery/jobs/{job_id}/profile")
async def get_discovery_profile(job_id: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/profile")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404, detail="Discovery job not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc


@app.get("/api/adc/health")
async def adc_health() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(f"{ADAPTER_URL}/healthz")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler adapter unavailable") from exc


async def adapter_read(path: str) -> Any:
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(f"{ADAPTER_URL}{path}")
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="NetScaler read operation failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler adapter unavailable") from exc


@app.get("/api/adc/version")
async def adc_version() -> Any:
    return await adapter_read("/api/adc/version")


@app.get("/api/adc/appfw/profiles")
async def adc_appfw_profiles() -> Any:
    return await adapter_read("/api/adc/appfw/profiles")


@app.post("/api/adc/appfw/profiles/duplicate-plan")
async def duplicate_appfw_profile_plan(request: ProfileDuplicateRequest) -> dict[str, Any]:
    profiles_payload = await adapter_read("/api/adc/appfw/profiles")
    profiles = nitro_records(profiles_payload, "appfwprofile")
    source = next((item for item in profiles if str(item.get("name", "")) == request.profile_name), None)
    if not source:
        raise HTTPException(status_code=404, detail="Source AppFW profile was not found")
    requested_name = (request.duplicate_name or "").strip()
    if requested_name and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", requested_name):
        raise HTTPException(status_code=422, detail="Destination profile name may contain only letters, numbers, underscore, dot, and hyphen")
    if requested_name and requested_name in {str(item.get("name", "")) for item in profiles}:
        raise HTTPException(status_code=409, detail="Duplicate profile name already exists")
    if not requested_name:
        slug = re.sub(r"[^a-z0-9]+", "-", request.profile_name.lower()).strip("-")[:80] or "appfw-profile"
        requested_name = f"{slug}-custom"
        suffix = 2
        existing_names = {str(item.get("name", "")) for item in profiles}
        while requested_name in existing_names:
            requested_name = f"{slug}-custom-{suffix}"
            suffix += 1
    source_snapshot = {key: source.get(key) for key in ("name", "type", "state", "signatures", "builtin") if key in source}
    profile_body: dict[str, Any] = {"name": requested_name}
    if source.get("type"):
        profile_body["type"] = source.get("type")
    if str(source.get("signatures", "")).strip():
        profile_body["signatures"] = str(source.get("signatures")).strip()
    profile_type = source.get("type")
    cli_type = profile_type[0] if isinstance(profile_type, list) and profile_type else profile_type
    cli_create = f"add appfw profile {requested_name}{(' ' + str(cli_type)) if cli_type else ''}"
    if str(source.get("signatures", "")).strip():
        cli_create += f" && set appfw profile {requested_name} -signatures {str(source.get('signatures')).strip()}"
    plan = {
        "operation_id": "appfw-profile-duplicate",
        "plan_status": "prepared-disabled",
        "approval_required": True,
        "changes_applied": False,
        "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true",
        "source_profile": request.profile_name,
        "proposed_profile_name": requested_name,
        "source_snapshot": source_snapshot,
        "copy_mode": "copy-source-profile-to-new-custom-profile",
        "checks": [
            {"name": "Source profile", "status": "passed", "detail": "The source AppFW profile was found in the current ADC inventory."},
            {"name": "Destination name", "status": "passed", "detail": "The proposed custom profile name is not currently present."},
            {"name": "Write safety", "status": "blocked", "detail": "No ADC change is applied from this plan view."},
        ],
        "write_plan": {
            "resource": "appfwprofile",
            "action": "duplicate-profile",
            "source_profile": request.profile_name,
            "destination_profile": requested_name,
            "mode": "Log",
            "status": "blocked-until-approved",
            "requires_drift_check": True,
            "rollback": "Delete only the newly created destination profile after verifying it is not referenced.",
        },
        "command_preview": {
            "create": {
                "nitro": {"method": "POST", "path": "/nitro/v1/config/appfwprofile", "body": {"appfwprofile": profile_body}},
                "cli_equivalent": cli_create,
                "note": "Credentials and session headers are intentionally omitted from the preview.",
            },
            "rollback": {
                "nitro": {"method": "DELETE", "path": f"/nitro/v1/config/appfwprofile/{requested_name}"},
                "cli_equivalent": f"rm appfw profile {requested_name}",
                "note": "Rollback is allowed only after the destination profile is confirmed unreferenced.",
            },
        },
        "rollback": [
            "Verify the destination profile is not referenced by an AppFW policy or binding.",
            "Delete only the newly created destination profile.",
            "Re-read the source profile and target bindings.",
        ],
        "note": "Proposal only. The source profile is not modified and no destination profile is created.",
    }
    plan["plan_fingerprint"] = plan_fingerprint(plan)
    return plan


def duplicate_plan_job_key(source_profile: str, destination_profile: str) -> str:
    return f"profile-duplicate:{source_profile}:{destination_profile}"[:128]


@app.post("/api/adc/appfw/profiles/duplicate-plan/approve")
async def approve_duplicate_profile_plan(request: DuplicateProfileApprovalRequest) -> dict[str, Any]:
    if request.approval_phrase != "APPROVE PLAN":
        raise HTTPException(status_code=400, detail="Exact approval phrase APPROVE PLAN is required")
    plan = await duplicate_appfw_profile_plan(ProfileDuplicateRequest(profile_name=request.source_profile, duplicate_name=request.destination_profile))
    if plan.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Duplicate profile plan fingerprint changed")
    try:
        approval_id, expires_at = await asyncio.to_thread(save_plan_approval_sync, duplicate_plan_job_key(request.source_profile, request.destination_profile), request.plan_fingerprint, [], plan)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Plan approval database unavailable") from exc
    return {"approval_id": approval_id, "status": "approved", "source_profile": request.source_profile, "destination_profile": request.destination_profile, "plan_fingerprint": request.plan_fingerprint, "approved_at": datetime.now(timezone.utc), "expires_at": expires_at, "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true", "changes_applied": False}


@app.post("/api/adc/appfw/profiles/duplicate-plan/preflight")
async def preflight_duplicate_profile_plan(request: DuplicateProfilePreflightRequest) -> dict[str, Any]:
    approval = await asyncio.to_thread(load_plan_approval_sync, request.approval_id)
    expected_job = duplicate_plan_job_key(request.source_profile, request.destination_profile)
    if not approval or approval.get("status") != "approved" or approval.get("job_id") != expected_job:
        raise HTTPException(status_code=403, detail="Valid approved duplicate profile plan not found")
    if approval.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Approval does not match the duplicate profile plan")
    if approval.get("expires_at") and approval["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Plan approval has expired")
    current_plan = await duplicate_appfw_profile_plan(ProfileDuplicateRequest(profile_name=request.source_profile, duplicate_name=request.destination_profile))
    current_fingerprint = current_plan.get("plan_fingerprint")
    checks = [
        {"name": "Approval validity", "status": "passed", "detail": "Approval exists and has not expired."},
        {"name": "Plan fingerprint", "status": "passed" if current_fingerprint == request.plan_fingerprint else "failed", "detail": "The current duplicate plan matches the approved plan." if current_fingerprint == request.plan_fingerprint else "The source profile or destination state changed."},
        {"name": "Source profile", "status": "passed" if current_plan.get("source_profile") == request.source_profile else "failed", "detail": "The source profile is still present."},
        {"name": "Destination name", "status": "passed", "detail": "The destination profile name is still available."},
        {"name": "Rollback snapshot", "status": "passed", "detail": "Rollback will remove only the newly created destination profile after reference checks."},
    ]
    status = "drift-detected" if any(item["status"] == "failed" for item in checks) else ("blocked-write-disabled" if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true" else "ready-for-apply")
    rollback_snapshot = {"status": "ready", "destination_profile": request.destination_profile, "action": "delete-new-profile-after-reference-check", "verification": ["Confirm the destination profile is not referenced.", "Re-read the source profile and AppFW bindings."]}
    try:
        preview_id = await asyncio.to_thread(save_change_preview_sync, request.approval_id, expected_job, request.plan_fingerprint, status, request.plan_fingerprint, current_fingerprint or "", checks, rollback_snapshot)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Change preview database unavailable") from exc
    return {"preview_id": preview_id, "status": status, "approval_id": request.approval_id, "source_profile": request.source_profile, "destination_profile": request.destination_profile, "plan_fingerprint": request.plan_fingerprint, "checks": checks, "rollback_snapshot": rollback_snapshot, "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true", "changes_applied": False}


@app.post("/api/adc/writes/appfw-profile-duplicate")
async def apply_duplicate_profile(request: DuplicateProfileWriteRequest) -> dict[str, Any]:
    if request.confirmation_phrase != "ENABLE WRITE":
        raise HTTPException(status_code=400, detail="Exact confirmation phrase ENABLE WRITE is required")
    if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    expected_job = duplicate_plan_job_key(request.source_profile, request.destination_profile)
    approval = await asyncio.to_thread(load_plan_approval_sync, request.approval_id)
    if not approval or approval.get("status") != "approved" or approval.get("job_id") != expected_job or approval.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=403, detail="Valid approved duplicate profile plan not found")
    if approval.get("expires_at") and approval["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Plan approval has expired")
    preview = await asyncio.to_thread(load_change_preview_sync, request.preview_id)
    if not preview or preview.get("status") != "ready-for-apply" or preview.get("approval_id") != request.approval_id or preview.get("job_id") != expected_job or preview.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=403, detail="Successful duplicate profile preflight is required")
    current_plan = await duplicate_appfw_profile_plan(ProfileDuplicateRequest(profile_name=request.source_profile, duplicate_name=request.destination_profile))
    if current_plan.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Duplicate profile plan drifted; regenerate and re-approve")
    source = current_plan.get("source_snapshot") or {}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(f"{ADAPTER_URL}/api/adc/writes/appfw-profile-duplicate", json={"destination_profile": request.destination_profile, "profile_type": source.get("type"), "signature_binding": source.get("signatures")})
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="NetScaler duplicate profile write failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler write service unavailable") from exc
    nsip_payload = await adapter_read("/api/adc/target")
    nsip = str(nsip_payload.get("host", "unknown")) if isinstance(nsip_payload, dict) else "unknown"
    try:
        await asyncio.to_thread(save_write_audit_sync, "appfw-profile-duplicate", nsip, request.source_profile, request.destination_profile, "applied", {"mode": "Log", "source_profile": request.source_profile, "changes_applied": True})
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Write audit database unavailable") from exc
    return {"changes_applied": True, "source_profile": request.source_profile, "destination_profile": request.destination_profile, "mode": "Log", "adapter_result": result}


@app.post("/api/adc/writes/appfw-profile-duplicate/rollback")
async def rollback_duplicate_profile(request: DuplicateProfileWriteRequest) -> dict[str, Any]:
    if request.confirmation_phrase != "ENABLE WRITE":
        raise HTTPException(status_code=400, detail="Exact confirmation phrase ENABLE WRITE is required")
    if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    expected_job = duplicate_plan_job_key(request.source_profile, request.destination_profile)
    approval = await asyncio.to_thread(load_plan_approval_sync, request.approval_id)
    preview = await asyncio.to_thread(load_change_preview_sync, request.preview_id)
    if not approval or approval.get("job_id") != expected_job or approval.get("plan_fingerprint") != request.plan_fingerprint or not preview or preview.get("status") != "ready-for-apply":
        raise HTTPException(status_code=403, detail="Valid duplicate profile approval and preflight are required")
    policies = await adapter_read("/api/adc/appfw/policies")
    if request.destination_profile in json.dumps(policies, sort_keys=True):
        raise HTTPException(status_code=409, detail="Rollback blocked because the destination profile appears in the current AppFW policy inventory")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.delete(f"{ADAPTER_URL}/api/adc/writes/appfw-profile-duplicate/{quote(request.destination_profile, safe='')}")
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="NetScaler duplicate profile rollback failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler write service unavailable") from exc
    nsip_payload = await adapter_read("/api/adc/target")
    nsip = str(nsip_payload.get("host", "unknown")) if isinstance(nsip_payload, dict) else "unknown"
    await asyncio.to_thread(save_write_audit_sync, "appfw-profile-duplicate-rollback", nsip, request.source_profile, request.destination_profile, "rolled-back", {"changes_applied": True})
    return {"changes_applied": True, "rolled_back": True, "destination_profile": request.destination_profile, "adapter_result": result}


@app.get("/api/adc/appfw/policies")
async def adc_appfw_policies() -> Any:
    return await adapter_read("/api/adc/appfw/policies")


@app.get("/api/adc/signatures")
async def adc_signatures() -> Any:
    return await adapter_read("/api/adc/signatures")


@app.get("/api/adc/signatures/catalog")
async def adc_signature_catalog() -> dict[str, Any]:
    signatures_payload = await adapter_read("/api/adc/signatures")
    version_payload = await adapter_read("/api/adc/version")
    target_payload = await adapter_read("/api/adc/target")
    catalog = parse_signature_catalog(signatures_payload)
    catalog["nsip"] = str(target_payload.get("host", "unknown"))[:64] if isinstance(target_payload, dict) else "unknown"
    catalog["adc_version"] = adc_version_value(version_payload)
    try:
        await asyncio.to_thread(save_signature_inventory_sync, catalog["nsip"], catalog["adc_version"], catalog)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature inventory database unavailable") from exc
    return catalog


def signature_profile_name(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
        raise HTTPException(status_code=422, detail="Profile name may contain only letters, numbers, underscore, dot, and hyphen")
    return value


def signature_set_fingerprint(plan: dict[str, Any], selected_urls: list[str], destination_profile: str) -> str:
    fingerprint_input = {
        "job_id": plan.get("job_id"),
        "source_profile": plan.get("source_profile"),
        "destination_profile": destination_profile,
        "source_snapshot": plan.get("source_snapshot"),
        "technology_context": plan.get("technology_context"),
        "available_signatures": plan.get("available_signatures"),
        "selected_signature_urls": sorted(set(selected_urls)),
    }
    return hashlib.sha256(json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def signature_set_commands(source_snapshot: dict[str, Any], destination_profile: str, selected_entries: list[dict[str, Any]]) -> dict[str, Any]:
    profile_body: dict[str, Any] = {"name": destination_profile}
    if source_snapshot.get("type"):
        profile_body["type"] = source_snapshot.get("type")
    if len(selected_entries) == 1:
        profile_body["signatures"] = selected_entries[0].get("name")
        return {
            "binding_supported": True,
            "create": {"nitro": {"method": "POST", "path": "/nitro/v1/config/appfwprofile", "body": {"appfwprofile": profile_body}}, "cli_equivalent": f"add appfw profile {destination_profile} && set appfw profile {destination_profile} -signatures {selected_entries[0].get('name')}", "note": "This is the exact sanitized request shape; credentials and session headers are omitted."},
            "enable": {"nitro": {"method": "PUT", "path": "/nitro/v1/config/appfwprofile", "body": {"appfwprofile": {"name": destination_profile, "state": "ENABLED"}}}, "cli_equivalent": f"enable appfw profile {destination_profile}"},
            "rollback": {"nitro": {"method": "DELETE", "path": f"/nitro/v1/config/appfwprofile/{destination_profile}"}, "cli_equivalent": f"rm appfw profile {destination_profile}"},
        }
    return {
        "binding_supported": False,
        "create": {"nitro": None, "cli_equivalent": None, "note": "The current ADC adapter exposes one AppFW profile signature binding. Reduce the selected set to exactly one catalog before apply."},
        "enable": None,
        "rollback": {"nitro": {"method": "DELETE", "path": f"/nitro/v1/config/appfwprofile/{destination_profile}"}, "cli_equivalent": f"rm appfw profile {destination_profile}"},
    }


async def build_signature_set_plan(job_id: str, source_profile_name: str | None = None, destination_profile_name: str | None = None) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            job_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}")
            job_response.raise_for_status()
            profile_response = await client.get(f"{DISCOVERY_WORKER_URL}/jobs/{job_id}/profile")
            profile_response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=404, detail="Completed discovery job was not found") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Discovery worker unavailable") from exc
    job = job_response.json()
    profile = profile_response.json()
    if job.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Signature proposal requires a completed discovery job")
    analysis = await get_discovery_analysis(job_id)
    profiles_payload = await adapter_read("/api/adc/appfw/profiles")
    signatures_payload = await adapter_read("/api/adc/signatures")
    target_payload = await adapter_read("/api/adc/target")
    profiles = nitro_records(profiles_payload, "appfwprofile")
    source_name = source_profile_name
    if source_name:
        source = next((item for item in profiles if str(item.get("name", "")) == source_name), None)
    else:
        preferred = [item for item in profiles if "web" in str(item.get("name", "")).lower() and "default" in str(item.get("name", "")).lower()]
        source = (preferred or profiles)[0] if (preferred or profiles) else None
        source_name = str(source.get("name", "")) if source else ""
    if not source:
        raise HTTPException(status_code=404, detail="Source AppFW profile was not found")
    source_snapshot = {key: source.get(key) for key in ("name", "type", "state", "signatures", "builtin") if key in source}
    existing_names = {str(item.get("name", "")) for item in profiles}
    destination = signature_profile_name(destination_profile_name or f"{source_name}-custom-signatures")
    if destination == source_name:
        raise HTTPException(status_code=409, detail="Destination profile must be different from the source profile")
    suffix = 2
    base_destination = destination
    while destination in existing_names and destination != source_name:
        destination = signature_profile_name(f"{base_destination}-{suffix}")
        suffix += 1
    catalog = parse_signature_catalog(signatures_payload)
    recommendations = analysis.get("protection_plan", {}).get("signature_recommendations", [])
    recommendation_keys = [str(item.get("catalog_key", "")) for item in recommendations]
    generic_intents = analysis.get("generic_protection_intents", [])
    rule_catalog_resolution = resolve_rule_catalog(generic_intents, [])
    technology_names = [str(item.get("technology", "")) for item in (profile.get("technologies", []) or []) if item.get("technology")]
    current_binding = str(source.get("signatures", "")).strip().lower()
    available: list[dict[str, Any]] = []
    for entry in catalog.get("entries", []):
        entry_name = str(entry.get("name") or "")
        entry_url = str(entry.get("url") or "")
        searchable = f"{entry_name} {entry_url}".lower()
        matching_keys = []
        for key in recommendation_keys:
            tokens = [token for token in key.replace("-", " ").split() if len(token) > 2 and token not in {"web", "baseline"}]
            if (key == "web-baseline" and ("default" in searchable or "web" in searchable)) or any(token in searchable for token in tokens):
                matching_keys.append(key)
        baseline = bool(current_binding and (current_binding in entry_name.lower() or current_binding in entry_url.lower() or entry_name.lower() in current_binding or entry_url.lower() in current_binding))
        recommended = bool(matching_keys or baseline)
        available.append({"name": entry_name, "url": entry_url, "base_version": entry.get("base_version"), "encrypted_version": entry.get("encrypted_version"), "creation_date": entry.get("creation_date"), "selected": recommended, "baseline": baseline, "recommended": recommended, "matching_catalog_keys": matching_keys, "matching_technologies": technology_names[:20], "reason": "Existing source binding or technology/application recommendation." if recommended else "Available on the ADC but not selected by the current discovery evidence."})
    selected_urls = [item["url"] for item in available if item.get("selected") and item.get("url")]
    if rule_catalog_resolution["status"] == "blocked-missing-rule-level-catalog":
        for item in available:
            item["selected"] = False
            item["recommended"] = False
            item["reason"] = "Catalog file is available, but rule-level metadata is required before generic applicability can be resolved."
        selected_urls = []
    baseline_urls = [item["url"] for item in available if item.get("baseline") and item.get("url")]
    selected_entries = [item for item in available if item.get("url") in selected_urls]
    technology_context = {"primary_technology": (analysis.get("application") or {}).get("primary_technology"), "technologies": technology_names[:50], "recommendation_keys": recommendation_keys, "generic_protection_intents": generic_intents, "rule_catalog_resolution": rule_catalog_resolution, "route_count": len(profile.get("route_inventory", [])), "field_count": len(profile.get("field_formats", [])), "evidence_count": len(profile.get("evidence", []))}
    plan = {"job_id": job_id, "nsip": str(target_payload.get("host", "unknown"))[:64] if isinstance(target_payload, dict) else "unknown", "source_profile": source_name, "destination_profile": destination, "source_snapshot": source_snapshot, "technology_context": technology_context, "rule_catalog_resolution": rule_catalog_resolution, "available_signatures": available, "selected_signature_urls": selected_urls, "added_signature_urls": sorted(set(selected_urls) - set(baseline_urls)), "removed_signature_urls": sorted(set(baseline_urls) - set(selected_urls)), "commands": signature_set_commands(source_snapshot, destination, selected_entries), "status": "blocked-missing-rule-level-catalog" if rule_catalog_resolution["status"] == "blocked-missing-rule-level-catalog" else "draft", "approval_required": True, "changes_applied": False, "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true", "note": "Generic intents are resolved against normalized provider rule metadata. Catalog-file metadata alone is never treated as an applicable rule selection."}
    plan["plan_fingerprint"] = signature_set_fingerprint(plan, selected_urls, destination)
    return plan


def signature_set_response(record: dict[str, Any]) -> dict[str, Any]:
    return {"signature_set_id": record.get("id"), "job_id": record.get("job_id"), "nsip": record.get("nsip"), "source_profile": record.get("source_profile"), "destination_profile": record.get("destination_profile"), "status": record.get("status"), "plan_fingerprint": record.get("plan_fingerprint"), "source_snapshot": record.get("source_snapshot"), "technology_context": record.get("technology_context"), "available_signatures": record.get("available_signatures"), "selected_signature_urls": record.get("selected_signature_urls"), "added_signature_urls": record.get("added_signature_urls"), "removed_signature_urls": record.get("removed_signature_urls"), "approval_id": record.get("approval_id"), "approved_at": record.get("approved_at"), "expires_at": record.get("expires_at"), "preview_id": record.get("preview_id"), "preflight_status": record.get("preflight_status"), "changes_applied": record.get("changes_applied", False), "commands": signature_set_commands(record.get("source_snapshot") or {}, record.get("destination_profile", ""), [item for item in (record.get("available_signatures") or []) if item.get("url") in (record.get("selected_signature_urls") or [])])}


def signature_set_record_values(plan: dict[str, Any]) -> dict[str, Any]:
    return {"job_id": plan["job_id"], "nsip": plan["nsip"], "source_profile": plan["source_profile"], "destination_profile": plan["destination_profile"], "status": plan["status"], "plan_fingerprint": plan["plan_fingerprint"], "source_snapshot": plan["source_snapshot"], "technology_context": plan["technology_context"], "available_signatures": plan["available_signatures"], "selected_signature_urls": plan["selected_signature_urls"], "added_signature_urls": plan["added_signature_urls"], "removed_signature_urls": plan["removed_signature_urls"]}


def signature_set_fingerprint_from_record(record: dict[str, Any], selected_urls: list[str], destination: str) -> str:
    base = {"job_id": record["job_id"], "source_profile": record["source_profile"], "source_snapshot": record["source_snapshot"], "technology_context": record["technology_context"], "available_signatures": record["available_signatures"]}
    return signature_set_fingerprint(base, selected_urls, destination)


@app.post("/api/signature-sets/prepare")
async def prepare_signature_set(request: SignatureSetPrepareRequest) -> dict[str, Any]:
    destination = signature_profile_name(request.destination_profile) if request.destination_profile else None
    plan = await build_signature_set_plan(request.job_id, request.source_profile, destination)
    try:
        set_id = await asyncio.to_thread(save_signature_set_sync, signature_set_record_values(plan))
        record = await asyncio.to_thread(load_signature_set_sync, set_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set database unavailable") from exc
    return {**plan, "signature_set_id": set_id, "commands": plan["commands"]}


@app.get("/api/signature-sets")
async def list_signature_sets(job_id: str | None = Query(default=None, max_length=128)) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(list_signature_sets_sync, job_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set database unavailable") from exc


@app.get("/api/signature-sets/{set_id}")
async def get_signature_set(set_id: str) -> dict[str, Any]:
    try:
        record = await asyncio.to_thread(load_signature_set_sync, set_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set database unavailable") from exc
    if not record:
        raise HTTPException(status_code=404, detail="Signature set was not found")
    return signature_set_response(record)


@app.patch("/api/signature-sets/{set_id}")
async def edit_signature_set(set_id: str, request: SignatureSetEditRequest) -> dict[str, Any]:
    destination = signature_profile_name(request.destination_profile)
    record = await asyncio.to_thread(load_signature_set_sync, set_id)
    if not record:
        raise HTTPException(status_code=404, detail="Signature set was not found")
    if record.get("status") in {"applied", "rolled-back"}:
        raise HTTPException(status_code=409, detail="Applied signature sets cannot be edited")
    available = record.get("available_signatures") or []
    available_urls = {str(item.get("url")) for item in available if item.get("url")}
    selected = sorted(set(str(value)[:300] for value in request.selected_signature_urls if value))
    if not set(selected).issubset(available_urls):
        raise HTTPException(status_code=422, detail="Selected signature catalog is not present in the current ADC inventory")
    baseline = {str(item.get("url")) for item in available if item.get("baseline") and item.get("url")}
    values = {"destination_profile": destination, "status": "edited", "plan_fingerprint": signature_set_fingerprint_from_record(record, selected, destination), "selected_signature_urls": selected, "added_signature_urls": sorted(set(selected) - baseline), "removed_signature_urls": sorted(set(baseline) - set(selected)), "approval_id": None, "approved_at": None, "expires_at": None, "preview_id": None, "preflight_status": None}
    try:
        await asyncio.to_thread(update_signature_set_sync, set_id, values)
        updated = await asyncio.to_thread(load_signature_set_sync, set_id)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set database unavailable") from exc
    return signature_set_response(updated or record)


@app.post("/api/signature-sets/{set_id}/approve")
async def approve_signature_set(set_id: str, request: SignatureSetApprovalRequest) -> dict[str, Any]:
    if request.approval_phrase != "APPROVE SIGNATURE SET":
        raise HTTPException(status_code=400, detail="Exact approval phrase APPROVE SIGNATURE SET is required")
    record = await asyncio.to_thread(load_signature_set_sync, set_id)
    if not record:
        raise HTTPException(status_code=404, detail="Signature set was not found")
    if record.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Signature set changed; regenerate the approval view")
    approval_id = str(uuid4())
    approved_at = datetime.now(timezone.utc)
    expires_at = approved_at + timedelta(minutes=30)
    try:
        await asyncio.to_thread(update_signature_set_sync, set_id, {"status": "approved", "approval_id": approval_id, "approved_at": approved_at, "expires_at": expires_at})
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set database unavailable") from exc
    return {"signature_set_id": set_id, "approval_id": approval_id, "status": "approved", "plan_fingerprint": request.plan_fingerprint, "approved_at": approved_at, "expires_at": expires_at, "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true", "changes_applied": False}


@app.post("/api/signature-sets/{set_id}/preflight")
async def preflight_signature_set(set_id: str, request: SignatureSetPreflightRequest) -> dict[str, Any]:
    record = await asyncio.to_thread(load_signature_set_sync, set_id)
    if not record:
        raise HTTPException(status_code=404, detail="Signature set was not found")
    if record.get("approval_id") != request.approval_id or record.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Approved signature set not found")
    if record.get("expires_at") and record["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Signature-set approval has expired")
    if record.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Approval does not match the signature set")
    current = await build_signature_set_plan(record["job_id"], record["source_profile"], record["destination_profile"])
    selected_urls = list(record.get("selected_signature_urls") or [])
    current_urls = {str(item.get("url")) for item in current.get("available_signatures", []) if item.get("url")}
    current["selected_signature_urls"] = selected_urls
    current["added_signature_urls"] = list(record.get("added_signature_urls") or [])
    current["removed_signature_urls"] = list(record.get("removed_signature_urls") or [])
    current["plan_fingerprint"] = signature_set_fingerprint(current, selected_urls, record["destination_profile"])
    checks = [
        {"name": "Approval validity", "status": "passed", "detail": "Approval exists and has not expired."},
        {"name": "Plan fingerprint", "status": "passed" if current["plan_fingerprint"] == request.plan_fingerprint else "failed", "detail": "Current discovery, ADC inventory, and edited selection match the approved plan." if current["plan_fingerprint"] == request.plan_fingerprint else "Discovery or ADC inventory changed since approval."},
        {"name": "Source profile", "status": "passed" if current.get("source_snapshot", {}).get("name") == record["source_profile"] else "failed", "detail": "Source profile is still present."},
        {"name": "Selected catalogs", "status": "passed" if set(selected_urls).issubset(current_urls) and selected_urls else "failed", "detail": f"{len(selected_urls)} selected catalog(s) are still available on the ADC."},
        {"name": "Destination name", "status": "passed" if record["destination_profile"] not in {str(item.get("name", "")) for item in nitro_records(await adapter_read("/api/adc/appfw/profiles"), "appfwprofile")} else "failed", "detail": "Destination profile name is unused."},
        {"name": "ADC binding model", "status": "passed" if len(selected_urls) == 1 else "failed", "detail": "One selected catalog can be bound by the current adapter." if len(selected_urls) == 1 else "The current ADC profile binding exposes one signature catalog; reduce the selection to one before apply."},
    ]
    status = "drift-detected" if any(item["status"] == "failed" for item in checks) else ("blocked-write-disabled" if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true" else "ready-for-apply")
    expected_config = hashlib.sha256(json.dumps({"source": current.get("source_snapshot"), "available": current.get("available_signatures")}, sort_keys=True, default=str).encode()).hexdigest()
    rollback = {"status": "ready", "destination_profile": record["destination_profile"], "action": "delete-new-profile-after-reference-check", "verification": ["Confirm destination profile is not referenced.", "Re-read source profile and resulting signature binding."]}
    try:
        preview_id = await asyncio.to_thread(save_change_preview_sync, request.approval_id, set_id, request.plan_fingerprint, status, expected_config, expected_config, checks, rollback)
        await asyncio.to_thread(update_signature_set_sync, set_id, {"preflight_status": status, "preview_id": preview_id})
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Signature-set preflight database unavailable") from exc
    return {"signature_set_id": set_id, "preview_id": preview_id, "status": status, "approval_id": request.approval_id, "plan_fingerprint": request.plan_fingerprint, "checks": checks, "rollback_snapshot": rollback, "commands": signature_set_commands(record["source_snapshot"], record["destination_profile"], [item for item in current.get("available_signatures", []) if item.get("url") in selected_urls]), "write_enabled": os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() == "true", "changes_applied": False}


@app.post("/api/signature-sets/{set_id}/apply")
async def apply_signature_set(set_id: str, request: SignatureSetWriteRequest) -> dict[str, Any]:
    if request.confirmation_phrase != "ENABLE WRITE":
        raise HTTPException(status_code=400, detail="Exact confirmation phrase ENABLE WRITE is required")
    if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    record = await asyncio.to_thread(load_signature_set_sync, set_id)
    preview = await asyncio.to_thread(load_change_preview_sync, request.preview_id)
    if not record or record.get("status") != "approved" or record.get("approval_id") != request.approval_id or record.get("plan_fingerprint") != request.plan_fingerprint or not preview or preview.get("status") != "ready-for-apply":
        raise HTTPException(status_code=403, detail="Approved signature set and successful preflight are required")
    current = await build_signature_set_plan(record["job_id"], record["source_profile"], record["destination_profile"])
    selected = [item for item in current.get("available_signatures", []) if item.get("url") in (record.get("selected_signature_urls") or [])]
    current["plan_fingerprint"] = signature_set_fingerprint(current, list(record.get("selected_signature_urls") or []), record["destination_profile"])
    if current["plan_fingerprint"] != request.plan_fingerprint or len(selected) != 1:
        raise HTTPException(status_code=409, detail="Signature set drifted or does not contain exactly one applicable ADC catalog")
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.post(f"{ADAPTER_URL}/api/adc/writes/signature-set", json={"destination_profile": record["destination_profile"], "profile_type": record["source_snapshot"].get("type"), "signature_name": selected[0].get("name"), "enable": True})
            response.raise_for_status()
            result = response.json()
        await asyncio.to_thread(save_write_audit_sync, "signature-set-apply", record["nsip"], record["source_profile"], selected[0].get("name", ""), "applied", {"destination_profile": record["destination_profile"], "selected_signature_url": selected[0].get("url"), "mode": "Log", "enabled": True, "changes_applied": True})
        await asyncio.to_thread(update_signature_set_sync, set_id, {"status": "applied", "changes_applied": True})
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="NetScaler signature-set apply failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler write service unavailable") from exc
    return {"signature_set_id": set_id, "changes_applied": True, "destination_profile": record["destination_profile"], "signature_name": selected[0].get("name"), "enabled": True, "adapter_result": result}


@app.post("/api/signature-sets/{set_id}/rollback")
async def rollback_signature_set(set_id: str, request: SignatureSetWriteRequest) -> dict[str, Any]:
    if request.confirmation_phrase != "ENABLE WRITE":
        raise HTTPException(status_code=400, detail="Exact confirmation phrase ENABLE WRITE is required")
    if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    record = await asyncio.to_thread(load_signature_set_sync, set_id)
    preview = await asyncio.to_thread(load_change_preview_sync, request.preview_id)
    if not record or record.get("approval_id") != request.approval_id or record.get("plan_fingerprint") != request.plan_fingerprint or not preview or preview.get("status") != "ready-for-apply":
        raise HTTPException(status_code=403, detail="Approved signature set and successful preflight are required")
    policies = await adapter_read("/api/adc/appfw/policies")
    if record["destination_profile"] in json.dumps(policies, sort_keys=True):
        raise HTTPException(status_code=409, detail="Rollback blocked because the destination profile is referenced")
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            response = await client.delete(f"{ADAPTER_URL}/api/adc/writes/appfw-profile-duplicate/{quote(record['destination_profile'], safe='')}")
            response.raise_for_status()
            result = response.json()
        await asyncio.to_thread(save_write_audit_sync, "signature-set-rollback", record["nsip"], record["source_profile"], record["destination_profile"], "rolled-back", {"changes_applied": True})
        await asyncio.to_thread(update_signature_set_sync, set_id, {"status": "rolled-back", "changes_applied": False})
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail="NetScaler signature-set rollback failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler write service unavailable") from exc
    return {"signature_set_id": set_id, "rolled_back": True, "changes_applied": True, "adapter_result": result}


@app.post("/api/adc/writes/appfw-profile-signature")
async def apply_appfw_profile_signature(request: SignatureWriteRequest) -> dict[str, Any]:
    if request.confirmation_phrase != "ENABLE WRITE":
        raise HTTPException(status_code=400, detail="Exact confirmation phrase ENABLE WRITE is required")
    if os.getenv("NETSCALER_WRITE_ENABLED", "false").strip().lower() != "true":
        raise HTTPException(status_code=403, detail="NetScaler write mode is disabled")
    if not request.job_id or not request.approval_id or not request.plan_fingerprint or not request.preview_id:
        raise HTTPException(status_code=403, detail="Approved plan, approval id, plan fingerprint, and preflight preview are required")
    approval = await asyncio.to_thread(load_plan_approval_sync, request.approval_id)
    if not approval or approval.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Valid approved plan not found")
    if approval.get("job_id") != request.job_id or approval.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Approval does not match the requested discovery plan")
    if approval.get("expires_at") and approval["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Plan approval has expired")
    preview = await asyncio.to_thread(load_change_preview_sync, request.preview_id)
    if not preview or preview.get("status") != "ready-for-apply":
        raise HTTPException(status_code=403, detail="A successful pre-write validation preview is required")
    if preview.get("approval_id") != request.approval_id or preview.get("job_id") != request.job_id or preview.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Pre-write preview does not match the approved plan")
    selected_catalog_urls = [str(value)[:300] for value in (approval.get("selected_catalog_urls") or []) if value]
    current_plan = await get_adc_plan(request.job_id, selected_catalog_url=selected_catalog_urls)
    if current_plan.get("plan_fingerprint") != request.plan_fingerprint:
        raise HTTPException(status_code=409, detail="Approved plan drifted; regenerate and re-approve before writing")
    selected_profile = (current_plan.get("adc_catalog_match") or {}).get("selected_profile") or {}
    if selected_profile.get("name") and selected_profile.get("name") != request.profile_name:
        raise HTTPException(status_code=409, detail="Requested AppFW profile does not match the approved plan")
    if request.signature_catalog_url not in selected_catalog_urls:
        raise HTTPException(status_code=422, detail="Requested signature catalog was not included in the approved plan")
    profiles_payload = await adapter_read("/api/adc/appfw/profiles")
    profiles = nitro_records(profiles_payload, "appfwprofile")
    profile = next((item for item in profiles if str(item.get("name", "")) == request.profile_name), None)
    if not profile:
        raise HTTPException(status_code=404, detail="Target AppFW profile was not found")
    current_binding = str(profile.get("signatures", "")).strip() or None
    expected_binding = str(request.expected_signature_binding or "").strip() or None
    if current_binding != expected_binding:
        raise HTTPException(status_code=409, detail="AppFW profile changed since the plan was generated; drift check failed")
    catalog = parse_signature_catalog(await adapter_read("/api/adc/signatures"))
    selected = next((item for item in catalog.get("entries", []) if item.get("url") == request.signature_catalog_url), None)
    if not selected:
        raise HTTPException(status_code=422, detail="Requested signature catalog is not present in the current ADC inventory")
    nsip_payload = await adapter_read("/api/adc/target")
    nsip = str(nsip_payload.get("host", "unknown")) if isinstance(nsip_payload, dict) else "unknown"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(f"{ADAPTER_URL}/api/adc/writes/appfw-profile-signature", json={"profile_name": request.profile_name, "signature_name": selected["name"]})
            response.raise_for_status()
            result = response.json()
    except httpx.HTTPStatusError as exc:
        try:
            await asyncio.to_thread(save_write_audit_sync, "appfw-profile-signature", nsip, request.profile_name, selected["name"], "failed", {"status_code": exc.response.status_code})
        except psycopg.Error:
            pass
        raise HTTPException(status_code=502, detail="NetScaler AppFW profile write failed") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="NetScaler write service unavailable") from exc
    try:
        await asyncio.to_thread(save_write_audit_sync, "appfw-profile-signature", nsip, request.profile_name, selected["name"], "applied", {"catalog_url": selected["url"], "mode": "Log", "changes_applied": True})
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Write audit database unavailable") from exc
    return {"changes_applied": True, "nsip": nsip, "profile_name": request.profile_name, "signature_name": selected["name"], "mode": "Log", "adapter_result": result}


@app.get("/api/adc/topology/lbvservers")
async def topology_lbvservers() -> Any:
    return await adapter_read("/api/adc/lbvservers")


@app.get("/api/adc/topology/csvservers")
async def topology_csvservers() -> Any:
    return await adapter_read("/api/adc/csvservers")


@app.get("/api/adc/topology/cspolicies")
async def topology_cspolicies() -> Any:
    return await adapter_read("/api/adc/cspolicies")


@app.get("/api/adc/topology/services")
async def topology_services() -> Any:
    return await adapter_read("/api/adc/services")


@app.get("/api/adc/topology/servicegroups")
async def topology_servicegroups() -> Any:
    return await adapter_read("/api/adc/servicegroups")


@app.get("/api/adc/ha/nodes")
async def adc_ha_nodes() -> Any:
    return await adapter_read("/api/adc/ha/nodes")
