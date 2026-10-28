"""Compile observe-only positive-model previews for AppFW relaxation planning.

This module never enables enforcement. Output is a review artifact describing
path/method allowlist candidates derived from an accepted (or draft) model.
"""

from __future__ import annotations

from typing import Any


def compile_observe_only_preview(model: dict[str, Any], *, candidate_id: str | None = None, status: str | None = None) -> dict[str, Any]:
    endpoints = model.get("endpoints") if isinstance(model, dict) else None
    if not isinstance(endpoints, list):
        endpoints = []
    compiled: list[dict[str, Any]] = []
    skipped = 0
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            skipped += 1
            continue
        method = str(endpoint.get("method") or "GET").upper()
        path = str(endpoint.get("path_template") or endpoint.get("path") or "").strip()
        if not path:
            skipped += 1
            continue
        fields = []
        for field in endpoint.get("fields") or []:
            if not isinstance(field, dict):
                continue
            fields.append({
                "name": field.get("name"),
                "location": field.get("location"),
                "requiredness": (field.get("proposed_constraints") or {}).get("requiredness") if isinstance(field.get("proposed_constraints"), dict) else None,
                "value_type": (field.get("proposed_constraints") or {}).get("value_type") if isinstance(field.get("proposed_constraints"), dict) else None,
                "sensitivity": field.get("sensitivity"),
            })
        compiled.append({
            "method": method,
            "path_template": path,
            "authentication": endpoint.get("authentication") or "unknown",
            "decision_mode": "observe",
            "lifecycle": endpoint.get("lifecycle") or "discovered",
            "field_count": len(fields),
            "fields": fields[:50],
            "suggested_appfw_controls": [
                {"control": "start_url", "mode": "observe", "detail": f"Allow observed {method} {path} in learning/observe mode only."},
                {"control": "field_consistency", "mode": "observe", "detail": "Track observed field names without blocking."} if fields else None,
            ],
        })
        compiled[-1]["suggested_appfw_controls"] = [item for item in compiled[-1]["suggested_appfw_controls"] if item]
    return {
        "status": "observe-only-preview",
        "candidate_id": candidate_id,
        "candidate_status": status,
        "hostname": model.get("hostname") if isinstance(model, dict) else None,
        "model_id": model.get("model_id") if isinstance(model, dict) else None,
        "schema_version": model.get("schema_version") if isinstance(model, dict) else None,
        "enforcement_mode": "observe",
        "positive_model_enabled": False,
        "endpoint_count": len(compiled),
        "skipped_endpoint_count": skipped,
        "endpoints": compiled,
        "appfw_relaxation_preview": {
            "format": "netscaler-observe-only-planning",
            "blocks": False,
            "writes": False,
            "summary": f"{len(compiled)} observe-only endpoint relaxation candidates compiled; no ADC change is prepared.",
        },
        "note": "Compiled for operator review only. Enforcement remains disabled (positive_model.enabled=false).",
    }


def structured_endpoint_editor_payload(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten endpoints into GUI-editable structured rows."""
    rows: list[dict[str, Any]] = []
    for index, endpoint in enumerate((model or {}).get("endpoints") or []):
        if not isinstance(endpoint, dict):
            continue
        rows.append({
            "index": index,
            "method": str(endpoint.get("method") or "GET").upper(),
            "path_template": str(endpoint.get("path_template") or endpoint.get("path") or ""),
            "authentication": endpoint.get("authentication") or "unknown",
            "decision_mode": endpoint.get("decision_mode") or "observe",
            "lifecycle": endpoint.get("lifecycle") or "discovered",
            "field_count": len(endpoint.get("fields") or []),
        })
    return rows
