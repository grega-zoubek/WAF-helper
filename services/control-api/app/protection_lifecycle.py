"""LOG → review → promote / exception helpers for exported custom signature sets.

These helpers create new review-only drafts. They never bypass approval,
preflight, or ENABLE WRITE gates.
"""

from __future__ import annotations

import re
from typing import Any


OBJECT_NAME_RE = re.compile(r"^[A-Za-z0-9_.# @=-]{1,31}$")


def _safe_object_name(base: str, suffix: str) -> str:
    root = re.sub(r"[^A-Za-z0-9_.# @=-]+", "-", str(base or "waf").strip())[:24].rstrip("-_. ")
    candidate = f"{root}-{suffix}"[:31]
    if not OBJECT_NAME_RE.fullmatch(candidate):
        candidate = f"waf-{suffix}"[:31]
    return candidate


def build_promote_selection(record: dict[str, Any], rule_ids: list[str] | None = None) -> dict[str, Any]:
    """Select rules from an exported LOG set for a BLOCK promotion draft."""
    selected = list(record.get("selected_rules") or [])
    available_ids = [str(item.get("rule_id")) for item in selected if isinstance(item, dict) and item.get("rule_id") is not None]
    requested = [str(value).strip() for value in (rule_ids or available_ids) if str(value).strip()]
    missing = sorted({value for value in requested if value not in set(available_ids)})
    kept = [item for item in selected if str(item.get("rule_id")) in set(requested)]
    return {
        "kind": "promote-to-block",
        "source_custom_signature_set_id": record.get("custom_signature_set_id"),
        "source_signature_object_name": record.get("signature_object_name"),
        "source_action": record.get("action"),
        "action": "BLOCK",
        "signature_object_name": _safe_object_name(record.get("signature_object_name") or "waf", "blk"),
        "selected_rule_ids": [str(item.get("rule_id")) for item in kept],
        "selected_rules": kept,
        "missing_requested_rule_ids": missing,
        "note": "Promotion creates a new proposal with BLOCK action for the selected rules. Export remains gated by approval, preflight, and ENABLE WRITE.",
    }


def build_exception_selection(record: dict[str, Any], disable_rule_ids: list[str]) -> dict[str, Any]:
    """Remove noisy rules from an exported set for a LOG exception draft."""
    disable = {str(value).strip() for value in disable_rule_ids if str(value).strip()}
    selected = list(record.get("selected_rules") or [])
    available_ids = {str(item.get("rule_id")) for item in selected if isinstance(item, dict) and item.get("rule_id") is not None}
    unknown = sorted(disable - available_ids)
    kept = [item for item in selected if str(item.get("rule_id")) not in disable]
    removed = [item for item in selected if str(item.get("rule_id")) in disable]
    return {
        "kind": "exception-disable-rules",
        "source_custom_signature_set_id": record.get("custom_signature_set_id"),
        "source_signature_object_name": record.get("signature_object_name"),
        "source_action": record.get("action") or "LOG",
        "action": record.get("action") or "LOG",
        "signature_object_name": _safe_object_name(record.get("signature_object_name") or "waf", "exc"),
        "selected_rule_ids": [str(item.get("rule_id")) for item in kept],
        "selected_rules": kept,
        "disabled_rule_ids": [str(item.get("rule_id")) for item in removed],
        "missing_requested_rule_ids": unknown,
        "note": "Exception draft keeps LOG mode and drops the selected noisy rule IDs. It does not change the ADC until the operator exports a replacement object through the guarded workflow.",
    }


def summarize_protection_status(adc_status: dict[str, Any], sets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Operator-facing summary combining ADC bindings and exported set metadata."""
    sets = sets or []
    exported = [item for item in sets if item.get("status") == "exported"]
    latest = exported[0] if exported else (sets[0] if sets else None)
    policies = adc_status.get("policies") or []
    profiles = adc_status.get("profiles") or []
    hits = adc_status.get("hit_counters") or []
    binding_state = "bound" if adc_status.get("bound_vservers") else ("profile-present" if profiles else ("object-present" if adc_status.get("signatures") else "unbound"))
    return {
        "status": adc_status.get("status") or "unavailable",
        "binding_state": binding_state,
        "signature_object_name": adc_status.get("signature_object_name") or (latest or {}).get("signature_object_name"),
        "action": (latest or {}).get("action"),
        "custom_signature_set_id": (latest or {}).get("custom_signature_set_id"),
        "job_id": (latest or {}).get("job_id"),
        "bound_vservers": adc_status.get("bound_vservers") or [],
        "profiles": [{"name": item.get("name"), "signatures": item.get("signatures"), "hits": item.get("hits"), "last_seen": item.get("last_seen")} for item in profiles],
        "policies": [{"name": item.get("name") or item.get("policyname"), "profile": item.get("profilename") or item.get("profile"), "bound_vservers": item.get("bound_vservers") or [], "hits": item.get("hits"), "last_seen": item.get("last_seen"), "priority": item.get("priority")} for item in policies],
        "hit_counters": hits,
        "hits_available": bool(adc_status.get("hits_available")),
        "sets": [{"custom_signature_set_id": item.get("custom_signature_set_id"), "signature_object_name": item.get("signature_object_name"), "action": item.get("action"), "status": item.get("status"), "selected_rule_count": item.get("selected_rule_count"), "updated_at": str(item.get("updated_at") or "")} for item in sets[:20]],
        "note": adc_status.get("note") or "",
        "reason": adc_status.get("reason"),
    }
