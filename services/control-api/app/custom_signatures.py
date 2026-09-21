from __future__ import annotations

import hashlib
import re
from typing import Any


LOCAL_RULE_ID_MIN = 1_000_000
LOCAL_RULE_ID_MAX = 1_999_999
PATTERN_TYPES = {"literal", "pcre", "builtin-sql", "builtin-xss"}
MATCH_LOCATIONS = {"URL_PATH_OR_HASH_ROUTE", "FORM_FIELD_NAME_OR_ID", "URL_QUERY", "HEADER", "BODY", "COOKIE"}
ACTIONS = {"LOG", "BLOCK"}
SEVERITIES = {"Low", "Medium", "High"}
VIOLATION_TYPES = {"Vulnerable", "Warning"}


def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def allocate_local_rule_id(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    span = LOCAL_RULE_ID_MAX - LOCAL_RULE_ID_MIN + 1
    return LOCAL_RULE_ID_MIN + (int(digest[:16], 16) % span)


def validate_draft_input(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    object_name = _text(data.get("signature_object_name"), 64)
    if not object_name or not re.fullmatch(r"[A-Za-z0-9_.# @=-]{1,31}", object_name):
        errors.append("signature_object_name must use the documented NetScaler name characters and be 1-31 characters")
    rule_name = _text(data.get("rule_name"), 128)
    if not rule_name:
        errors.append("rule_name is required")
    category = _text(data.get("category"), 64)
    if not category or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", category):
        errors.append("category must contain only letters, numbers, dot, underscore, or hyphen")
    log_string = _text(data.get("log_string"), 256)
    if not log_string:
        errors.append("log_string is required")
    pattern_type = _text(data.get("pattern_type"), 32)
    if pattern_type not in PATTERN_TYPES:
        errors.append(f"pattern_type must be one of: {', '.join(sorted(PATTERN_TYPES))}")
    pattern = _text(data.get("pattern"), 4096)
    if pattern_type in {"literal", "pcre"} and not pattern:
        errors.append("pattern is required for literal and pcre rules")
    if pattern_type == "literal" and len(pattern) < 3:
        errors.append("literal patterns must contain at least 3 characters")
    if pattern_type == "pcre":
        if len(pattern) < 3:
            errors.append("pcre patterns must contain at least 3 characters")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"pcre pattern is not locally compilable: {exc}")
            if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
                errors.append("pcre pattern contains a nested quantifier and requires manual review")
    match_location = _text(data.get("match_location"), 64)
    if match_location not in MATCH_LOCATIONS:
        errors.append(f"match_location must be one of: {', '.join(sorted(MATCH_LOCATIONS))}")
    action = _text(data.get("action"), 16).upper() or "LOG"
    if action not in ACTIONS:
        errors.append("action must be LOG or BLOCK")
    if bool(data.get("enabled")):
        errors.append("new custom rules must start disabled and be promoted only after review")
    if not 1 <= int(data.get("harm_score", 5)) <= 10:
        errors.append("harm_score must be between 1 and 10")
    severity = _text(data.get("severity"), 16) or "Medium"
    if severity not in SEVERITIES:
        errors.append("severity must be Low, Medium, or High")
    violation_type = _text(data.get("violation_type"), 16) or "Warning"
    if violation_type not in VIOLATION_TYPES:
        errors.append("violation_type must be Vulnerable or Warning")
    if len(data.get("positive_test_cases") or []) > 20 or len(data.get("negative_test_cases") or []) > 20:
        errors.append("positive_test_cases and negative_test_cases allow at most 20 entries each")
    if not data.get("positive_test_cases") or not data.get("negative_test_cases"):
        errors.append("at least one positive and one negative offline test case are required")
    return errors


def build_custom_signature_spec(*, request: dict[str, Any], job: dict[str, Any], profile: dict[str, Any], existing_rule_ids: set[int] | None = None) -> dict[str, Any]:
    errors = validate_draft_input(request)
    existing_rule_ids = existing_rule_ids or set()
    seed = "|".join(_text(request.get(key), 4096) for key in ("signature_object_name", "rule_name", "category", "pattern_type", "pattern"))
    requested_rule_id = request.get("rule_id")
    rule_id = int(requested_rule_id) if requested_rule_id is not None else allocate_local_rule_id(seed)
    if not LOCAL_RULE_ID_MIN <= rule_id <= LOCAL_RULE_ID_MAX:
        errors.append("rule_id must be between 1000000 and 1999999 for a local signature rule")
    if rule_id in existing_rule_ids:
        errors.append(f"rule_id {rule_id} is already assigned in the local draft repository")
    technologies = [
        {
            "technology": item.get("technology"),
            "category": item.get("category"),
            "confidence": item.get("confidence"),
            "confidence_score": item.get("confidence_score"),
            "evidence_count": item.get("evidence_count"),
        }
        for item in (profile.get("technologies") or [])
        if isinstance(item, dict) and item.get("technology")
    ]
    detection_context = {
        "job_id": job.get("id"),
        "seed_url": (job.get("scope") or {}).get("seed_url"),
        "technology_detector_version": profile.get("technology_detector_version"),
        "technologies": technologies,
        "signature_technology_context": profile.get("signature_technology_context") or {},
        "route_count": len(profile.get("route_inventory") or []),
        "field_count": len(profile.get("field_formats") or []),
        "evidence_count": len(profile.get("evidence") or []),
        "evidence_refs": [_text(value, 160) for value in (request.get("evidence_refs") or [])[:50]],
    }
    pattern_type = _text(request.get("pattern_type"), 32)
    pattern_value = _text(request.get("pattern"), 4096)
    rule = {
        "rule_id": rule_id,
        "version": int(request.get("version") or 1),
        "enabled": False,
        "actions": ["LOG"],
        "requested_action": _text(request.get("action"), 16).upper() or "LOG",
        "category": _text(request.get("category"), 64),
        "source": "Local",
        "rule_name": _text(request.get("rule_name"), 128),
        "log_string": _text(request.get("log_string"), 256),
        "comment": _text(request.get("comment"), 512),
        "harm_score": int(request.get("harm_score") or 5),
        "severity": _text(request.get("severity"), 16) or "Medium",
        "violation_type": _text(request.get("violation_type"), 16) or "Warning",
        "match_location": _text(request.get("match_location"), 64),
        "pattern_type": pattern_type,
        "pattern": pattern_value,
        "positive_test_cases": [_text(value, 4096) for value in (request.get("positive_test_cases") or [])[:20]],
        "negative_test_cases": [_text(value, 4096) for value in (request.get("negative_test_cases") or [])[:20]],
    }
    status = "draft-needs-review" if not errors else "invalid"
    return {
        "status": status,
        "validation": {"status": "passed" if not errors else "failed", "errors": errors},
        "signature_object_name": _text(request.get("signature_object_name"), 31),
        "rule": rule,
        "detection_context": detection_context,
        "provider_artifact": {
            "format": "netscaler-local-signature-rule-spec",
            "native_xml": None,
            "native_xml_status": "blocked-until-appliance-template-validation",
            "reason": "The repository has not yet been given an appliance-exported user-defined signature template; it will not guess native XML element names or pattern encoding.",
            "import_command_template": "import appfw signatures local:<validated-native-file> <signature-object-name> -merge -autoEnableNewSignatures OFF",
            "save_command": "save ns config",
        },
        "proposal_only": True,
        "write_enabled": False,
        "changes_applied": False,
        "requires_review": True,
        "requires_offline_positive_negative_tests": True,
        "note": "Detection evidence provides scope and applicability context only; it does not create an attack pattern. The pattern and test cases must be operator-supplied or derived from separately verified vulnerability evidence.",
    }
