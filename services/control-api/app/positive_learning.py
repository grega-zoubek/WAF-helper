"""Build conservative, non-persistent positive-model candidates from redacted browser metadata."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.positive_model import (
    AuthenticationState,
    ConfidenceAssessment,
    DecisionMode,
    Environment,
    EvidenceRef,
    EvidenceSource,
    FieldConstraints,
    FieldLocation,
    FieldModel,
    FieldShape,
    Lifecycle,
    PositiveModelDocument,
    Requiredness,
    Sensitivity,
    ValueType,
)


SECRET_NAME = re.compile(r"(?:pass(?:word)?|secret|token|credential|authorization|api[_-]?key|session|csrf|xsrf)", re.I)
SAFE_FIELD_NAME = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.:\[\]-]{0,255}$")
FORBIDDEN_SOURCE_KEYS = {"value", "raw_value", "values", "raw_values", "body", "request_body", "response_body", "cookie_value", "cookie_values", "headers", "request_headers", "response_headers", "cookies", "samples"}


def _reject_raw_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).casefold() in FORBIDDEN_SOURCE_KEYS:
                raise ValueError("Raw values, headers, cookies, samples, and bodies are not accepted")
            _reject_raw_material(child)
    elif isinstance(value, list):
        for child in value:
            _reject_raw_material(child)


def _confidence(sample_count: int, selected: bool = False) -> ConfidenceAssessment:
    score = min(0.45, 0.2 + 0.05 * max(0, min(sample_count - 1, 5)))
    if selected:
        score = min(0.5, score + 0.05)
    return ConfidenceAssessment(
        score=score,
        sample_count=max(1, sample_count),
        independent_session_count=1,
        source_count=1,
    )


def _sensitivity(name: str, input_type: str = "") -> Sensitivity:
    if input_type.casefold() == "password" or re.search(r"(?:pass(?:word)?|secret|credential)", name, re.I):
        return Sensitivity.CREDENTIAL
    if SECRET_NAME.search(name):
        return Sensitivity.SECRET
    return Sensitivity.UNKNOWN


def _field(
    name: str,
    location: FieldLocation,
    sample_count: int,
    selected_names: set[str],
    input_type: str = "",
    value_type: ValueType = ValueType.UNKNOWN,
    format_hint: str | None = None,
) -> FieldModel:
    safe_name = name[:256]
    selected = safe_name.casefold() in selected_names
    return FieldModel(
        name=safe_name,
        location=location,
        sensitivity=_sensitivity(safe_name, input_type),
        shape=FieldShape(
            sample_count=max(0, sample_count),
            present_count=max(0, sample_count),
            distinct_value_count=0,
            observed_types=[value_type] if value_type != ValueType.UNKNOWN else [ValueType.UNKNOWN],
            character_classes=[],
            min_length=None,
            max_length=None,
        ),
        proposed_constraints=FieldConstraints(
            requiredness=Requiredness.UNKNOWN,
            value_type=value_type,
            format_hint=format_hint,
        ),
        confidence=_confidence(sample_count, selected),
    )


def build_guided_candidate(source: dict[str, Any]) -> PositiveModelDocument:
    """Return a strict observe-only candidate; source values and bodies are never accepted."""
    _reject_raw_material(source)
    hostname = str(source.get("hostname", ""))
    session_id = str(source.get("session_id", ""))
    requests = [
        item for item in source.get("requests", [])
        if isinstance(item, dict)
        and str(item.get("method", "")).upper() in {"GET", "HEAD"}
        and str(item.get("path_template", "")).startswith("/")
    ]
    selected_names: set[str] = set()
    selected_types: dict[str, str] = {}
    for item in source.get("interaction_events", []):
        if not isinstance(item, dict):
            continue
        linked_names = set(item.get("matched_parameter_names", [])) if item.get("correlated_request_ids") else set()
        for value in linked_names:
            if isinstance(value, str) and value:
                selected_names.add(value.casefold())
                selected_types[value.casefold()] = str(item.get("input_type", ""))

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in requests:
        grouped[(str(item["path_template"]), str(item["method"]).upper())].append(item)

    endpoints = []
    now = datetime.now(timezone.utc)
    for (path_template, method), observations in sorted(grouped.items()):
        fields: list[FieldModel] = []
        query_counts: Counter[str] = Counter()
        request_headers: Counter[str] = Counter()
        response_headers: Counter[str] = Counter()
        response_types: set[str] = set()
        for item in observations:
            query_counts.update({name for name in item.get("query_names", []) if isinstance(name, str) and SAFE_FIELD_NAME.fullmatch(name)})
            request_headers.update({name.lower()[:128] for name in item.get("request_header_names", []) if isinstance(name, str) and SAFE_FIELD_NAME.fullmatch(name)})
            response_headers.update({name.lower()[:128] for name in item.get("response_header_names", []) if isinstance(name, str) and SAFE_FIELD_NAME.fullmatch(name)})
            content_type = str(item.get("response_content_type", "")).split(";", 1)[0].strip().lower()
            if content_type and len(content_type) <= 128:
                response_types.add(content_type)
        for name, count in sorted(query_counts.items(), key=lambda pair: pair[0].casefold()):
            fields.append(_field(name, FieldLocation.QUERY, count, selected_names, selected_types.get(name.casefold(), "")))
        for name, count in sorted(request_headers.items()):
            fields.append(_field(name, FieldLocation.REQUEST_HEADER, count, selected_names))
        for name, count in sorted(response_headers.items()):
            fields.append(_field(name, FieldLocation.RESPONSE_HEADER, count, selected_names))

        cookies = [item for item in source.get("cookie_metadata", []) if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]]
        for cookie in cookies:
            cookie_path = str(cookie.get("path", "/")) or "/"
            path_prefix = cookie_path.rstrip("/") or "/"
            eligible_observations = [
                item for item in observations
                if item.get("cookie_header_present")
                and (not cookie.get("secure") or item.get("scheme") == "https")
                and (path_prefix == "/" or path_template == path_prefix or path_template.startswith(path_prefix + "/"))
            ]
            cookie_name = str(cookie["name"])[:256]
            if eligible_observations and SAFE_FIELD_NAME.fullmatch(cookie_name):
                fields.append(_field(cookie_name, FieldLocation.REQUEST_COOKIE, len(eligible_observations), selected_names))

        used_path_names: set[str] = set()
        for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*):(int|uuid)\}", path_template):
            param_name, param_kind = match.groups()
            if param_name in used_path_names:
                suffix = 2
                while f"{param_name}_{suffix}" in used_path_names:
                    suffix += 1
                param_name = f"{param_name}_{suffix}"
            used_path_names.add(param_name)
            value_type = ValueType.INTEGER if param_kind == "int" else ValueType.STRING
            fields.append(_field(
                param_name, FieldLocation.PATH, len(observations), selected_names,
                value_type=value_type, format_hint="uuid" if param_kind == "uuid" else None,
            ))

        endpoint_id = str(uuid4())
        evidence = EvidenceRef(
            evidence_id=f"guided-{session_id[:64]}-{endpoint_id}",
            source=EvidenceSource.GUIDED_BROWSER,
            observed_at=now,
            sample_count=min(10_000_000, max(1, len(observations))),
            confidence=_confidence(len(observations)).score,
        )
        endpoints.append({
            "path_template": path_template,
            "method": method,
            "request_content_types": [],
            "response_content_types": sorted(response_types),
            "authentication": AuthenticationState.UNKNOWN,
            "fields": fields,
            "evidence": [evidence],
            "confidence": _confidence(len(observations)),
            "lifecycle": Lifecycle.DISCOVERED,
            "decision_mode": DecisionMode.OBSERVE,
        })

    app_id = re.sub(r"[^A-Za-z0-9._:-]", "-", hostname)[:128] or "guided-app"
    candidate = PositiveModelDocument(
        model_id=f"guided-{uuid4()}",
        application_id=f"app-{app_id}"[:128],
        hostname=hostname,
        environment=Environment.TEST,
        lifecycle=Lifecycle.DISCOVERED,
        endpoints=endpoints,
    )
    return candidate
