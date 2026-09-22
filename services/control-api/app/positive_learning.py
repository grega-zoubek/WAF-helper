"""Build conservative, non-persistent positive-model candidates from redacted browser metadata."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlparse
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
        evidence_refs = []
        source_counts = Counter(str(item.get("evidence_source", source.get("evidence_source", EvidenceSource.GUIDED_BROWSER.value))) for item in observations)
        for evidence_source, source_count in sorted(source_counts.items()):
            source_name = re.sub(r"[^A-Za-z0-9._:-]", "-", evidence_source)[:24]
            evidence_refs.append(EvidenceRef(
                evidence_id=f"{source_name}-{session_id[:48]}-{endpoint_id}",
                source=EvidenceSource(evidence_source),
                observed_at=now,
                sample_count=min(10_000_000, max(1, source_count)),
                confidence=_confidence(source_count).score,
            ))
        endpoint_confidence = min(0.65, _confidence(len(observations)).score + 0.05 * max(0, len(source_counts) - 1))
        endpoints.append({
            "path_template": path_template,
            "method": method,
            "request_content_types": [],
            "response_content_types": sorted(response_types),
            "authentication": AuthenticationState.UNKNOWN,
            "fields": fields,
            "evidence": evidence_refs,
            "confidence": ConfidenceAssessment(
                score=endpoint_confidence,
                sample_count=max(1, len(observations)),
                independent_session_count=1,
                source_count=max(1, len(source_counts)),
            ),
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


def _safe_observed_path(value: str, hostname: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        if (parsed.hostname or "").casefold() != hostname.casefold():
            return None
        path = parsed.path or "/"
    else:
        path = parsed.path or value
    if not path.startswith("/") or path.startswith("//") or any(char in path for char in "?#\r\n"):
        return None
    return path[:2048]


def build_discovery_candidate(
    hostname: str,
    job_id: str,
    profile: dict[str, Any],
    analysis: dict[str, Any],
    adc_topology: dict[str, Any] | None = None,
) -> tuple[PositiveModelDocument, dict[str, Any]]:
    """Fuse only observed, same-host GET/HEAD metadata into a review-only model draft.

    Static JavaScript candidates contribute to coverage context, never to endpoint
    allow-list candidates, because those routes have not been verified as reachable.
    """
    requests: list[dict[str, Any]] = []
    route_rows = [row for row in profile.get("route_inventory", []) if isinstance(row, dict)]
    for row in route_rows:
        method = str(row.get("request_method") or "").upper()
        if method not in {"GET", "HEAD"} or row.get("status_code") is None:
            continue
        path = _safe_observed_path(str(row.get("source_url") or ""), hostname)
        if not path:
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        header_names = metadata.get("headers") if isinstance(metadata.get("headers"), dict) else {}
        requests.append({
            "method": method,
            "path_template": path,
            "scheme": urlparse(str(row.get("source_url") or "")).scheme,
            "query_names": [key for key, _ in parse_qsl(urlparse(str(row.get("source_url") or "")).query, keep_blank_values=True) if SAFE_FIELD_NAME.fullmatch(key)],
            "response_header_names": [key for key in header_names if isinstance(key, str) and SAFE_FIELD_NAME.fullmatch(key)],
            "response_content_type": str(metadata.get("content_type") or ""),
            "evidence_source": EvidenceSource.PASSIVE_CRAWL.value,
        })
    api_keys: set[tuple[str, str]] = set()
    for item in profile.get("api_endpoints", []):
        if not isinstance(item, dict) or str(item.get("method") or "").upper() not in {"GET", "HEAD"}:
            continue
        path = _safe_observed_path(str(item.get("url") or ""), hostname)
        api_key = (path, str(item.get("method")).upper()) if path else None
        if not path or api_key in api_keys:
            continue
        if item.get("status_code") is None:
            continue
        response_headers = item.get("response_headers") if isinstance(item.get("response_headers"), dict) else {}
        content_type = next((str(value) for key, value in response_headers.items() if str(key).casefold() == "content-type"), "")
        requests.append({
            "method": str(item.get("method")).upper(),
            "path_template": path,
            "scheme": urlparse(str(item.get("url") or "")).scheme,
            "query_names": [key for key, _ in parse_qsl(urlparse(str(item.get("url") or "")).query, keep_blank_values=True) if SAFE_FIELD_NAME.fullmatch(key)],
            "response_content_type": content_type,
            "evidence_source": EvidenceSource.RUNTIME_INSPECTION.value,
        })
        api_keys.add(api_key)

    source = {
        "hostname": hostname,
        "session_id": re.sub(r"[^A-Za-z0-9._:-]", "-", job_id)[:64],
        "requests": requests,
        "interaction_events": [],
        "cookie_metadata": [],
        "evidence_source": EvidenceSource.PASSIVE_CRAWL.value,
    }
    model = build_guided_candidate(source)
    model.model_id = f"discovery-{uuid4()}"
    model.evidence = []
    if profile.get("technologies"):
        model.evidence.append(EvidenceRef(
        evidence_id=f"technology-{re.sub(r'[^A-Za-z0-9._:-]', '-', job_id)[:48]}",
        source=EvidenceSource.TECHNOLOGY_DETECTION,
        observed_at=datetime.now(timezone.utc),
        sample_count=max(1, int(profile.get("technology_count", 0))),
        confidence=max((float(item.get("confidence_score", 0)) for item in profile.get("technologies", []) if isinstance(item, dict)), default=0.0),
        ))
    if adc_topology and adc_topology.get("matched_vserver"):
        model.evidence.append(EvidenceRef(
            evidence_id=f"adc-{re.sub(r'[^A-Za-z0-9._:-]', '-', job_id)[:48]}",
            source=EvidenceSource.ADC_TOPOLOGY,
            observed_at=datetime.now(timezone.utc),
            sample_count=1,
            confidence=0.95,
        ))

    intents = analysis.get("generic_protection_intents", [])
    summary = {
        "evidence_sources": sorted({ref.source.value for endpoint in model.endpoints for ref in endpoint.evidence} | {"technology_detection"} | ({"adc_topology"} if adc_topology and adc_topology.get("matched_vserver") else set())),
        "endpoint_count": len(model.endpoints),
        "field_count": sum(len(endpoint.fields) for endpoint in model.endpoints),
        "confidence_note": "Observed same-host GET/HEAD routes only; one discovery run; static candidates are not promoted to endpoints; all endpoints remain observe-only.",
        "discovery_job_id": job_id,
        "route_candidates_not_verified": len(profile.get("route_candidates", []) or []) + len(profile.get("auth_endpoint_candidates", []) or []),
        "runtime_auth_surface_count": len(profile.get("auth_surfaces", []) or []),
        "runtime_api_endpoint_count": len(profile.get("api_endpoints", []) or []),
        "technology_signals": [str(item.get("technology"))[:128] for item in profile.get("technologies", []) if isinstance(item, dict) and item.get("technology")][:50],
        "generic_applicability": [{
            "intent_id": str(item.get("intent_id", ""))[:128],
            "score": float(item.get("applicability_score", 0)),
            "confidence": str(item.get("applicability_confidence", "low"))[:16],
        } for item in intents if isinstance(item, dict)][:30],
        "adc_match": bool(adc_topology and adc_topology.get("matched_vserver")),
        "adc_vserver": str(adc_topology.get("matched_vserver", ""))[:128] if adc_topology else "",
        "adc_topology_status": str(adc_topology.get("status", "unavailable"))[:32] if adc_topology else "unavailable",
    }
    return model, summary
