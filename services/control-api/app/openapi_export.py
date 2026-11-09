"""Export a metadata-only OpenAPI 3 document from an observed positive-model candidate.

Only names, locations and coarse types appear: no values, examples or response bodies. The
document is a starting point for a reviewed API specification, not a validated contract.
"""

from __future__ import annotations

import re
from typing import Any

_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*):(int|uuid)\}")
_TYPES = {"integer": "integer", "number": "number", "boolean": "boolean", "array": "array", "object": "object", "string": "string"}


def _schema(field: dict[str, Any]) -> dict[str, Any]:
    constraints = field.get("proposed_constraints") or {}
    schema: dict[str, Any] = {"type": _TYPES.get(str(constraints.get("value_type") or "string"), "string")}
    if schema["type"] == "array":
        schema["items"] = {}
    if constraints.get("format_hint") in {"uuid", "email", "uri", "date-time"}:
        schema["format"] = constraints["format_hint"]
    return schema


def _is_api(endpoint: dict[str, Any]) -> bool:
    return any("json" in str(t).lower() for t in (endpoint.get("response_content_types") or []) + (endpoint.get("request_content_types") or [])) or any(
        (f.get("location") == "json") for f in endpoint.get("fields") or [])


def openapi_from_model(model: dict[str, Any], title: str | None = None) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for endpoint in model.get("endpoints") or []:
        if not _is_api(endpoint):
            continue
        template = str(endpoint.get("path_template") or "/")
        names = _PARAM.findall(template)
        path = _PARAM.sub(lambda m: "{" + m.group(1) + "}", template)
        parameters = [{"name": name, "in": "path", "required": True, "schema": {"type": "integer"} if kind == "int" else {"type": "string", "format": "uuid"}} for name, kind in names]
        body: dict[str, dict[str, Any]] = {"application/json": {}, "application/x-www-form-urlencoded": {}}
        for field in endpoint.get("fields") or []:
            location = field.get("location")
            name = str(field.get("name") or "")
            if location == "query":
                parameters.append({"name": name, "in": "query", "required": False, "schema": _schema(field)})
            elif location == "json":
                body["application/json"].setdefault("properties", {})[name] = _schema(field)
            elif location == "form":
                body["application/x-www-form-urlencoded"].setdefault("properties", {})[name] = _schema(field)
        operation: dict[str, Any] = {"parameters": parameters, "responses": {"default": {"description": "Observed; response bodies are not modelled"}},
                                     "x-observed-authentication": str(endpoint.get("authentication") or "unknown")}
        content = {media: {"schema": {"type": "object", **schema}} for media, schema in body.items() if schema.get("properties")}
        if content and str(endpoint.get("method")).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            operation["requestBody"] = {"content": content}
        paths.setdefault(path, {})[str(endpoint.get("method") or "GET").lower()] = operation
    return {"openapi": "3.0.3", "info": {"title": title or f"Observed API of {model.get('hostname', 'application')}", "version": "0.0.0-observed",
            "description": "Generated from observed metadata only. Review before use; not validated against any appliance."},
            "paths": dict(sorted(paths.items())), "x-generated-by": "waf-intelligence"}
