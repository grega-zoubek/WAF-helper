"""Deterministic, value-minimizing dry-run validation for positive models."""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.positive_model import (
    AuthenticationState,
    FieldLocation,
    PositiveModelDocument,
    ValueType,
)


class TransactionField(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=256)
    location: FieldLocation
    value_type: ValueType = ValueType.UNKNOWN
    length: int | None = Field(default=None, ge=0, le=10_000_000)
    count: int = Field(default=1, ge=1, le=1_000_000)


class TransactionDescriptor(BaseModel):
    """Metadata-only transaction descriptor; raw values and bodies are forbidden."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: str = Field(min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=2048)
    content_type: str | None = Field(default=None, max_length=256)
    authentication: AuthenticationState = AuthenticationState.UNKNOWN
    fields: list[TransactionField] = Field(default_factory=list, max_length=1000)

    def validate_descriptor(self) -> None:
        if self.method.upper() not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported transaction method")
        if not self.path.startswith("/") or self.path.startswith("//") or any(c in self.path for c in "?#\r\n"):
            raise ValueError("path must be an origin-relative path without query or fragment")
        keys = [(field.location, field.name.casefold()) for field in self.fields]
        if len(keys) != len(set(keys)):
            raise ValueError("transaction field names must be unique within each location")


def _route_matches(template: str, path: str) -> bool:
    template_parts = template.strip("/").split("/") if template != "/" else []
    path_parts = path.strip("/").split("/") if path != "/" else []
    if len(template_parts) != len(path_parts):
        return False
    for expected, actual in zip(template_parts, path_parts):
        parameter = re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*(?::(int|uuid))?\}", expected)
        if not parameter:
            if expected != actual:
                return False
            continue
        if not actual:
            return False
        kind = parameter.group(1)
        if kind == "int" and not actual.isdecimal():
            return False
        if kind == "uuid":
            try:
                UUID(actual)
            except ValueError:
                return False
    return True


def validate_transaction(model: PositiveModelDocument, transaction: TransactionDescriptor) -> dict[str, Any]:
    """Compare metadata to the model. This function never inspects raw values."""
    transaction.validate_descriptor()
    method = transaction.method.upper()
    matching_path = [endpoint for endpoint in model.endpoints if _route_matches(endpoint.path_template, transaction.path)]
    endpoint = next((item for item in matching_path if item.method == method), None)
    findings: list[dict[str, str]] = []

    def add(code: str, severity: str, message: str) -> None:
        findings.append({"code": code, "severity": severity, "message": message})

    if endpoint is None:
        if matching_path:
            allowed = ", ".join(sorted({item.method for item in matching_path}))
            add("method_not_modeled", "error", f"Method {method} is not modeled for {transaction.path}; modeled methods: {allowed}.")
        else:
            add("route_not_modeled", "error", f"No modeled endpoint matches {transaction.path}.")
        return {"status": "findings", "matched_endpoint": None, "findings": findings, "raw_values_received": False}

    duplicates = [item for item in matching_path if item.method == method]
    if len(duplicates) > 1:
        add("ambiguous_model_route", "error", "More than one endpoint in the model matches this path and method.")

    expected_types = {value.split(";", 1)[0].strip().casefold() for value in endpoint.request_content_types}
    observed_type = (transaction.content_type or "").split(";", 1)[0].strip().casefold()
    if expected_types and observed_type not in expected_types:
        add("content_type_mismatch", "error", f"Content type {observed_type or '(missing)'} is not modeled for this endpoint.")
    if endpoint.authentication != AuthenticationState.UNKNOWN and transaction.authentication != AuthenticationState.UNKNOWN and endpoint.authentication != transaction.authentication:
        add("authentication_context_mismatch", "warning", f"Observed authentication context is {transaction.authentication.value}; model expects {endpoint.authentication.value}.")

    observed = {(item.location, item.name.casefold()): item for item in transaction.fields}
    modeled = {(item.location, item.name.casefold()): item for item in endpoint.fields}
    for key, field in modeled.items():
        constraint = field.proposed_constraints
        actual = observed.get(key)
        if actual is None:
            if constraint.requiredness.value == "required":
                add("required_field_missing", "error", f"Required {field.location.value} field '{field.name}' was not observed.")
            continue
        expected_type = constraint.value_type
        if expected_type != ValueType.UNKNOWN and actual.value_type != ValueType.UNKNOWN and expected_type != actual.value_type:
            add("field_type_mismatch", "error", f"Field '{field.name}' has type {actual.value_type.value}; expected {expected_type.value}.")
        if actual.length is not None:
            if constraint.min_length is not None and actual.length < constraint.min_length:
                add("field_below_min_length", "error", f"Field '{field.name}' length is below the modeled minimum.")
            if constraint.max_length is not None and actual.length > constraint.max_length:
                add("field_above_max_length", "error", f"Field '{field.name}' length exceeds the modeled maximum.")
        if constraint.format_hint or constraint.min_number is not None or constraint.max_number is not None:
            add("content_constraint_not_evaluated", "info", f"Content-dependent constraint for '{field.name}' was not evaluated because raw values are intentionally excluded.")

    for key, field in observed.items():
        if key not in modeled:
            add("unexpected_field", "warning", f"Observed {field.location.value} field '{field.name}' is not present in the endpoint model.")

    return {
        "status": "pass" if not any(item["severity"] in {"error", "warning"} for item in findings) else "findings",
        "matched_endpoint": {"path_template": endpoint.path_template, "method": endpoint.method},
        "findings": findings,
        "raw_values_received": False,
    }
