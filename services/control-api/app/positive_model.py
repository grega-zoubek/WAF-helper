"""Versioned, value-minimizing contract for learned positive-security models.

This module describes application behavior and reviewed constraints. It is not
an enforcement engine and does not accept raw HTTP samples.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


POSITIVE_MODEL_SCHEMA_VERSION = "1.0.0"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class Lifecycle(str, Enum):
    DISCOVERED = "discovered"
    CANDIDATE = "candidate"
    REVIEWED = "reviewed"
    STAGED = "staged"
    ENFORCED = "enforced"
    RETIRED = "retired"


class DecisionMode(str, Enum):
    OBSERVE = "observe"
    ALERT = "alert"
    BLOCK = "block"


class EvidenceSource(str, Enum):
    PASSIVE_CRAWL = "passive_crawl"
    HEADLESS_BROWSER = "headless_browser"
    GUIDED_BROWSER = "guided_browser"
    OPENAPI = "openapi"
    HAR_IMPORT = "har_import"
    ACCESS_LOG = "access_log"
    NETSCALER_LEARNING = "netscaler_learning"
    MANUAL = "manual"


class AuthenticationState(str, Enum):
    PUBLIC = "public"
    OPTIONAL = "optional"
    AUTHENTICATED = "authenticated"
    ROLE_SPECIFIC = "role_specific"
    UNKNOWN = "unknown"


class FieldLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    FORM = "form"
    JSON = "json"
    XML = "xml"
    REQUEST_HEADER = "request_header"
    RESPONSE_HEADER = "response_header"
    REQUEST_COOKIE = "request_cookie"
    RESPONSE_COOKIE = "response_cookie"


class ValueType(str, Enum):
    UNKNOWN = "unknown"
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    BINARY = "binary"


class CharacterClass(str, Enum):
    LETTER = "letter"
    DIGIT = "digit"
    WHITESPACE = "whitespace"
    PUNCTUATION = "punctuation"
    CONTROL = "control"
    NON_ASCII = "non_ascii"


class Sensitivity(str, Enum):
    UNKNOWN = "unknown"
    PUBLIC = "public"
    INTERNAL = "internal"
    PERSONAL = "personal"
    CREDENTIAL = "credential"
    SECRET = "secret"


class Requiredness(str, Enum):
    UNKNOWN = "unknown"
    REQUIRED = "required"
    OPTIONAL = "optional"
    CONDITIONAL = "conditional"


class EvidenceRef(StrictModel):
    """Opaque pointer to separately stored, already-redacted evidence."""

    evidence_id: str = Field(min_length=1, max_length=128)
    source: EvidenceSource
    observed_at: datetime
    sample_count: int = Field(default=1, ge=1, le=10_000_000)
    confidence: float | None = Field(default=None, ge=0, le=1)

    @field_validator("evidence_id")
    @classmethod
    def validate_opaque_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
            raise ValueError("evidence_id must be an opaque identifier, not copied content")
        return value

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class ConfidenceAssessment(StrictModel):
    score: float = Field(ge=0, le=1)
    sample_count: int = Field(default=0, ge=0, le=10_000_000)
    independent_session_count: int = Field(default=0, ge=0, le=1_000_000)
    source_count: int = Field(default=0, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @model_validator(mode="after")
    def validate_time_order(self) -> "ConfidenceAssessment":
        for name, value in (("first_seen", self.first_seen), ("last_seen", self.last_seen)):
            if value and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"{name} must include a timezone")
        if self.first_seen and self.last_seen and self.first_seen > self.last_seen:
            raise ValueError("first_seen must not be later than last_seen")
        if self.independent_session_count > self.sample_count:
            raise ValueError("independent_session_count cannot exceed sample_count")
        return self


class FieldShape(StrictModel):
    """Aggregate observations only; actual field values are intentionally absent."""

    sample_count: int = Field(default=0, ge=0, le=10_000_000)
    present_count: int = Field(default=0, ge=0, le=10_000_000)
    distinct_value_count: int = Field(default=0, ge=0, le=10_000_000)
    observed_types: list[ValueType] = Field(default_factory=list, max_length=8)
    character_classes: list[CharacterClass] = Field(default_factory=list, max_length=6)
    min_length: int | None = Field(default=None, ge=0, le=10_000_000)
    max_length: int | None = Field(default=None, ge=0, le=10_000_000)

    @model_validator(mode="after")
    def validate_aggregate_bounds(self) -> "FieldShape":
        if self.present_count > self.sample_count:
            raise ValueError("present_count cannot exceed sample_count")
        if self.distinct_value_count > self.present_count:
            raise ValueError("distinct_value_count cannot exceed present_count")
        if self.min_length is not None and self.max_length is not None and self.min_length > self.max_length:
            raise ValueError("min_length cannot exceed max_length")
        return self


class FieldConstraints(StrictModel):
    """Candidate or administrator-authored constraints, never captured values."""

    requiredness: Requiredness = Requiredness.UNKNOWN
    value_type: ValueType = ValueType.UNKNOWN
    min_length: int | None = Field(default=None, ge=0, le=10_000_000)
    max_length: int | None = Field(default=None, ge=0, le=10_000_000)
    min_number: float | None = None
    max_number: float | None = None
    format_hint: Literal["email", "uuid", "date", "date-time", "uri", "hostname", "ip-address"] | None = None

    @model_validator(mode="after")
    def validate_constraint_bounds(self) -> "FieldConstraints":
        if self.min_length is not None and self.max_length is not None and self.min_length > self.max_length:
            raise ValueError("min_length cannot exceed max_length")
        if self.min_number is not None and self.max_number is not None and self.min_number > self.max_number:
            raise ValueError("min_number cannot exceed max_number")
        return self


class FieldModel(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    location: FieldLocation
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    shape: FieldShape = Field(default_factory=FieldShape)
    proposed_constraints: FieldConstraints = Field(default_factory=FieldConstraints)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=100)
    confidence: ConfidenceAssessment = Field(default_factory=lambda: ConfidenceAssessment(score=0))


class EndpointModel(StrictModel):
    path_template: str = Field(min_length=1, max_length=2048)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    request_content_types: list[str] = Field(default_factory=list, max_length=32)
    response_content_types: list[str] = Field(default_factory=list, max_length=32)
    authentication: AuthenticationState = AuthenticationState.UNKNOWN
    fields: list[FieldModel] = Field(default_factory=list, max_length=1000)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=500)
    confidence: ConfidenceAssessment = Field(default_factory=lambda: ConfidenceAssessment(score=0))
    lifecycle: Lifecycle = Lifecycle.DISCOVERED
    decision_mode: DecisionMode = DecisionMode.OBSERVE

    @model_validator(mode="after")
    def validate_endpoint(self) -> "EndpointModel":
        if not self.path_template.startswith("/") or self.path_template.startswith("//"):
            raise ValueError("path_template must be an origin-relative path")
        if any(char in self.path_template for char in "?#\r\n"):
            raise ValueError("path_template must not contain query, fragment, or control characters")
        if self.decision_mode == DecisionMode.BLOCK and self.lifecycle not in {Lifecycle.STAGED, Lifecycle.ENFORCED}:
            raise ValueError("BLOCK mode requires a staged or enforced endpoint")
        field_keys = [(item.location, item.name.casefold()) for item in self.fields]
        if len(field_keys) != len(set(field_keys)):
            raise ValueError("field names must be unique within each location")
        return self


class PrivacyDeclaration(StrictModel):
    raw_observed_values_retained: Literal[False] = False
    credentials_and_tokens_redacted_before_persistence: Literal[True] = True
    raw_request_or_response_bodies_retained: Literal[False] = False


class PositiveModelDocument(StrictModel):
    schema_version: Literal["1.0.0"] = POSITIVE_MODEL_SCHEMA_VERSION
    model_id: str = Field(min_length=1, max_length=128)
    application_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=253)
    environment: Environment
    revision: int = Field(default=1, ge=1, le=1_000_000)
    lifecycle: Lifecycle = Lifecycle.DISCOVERED
    privacy: PrivacyDeclaration = Field(default_factory=PrivacyDeclaration)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=1000)
    endpoints: list[EndpointModel] = Field(default_factory=list, max_length=100_000)


def positive_model_json_schema() -> dict[str, object]:
    """Return the JSON Schema contract for API/docs consumers."""
    return PositiveModelDocument.model_json_schema()
