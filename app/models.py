from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Component:
    product: str
    version: str
    purl: str | None = None
    evidence_type: str = "unknown"
    evidence_source: str = "unknown"
    confidence: float = 0.0


@dataclass(frozen=True)
class Vulnerability:
    cve: str
    product: str
    affected_range: str
    severity: float | None = None
    kev: bool = False


@dataclass(frozen=True)
class Signature:
    rule_id: int
    cves: tuple[str, ...]
    product: str
    introduced_version: int | None = None
    inspection: str = "request"
    performance_warning: bool = False


@dataclass(frozen=True)
class SignatureState:
    rule_id: int
    present: bool
    enabled: bool
    actions: tuple[str, ...] = ()


@dataclass
class Assessment:
    application: str
    components: list[Component] = field(default_factory=list)
    applicable: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)

