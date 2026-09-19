import re

from app.models import Component, Vulnerability


_VERSION = re.compile(r"\d+(?:\.\d+)*")


def _parts(value: str) -> tuple[int, ...]:
    match = _VERSION.search(value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(0).split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    size = max(len(left), len(right))
    a = left + (0,) * (size - len(left))
    b = right + (0,) * (size - len(right))
    return (a > b) - (a < b)


def version_matches(version: str, expression: str) -> bool:
    """Evaluate the small, explicit range language used by the MVP input format."""
    actual = _parts(version)
    if not actual:
        return False
    expression = expression.strip()
    for clause in expression.split(","):
        match = re.fullmatch(r"(<=|>=|<|>|=|==)?\s*([0-9][0-9A-Za-z.\-]*)", clause.strip())
        if not match:
            raise ValueError(f"Unsupported affected-version clause: {clause}")
        operator = match.group(1) or "=="
        result = _compare(actual, _parts(match.group(2)))
        if not {"<": result < 0, "<=": result <= 0, ">": result > 0, ">=": result >= 0, "=": result == 0, "==": result == 0}[operator]:
            return False
    return True


def assess(vulnerability: Vulnerability, components: list[Component]) -> list[dict]:
    results = []
    for component in components:
        if component.product.casefold() != vulnerability.product.casefold():
            continue
        applicable = version_matches(component.version, vulnerability.affected_range)
        results.append({
            "cve": vulnerability.cve,
            "component": component.product,
            "version": component.version,
            "applicability": "CONFIRMED" if applicable and component.confidence >= 1.0 else "POSSIBLE" if applicable else "NOT_APPLICABLE",
            "evidence": {"type": component.evidence_type, "source": component.evidence_source, "confidence": component.confidence},
            "kev": vulnerability.kev,
            "severity": vulnerability.severity,
        })
    return results
