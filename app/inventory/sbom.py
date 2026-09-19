import json
from pathlib import Path

from app.models import Component


EVIDENCE_CONFIDENCE = {"CycloneDX": 1.0, "SPDX": 1.0}


def load_cyclonedx(path: str | Path) -> list[Component]:
    """Load components from a CycloneDX JSON SBOM as authoritative evidence."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM is not a CycloneDX document")
    components = []
    for item in document.get("components", []):
        product = item.get("name")
        version = item.get("version")
        if not product or not version:
            continue
        components.append(Component(
            product=product,
            version=version,
            purl=item.get("purl"),
            evidence_type="SBOM",
            evidence_source="CycloneDX",
            confidence=EVIDENCE_CONFIDENCE["CycloneDX"],
        ))
    return components
