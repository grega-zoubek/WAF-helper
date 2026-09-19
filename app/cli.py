import json
import sys
from pathlib import Path

from app.assessment import run
from app.models import Signature, SignatureState, Vulnerability
from app.inventory.sbom import load_cyclonedx


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m app.cli INPUT.json")
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    components = load_cyclonedx(document["sbom"])
    vulnerabilities = [Vulnerability(**item) for item in document.get("vulnerabilities", [])]
    signatures = [Signature(cves=tuple(item.pop("cves", [])), **item) for item in document.get("signatures", [])]
    states = [SignatureState(actions=tuple(item.pop("actions", [])), **item) for item in document.get("signature_states", [])]
    result = run(document["application"], components, vulnerabilities, signatures, states)
    print(json.dumps({"application": result.application, "components": [c.__dict__ for c in result.components], "applicable": result.applicable, "coverage": result.coverage, "recommendations": result.recommendations}, indent=2))


if __name__ == "__main__":
    main()
