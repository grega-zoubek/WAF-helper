from app.analysis.applicability import assess
from app.models import Assessment, Component, Signature, SignatureState, Vulnerability
from app.recommendations import generate


def run(application: str, components: list[Component], vulnerabilities: list[Vulnerability], signatures: list[Signature], states: list[SignatureState]) -> Assessment:
    result = Assessment(application=application, components=components)
    by_cve = {}
    for vulnerability in vulnerabilities:
        findings = assess(vulnerability, components)
        result.applicable.extend(findings)
        by_cve.setdefault(vulnerability.cve, []).extend(findings)
    signature_by_cve = {cve: signature for signature in signatures for cve in signature.cves}
    state_by_rule = {state.rule_id: state for state in states}
    for finding in result.applicable:
        signature = signature_by_cve.get(finding["cve"])
        state = state_by_rule.get(signature.rule_id) if signature else None
        status = "NO_NETSCALER_SIGNATURE" if signature is None else ("UNKNOWN" if state is None else None)
        if status is None:
            from app.analysis.coverage import calculate
            status = calculate(signature, state)
        result.coverage.append({"cve": finding["cve"], "rule_id": signature.rule_id if signature else None, "status": status})
        recommendation = generate(application, finding, signature, state)
        if recommendation:
            result.recommendations.append(recommendation)
    return result
