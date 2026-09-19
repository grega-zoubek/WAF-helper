from app.analysis.coverage import calculate
from app.models import Signature, SignatureState


def generate(application: str, finding: dict, signature: Signature | None, state: SignatureState | None) -> dict | None:
    coverage = calculate(signature, state)
    if coverage not in {"SIGNATURE_AVAILABLE_NOT_ENABLED", "MONITORED"}:
        return None
    if signature is None or state is None:
        return None
    return {
        "id": f"REC-{finding['cve']}-{signature.rule_id}",
        "application": application,
        "type": "enable_signature_monitor_mode" if coverage == "SIGNATURE_AVAILABLE_NOT_ENABLED" else "review_signature_for_enforcement",
        "target": {"rule_id": signature.rule_id},
        "reason": {"cve": finding["cve"], "component": finding["component"], "version": finding["version"]},
        "evidence": [finding["evidence"], {"source": "netscaler_signature_intelligence", "confidence": 1.0}],
        "current_state": {"present": state.present, "enabled": state.enabled, "actions": list(state.actions)},
        "desired_state": {"enabled": True, "actions": ["log", "stats"], "block": False},
        "impact": {"performance_risk": "high" if signature.performance_warning else "low"},
        "validation_required": True,
        "rollback": {"operation": "restore_previous_signature_state"},
        "read_only": True,
    }
