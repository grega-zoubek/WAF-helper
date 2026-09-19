from app.models import Signature, SignatureState


def calculate(signature: Signature | None, state: SignatureState | None) -> str:
    if signature is None:
        return "NO_NETSCALER_SIGNATURE"
    if state is None or not state.present:
        return "SIGNATURE_NOT_INSTALLED"
    if not state.enabled:
        return "SIGNATURE_AVAILABLE_NOT_ENABLED"
    if "block" in {action.casefold() for action in state.actions}:
        return "PROTECTED"
    return "MONITORED"
