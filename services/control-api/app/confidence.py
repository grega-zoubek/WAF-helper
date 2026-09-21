"""F5-inspired confidence dimensions for signature proposals.

The scanner keeps applicability, signature accuracy, attack risk, and
enforcement readiness separate.  A single combined score would hide the
difference between a confidently detected technology and a signature that is
likely to create false positives.
"""

from __future__ import annotations

from typing import Any


RATING_SCORES = {"high": 0.90, "medium": 0.65, "low": 0.35, "unknown": 0.50}
RATING_LABELS = ("high", "medium", "low")


def _rating(value: Any, fallback: str = "unknown") -> str:
    normalized = str(value or "").strip().casefold()
    return normalized if normalized in RATING_SCORES else fallback


def _score(value: Any, fallback: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return fallback
    return max(0.0, min(1.0, parsed))


def technology_detection_scores(profile: dict[str, Any]) -> dict[str, float]:
    """Map catalog technology tags to passive detector confidence scores."""
    by_key: dict[str, float] = {}
    for item in profile.get("technologies") or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("technology_key") or item.get("technology") or "").strip().casefold()
        if not key:
            continue
        score = _score(item.get("confidence_score"), RATING_SCORES.get(_rating(item.get("confidence")), 0.50))
        by_key[key] = max(by_key.get(key, 0.0), score)

    tag_scores: dict[str, float] = {}
    context = profile.get("signature_technology_context") or {}
    for match in context.get("technology_matches", []) if isinstance(context, dict) else []:
        if not isinstance(match, dict):
            continue
        key = str(match.get("technology_key") or match.get("technology") or "").strip().casefold()
        score = by_key.get(key, 0.50)
        for tag in match.get("matched_signature_tags") or []:
            tag_key = str(tag).strip().casefold()
            if tag_key:
                tag_scores[tag_key] = max(tag_scores.get(tag_key, 0.0), score)
    return tag_scores


def rule_confidence(
    rule: dict[str, Any],
    *,
    technology_tags: set[str],
    technology_scores: dict[str, float],
    explicitly_selected_product: bool = False,
    explicitly_selected_technology: bool = False,
    selection_sources: set[str] | None = None,
) -> dict[str, Any]:
    """Calculate independent confidence dimensions for one proposed rule."""
    sources = selection_sources or set()
    rule_tags = {str(value).strip().casefold() for value in (rule.get("technology_tags") or []) if value}
    matched_tags = sorted(rule_tags.intersection(technology_tags))
    if explicitly_selected_product or (explicitly_selected_technology and matched_tags):
        applicability_score = 1.0
        applicability = "explicit"
        applicability_basis = "administrator-selected product" if explicitly_selected_product else "administrator-selected technology"
        detection_score = None
    elif matched_tags:
        detection_score = max(technology_scores.get(tag, 0.50) for tag in matched_tags)
        applicability_score = min(0.99, detection_score + (0.05 if len(matched_tags) > 1 else 0.0))
        applicability = "high" if applicability_score >= 0.85 else "medium" if applicability_score >= 0.60 else "low"
        applicability_basis = f"detected technology tag: {', '.join(matched_tags)}"
    elif not rule_tags and sources:
        detection_score = None
        applicability_score = 0.70
        applicability = "medium"
        applicability_basis = "generic protection intent"
    else:
        detection_score = 0.0
        applicability_score = 0.0
        applicability = "low"
        applicability_basis = "no matching technology evidence"

    accuracy = _rating(rule.get("accuracy"))
    risk = _rating(rule.get("risk"), _rating(rule.get("severity")))
    return {
        "applicability": applicability,
        "applicability_score": round(applicability_score, 2),
        "applicability_basis": applicability_basis,
        "matched_technology_tags": matched_tags,
        "detection_score": round(detection_score, 2) if detection_score is not None else None,
        "accuracy": accuracy,
        "accuracy_score": RATING_SCORES[accuracy],
        "risk": risk,
        "risk_score": RATING_SCORES[risk],
        "enforcement_readiness": "staged",
        "enforcement_ready": False,
        "runtime_evidence": "not-collected",
        "recommended_action": "LOG",
    }


def confidence_summary(rules: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {label: 0 for label in (*RATING_LABELS, "explicit")}
    accuracy_counts = {label: 0 for label in (*RATING_LABELS, "unknown")}
    risk_counts = {label: 0 for label in (*RATING_LABELS, "unknown")}
    readiness_counts = {"staged": 0, "ready": 0, "enforced": 0, "suppressed": 0}
    for rule in rules:
        item = rule.get("confidence") or {}
        applicability = str(item.get("applicability") or "low")
        accuracy = str(item.get("accuracy") or "unknown")
        risk = str(item.get("risk") or "unknown")
        readiness = str(item.get("enforcement_readiness") or "staged")
        if applicability in counts:
            counts[applicability] += 1
        if accuracy in accuracy_counts:
            accuracy_counts[accuracy] += 1
        if risk in risk_counts:
            risk_counts[risk] += 1
        readiness_counts[readiness] = readiness_counts.get(readiness, 0) + 1
    return {
        "applicability": counts,
        "accuracy": accuracy_counts,
        "risk": risk_counts,
        "enforcement_readiness": readiness_counts,
        "automatic_block_allowed": False,
        "reason": "Runtime staging and false-positive review are required before BLOCK.",
    }
