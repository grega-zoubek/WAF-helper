"""Evidence gates for review, deliberately separate from deployment authorization."""
import json
from pathlib import Path
from typing import Any

POLICY = json.loads((Path(__file__).parent / 'data/readiness.json').read_text())


def evaluate_readiness(evidence: dict[str, Any], policy: dict | None = None) -> dict:
    policy = policy or POLICY
    missing = []
    level = 'INSUFFICIENT_EVIDENCE'
    required_roles = set(evidence.get('required_roles') or [])
    seen_roles = set(evidence.get('observed_roles') or []) - {'unknown', ''}
    if not required_roles:
        missing.append('Recommendation role scope is unknown')
    for name, thresholds in policy['levels'].items():
        reasons = []
        for key, field in [('occurrences','sample_count'),('sessions','independent_session_count')]:
            value = evidence.get(field)
            if not isinstance(value,int) or isinstance(value,bool) or value < thresholds[key]:
                reasons.append(f'{field} requires {thresholds[key]}')
        if not seen_roles or not required_roles or not required_roles <= seen_roles:
            reasons.append('All scoped roles need attributable observations')
        kind = evidence.get('field_kind','variable')
        if thresholds['distinct']:
            if kind in {'boolean','declared_enum'}:
                if not evidence.get('declared_categories_complete'):
                    reasons.append('Declared categories are not covered')
            elif kind in {'credential','token'}:
                if not evidence.get('session_behavior_reviewed'):
                    reasons.append('Sensitive field session behavior requires review')
            else:
                count = evidence.get('distinct_value_count')
                if not isinstance(count,int) or isinstance(count,bool) or count < thresholds['distinct']:
                    reasons.append(f"distinct_value_count requires {thresholds['distinct']}")
        if name == 'SUFFICIENT_EVIDENCE_FOR_CONFIGURATION_REVIEW':
            for flag in ['successful_journeys_reviewed','conflicts_reviewed','critical_coverage_complete']:
                if evidence.get(flag) is not True: reasons.append(flag+' must be confirmed')
        if reasons:
            missing.extend(reasons)
            break
        level = name
    return {'policy_version':policy['schema_version'],'level':level,
            'missing':list(dict.fromkeys(missing)), 'deployment_authorized':False,
            'note':'Observed presence and maxima do not establish requiredness or valid limits'}


def promotion_readiness(evidence: dict, policy: dict | None = None) -> dict:
    p = (policy or POLICY)['promotion']; gaps=[]
    for field,minimum in [('observation_days',p['days']),('relevant_requests',p['requests'])]:
        value=evidence.get(field)
        if not isinstance(value,(int,float)) or isinstance(value,bool) or value<minimum:
            gaps.append(f'{field} requires {minimum}')
    for flag in ['critical_journeys_validated','all_roles_validated','telemetry_coverage_healthy']:
        if evidence.get(flag) is not True: gaps.append(flag+' must be confirmed')
    if evidence.get('unresolved_false_positive_clusters') != 0 or isinstance(evidence.get('unresolved_false_positive_clusters'),bool):
        gaps.append('False-positive clusters must be measured and resolved')
    return {'ready_for_promotion_review':not gaps,'missing':gaps,'deployment_authorized':False}
