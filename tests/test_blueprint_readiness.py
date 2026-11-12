import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'services/control-api'))
from app.readiness import evaluate_readiness,promotion_readiness
from app.capabilities import resolve_capability

class ReadinessTests(unittest.TestCase):
    def test_legacy_unknown_not_ready(self):
        self.assertEqual(evaluate_readiness({})['level'],'INSUFFICIENT_EVIDENCE')
    def test_observe(self):
        v=evaluate_readiness(dict(sample_count=1,independent_session_count=1,required_roles=['anonymous'],observed_roles=['anonymous']))
        self.assertEqual(v['level'],'OBSERVE')
        self.assertFalse(v['deployment_authorized'])
    def test_review_boundaries(self):
        e=dict(sample_count=30,independent_session_count=3,distinct_value_count=5,required_roles=['user'],observed_roles=['user'])
        self.assertEqual(evaluate_readiness(e)['level'],'REVIEW')
        e['distinct_value_count']=4
        self.assertEqual(evaluate_readiness(e)['level'],'OBSERVE')
    def test_sensitive_fields_need_no_value_diversity(self):
        e=dict(sample_count=30,independent_session_count=3,field_kind='credential',session_behavior_reviewed=True,required_roles=['user'],observed_roles=['user'])
        self.assertEqual(evaluate_readiness(e)['level'],'REVIEW')
    def test_unknown_capability_blocks(self):
        self.assertEqual(resolve_capability('field_formats','14.1-73.49')['status'],'unknown')
    def test_missing_feedback_not_ready(self):
        self.assertFalse(promotion_readiness({})['ready_for_promotion_review'])
