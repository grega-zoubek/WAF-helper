import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'services/discovery-worker'))
from app.run_ledger import checkpoint_payload,policy,fingerprint,safe_target

class LedgerTests(unittest.TestCase):
 def test_checkpoint_withholds_sensitive_query_and_fragment(self):
  value=checkpoint_payload(['https://app.test/a','https://app.test/search?token=secret','https://app.test/#/route'],[],1,0)
  self.assertEqual(value['pending_get_urls'],['https://app.test/a'])
  self.assertEqual(value['withheld_urls'],2)
  self.assertNotIn('secret',str(value))
  self.assertFalse(value['replays_submissions'])
 def test_snapshot_has_fixed_actions_and_no_query_values(self):
  scope=dict(seed_url='https://app.test:8443/?token=private',allowed_paths=['/'],max_pages=25,rate_limit_per_second=1)
  snapshot=policy(scope)
  self.assertEqual(snapshot['origin'],'https://app.test:8443')
  self.assertFalse(snapshot['state_changing_actions'])
  self.assertNotIn('private',str(snapshot))
  self.assertEqual(fingerprint(snapshot),fingerprint(dict(reversed(list(snapshot.items())))))
 def test_checkpoint_visited_is_redacted(self):
  value=checkpoint_payload([],['https://app.test/a?q=secret'],1,0)
  self.assertEqual(value['visited'],['https://app.test/a'])
