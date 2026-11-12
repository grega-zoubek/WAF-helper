"""Run explicitly inside discovery-worker with WAF_LEDGER_DATABASE_TEST=1; isolated PG schema."""
import asyncio
import os
import sys
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'services/discovery-worker'))

@unittest.skipUnless(os.getenv('WAF_LEDGER_DATABASE_TEST')=='1','requires isolated PostgreSQL integration environment')
class WorkerLedgerIntegration(unittest.TestCase):
 def test_crawl_policy_checkpoint_report_and_resume(self):
  import psycopg
  from app import main as worker
  from app import run_ledger
  schema='ledger_test_'+uuid.uuid4().hex
  database=os.environ['DATABASE_URL']
  with psycopg.connect(database,autocommit=True) as c:c.execute('CREATE SCHEMA '+schema)
  original=worker.db_connect
  worker.db_connect=lambda:psycopg.connect(database,options='-csearch_path='+schema)
  class Handler(BaseHTTPRequestHandler):
   def do_GET(self):
    self.send_response(200);self.send_header('Content-Type','text/html');self.end_headers()
    self.wfile.write(b'<title>Fixture</title><a href="/second">Next</a><form action="/submit" method="post"><input name="q"></form>')
   def log_message(self,*args):pass
  server=HTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
  try:
   worker.init_db_sync()
   job=worker.DiscoveryJob(id='integration',scope=worker.DiscoveryScope(hostname='127.0.0.1',seed_url=f'http://127.0.0.1:{server.server_port}/',allowed_paths=['/'],max_pages=2,rate_limit_per_second=10))
   asyncio.run(worker.run_discovery(job))
   report=run_ledger.report(worker.db_connect,job.id)
   self.assertIsNotNone(report['policy'])
   self.assertTrue(report['events'])
   self.assertIsNotNone(report['checkpoint'])
   self.assertTrue(worker.evidence_sync(job.id)[0]['evidence_ref'].startswith('discovery:'))
   self.assertGreater(report['coverage']['successful_pages'],0)
   with self.assertRaises(psycopg.Error):
    with worker.db_connect() as c:c.execute("UPDATE discovery_run_policies SET fingerprint='tampered' WHERE run_id='integration'")
   # A missing request is not successful exploration.
   worker.save_run_sync(worker.DiscoveryJob(id='empty',scope=job.scope),'failed')
   self.assertEqual(run_ledger.report(worker.db_connect,'empty')['coverage']['status'],'failed')
   # A restart leaves an event rather than silently keeping a run active.
   worker.save_run_sync(worker.DiscoveryJob(id='lost',scope=job.scope),'running')
   self.assertEqual(worker.reconcile_incomplete_runs_sync(),1)
   self.assertEqual(run_ledger.report(worker.db_connect,'lost')['events'][-1]['status'],'interrupted')
   # Safe checkpoint resumption is accepted; completed runs cannot be scheduled again.
   run_ledger.save_checkpoint(worker.db_connect,'lost',run_ledger.checkpoint_payload([job.scope.seed_url],[],0,0))
   async def resume():
    response=await worker.resume_job('lost');self.assertEqual(response['status'],'queued')
    await worker.running_tasks['lost']
   asyncio.run(resume())
   self.assertEqual(run_ledger.report(worker.db_connect,'lost')['events'][-1]['status'],'completed')
  finally:
   server.shutdown();server.server_close();worker.db_connect=original
   with psycopg.connect(database,autocommit=True) as c:c.execute('DROP SCHEMA '+schema+' CASCADE')
