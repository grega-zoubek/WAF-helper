"""Run with WAF_LEDGER_DATABASE_TEST=1 and DATABASE_URL pointing at a disposable PostgreSQL.

Every scenario runs inside its own throwaway schema, so no existing table is read or changed.
"""
import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / 'services/control-api'))

LEGACY_DDL = """CREATE TABLE discovery_runs (
    run_id TEXT PRIMARY KEY, kind TEXT NOT NULL, hostname TEXT NOT NULL, mode TEXT NOT NULL,
    actor TEXT NOT NULL, started_at TIMESTAMPTZ NOT NULL, ended_at TIMESTAMPTZ NOT NULL,
    policy_fingerprint TEXT NOT NULL, policy_snapshot JSONB NOT NULL, coverage_status TEXT NOT NULL,
    coverage JSONB NOT NULL, permission_counts JSONB NOT NULL, permission_events JSONB NOT NULL,
    budget JSONB NOT NULL, source_ref TEXT NOT NULL)"""


@unittest.skipUnless(os.getenv('WAF_LEDGER_DATABASE_TEST') == '1', 'requires isolated PostgreSQL integration environment')
class ControlApiRecordsIntegration(unittest.TestCase):
    def setUp(self):
        import psycopg
        from app import discovery_runs
        self.psycopg = psycopg
        self.runs = discovery_runs
        self.database = os.environ['DATABASE_URL']
        self.schema = 'records_test_' + uuid.uuid4().hex
        with psycopg.connect(self.database, autocommit=True) as c:
            c.execute('CREATE SCHEMA ' + self.schema)
        self.connect = lambda: psycopg.connect(self.database, options='-csearch_path=' + self.schema)
        self.runs._ready = False

    def tearDown(self):
        self.runs._ready = False
        with self.psycopg.connect(self.database, autocommit=True) as c:
            c.execute('DROP SCHEMA ' + self.schema + ' CASCADE')

    def capture(self, session='s1', policy=None):
        from app.discovery_policy import build_policy
        return {'id': session, 'hostname': 'app.test', 'mode': 'operator',
                'policy': policy or build_policy('read_only'),
                'started_at': '2026-11-10T10:00:00+00:00', 'ended_at': '2026-11-10T10:05:00+00:00',
                'coverage': {'status': 'complete', 'failure_counts': {}}, 'permission_counts': {},
                'permission_events': [], 'budget': {}}

    def test_legacy_browser_ledger_is_copied_and_indexed(self):
        with self.connect() as c:
            c.execute(LEGACY_DDL)
            c.execute('CREATE INDEX idx_discovery_runs_ended ON discovery_runs (ended_at DESC)')
            c.execute("""INSERT INTO discovery_runs VALUES ('run-old','live_browser','app.test','operator','operator',
                '2026-11-01T10:00:00+00','2026-11-01T10:05:00+00','fp','{"a":1}','complete','{}','{}','[]','{}','old')""")
            c.commit()
        self.runs.ensure_table(self.connect)
        with self.connect() as c:
            self.assertEqual(c.execute('SELECT run_id FROM browser_discovery_runs').fetchall(), [('run-old',)])
            # The legacy table is left intact, and the new table gets its own ended_at index.
            self.assertEqual(c.execute('SELECT count(*) FROM discovery_runs').fetchone()[0], 1)
            indexed = c.execute("""SELECT count(*) FROM pg_indexes WHERE schemaname=%s
                AND tablename='browser_discovery_runs' AND indexdef LIKE '%%ended_at%%'""", (self.schema,)).fetchone()[0]
            self.assertEqual(indexed, 1)

    def test_crawler_shaped_table_is_never_reinterpreted(self):
        with self.connect() as c:
            c.execute('CREATE TABLE discovery_runs (id TEXT PRIMARY KEY, status TEXT, scope JSONB, created_at TIMESTAMPTZ)')
            c.execute("INSERT INTO discovery_runs VALUES ('crawl-1','completed','{}',now())")
            c.commit()
        self.runs.ensure_table(self.connect)
        with self.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM browser_discovery_runs').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT count(*) FROM discovery_runs').fetchone()[0], 1)

    def test_ensure_table_is_repeatable(self):
        self.runs.ensure_table(self.connect)
        self.runs._ready = False
        self.runs.ensure_table(self.connect)

    def test_policy_snapshot_is_immutable_but_results_extend(self):
        from app.discovery_policy import build_policy
        self.assertTrue(self.runs.save_run(self.connect, self.capture()))
        extended = self.capture()
        extended['ended_at'] = '2026-11-10T10:09:00+00:00'
        self.assertTrue(self.runs.save_run(self.connect, extended))
        with self.connect() as c:
            ended = c.execute("SELECT ended_at FROM browser_discovery_runs WHERE run_id='run-s1'").fetchone()[0]
            self.assertEqual((ended.hour, ended.minute), (10, 9))
        other = self.capture(policy=build_policy('operator_free'))
        with self.assertRaises(ValueError):
            self.runs.save_run(self.connect, other)
        with self.assertRaises(self.psycopg.Error):
            with self.connect() as c:
                c.execute("UPDATE browser_discovery_runs SET policy_fingerprint='tampered' WHERE run_id='run-s1'")

    def test_captures_without_policy_are_not_recorded(self):
        legacy = self.capture()
        del legacy['policy']
        self.assertFalse(self.runs.save_run(self.connect, legacy))

    def test_blueprint_revisions_are_append_only(self):
        from app import blueprint_records as records
        records.initialize(self.connect)
        first = records.append(self.connect, 'job-1', 'blueprint', 'operator', {'review_status': 'draft'})
        second = records.append(self.connect, 'job-1', 'blueprint', 'operator', {'review_status': 'accepted'}, first['id'])
        self.assertEqual(records.get(self.connect, second['id'])['parent_id'], first['id'])
        self.assertEqual([x['id'] for x in records.listing(self.connect, 'job-1')], [first['id'], second['id']])
        self.assertIsNone(records.get(self.connect, 'missing'))
        for statement in ("UPDATE waf_blueprint_revisions SET actor='x'", 'DELETE FROM waf_blueprint_revisions'):
            with self.assertRaises(self.psycopg.Error):
                with self.connect() as c:
                    c.execute(statement)
        self.assertEqual(len(records.listing(self.connect, 'job-1')), 2)
