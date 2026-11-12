"""Additive, append-only model and blueprint revisions on the existing control database."""
from datetime import datetime,timezone
from uuid import uuid4
from psycopg.types.json import Jsonb

DDL = '''CREATE TABLE IF NOT EXISTS waf_blueprint_revisions (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL, kind TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL, actor TEXT NOT NULL, parent_id TEXT,
 payload JSONB NOT NULL)'''


def initialize(connect):
    with connect() as c:
        c.execute(DDL)
        c.execute('CREATE INDEX IF NOT EXISTS waf_blueprint_job_idx ON waf_blueprint_revisions(job_id, created_at)')
        c.execute('''CREATE OR REPLACE FUNCTION waf_blueprint_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'blueprint revisions are immutable'; END; $$''')
        c.execute('DROP TRIGGER IF EXISTS immutable_blueprint ON waf_blueprint_revisions')
        c.execute('''CREATE TRIGGER immutable_blueprint BEFORE UPDATE OR DELETE ON waf_blueprint_revisions
        FOR EACH ROW EXECUTE FUNCTION waf_blueprint_immutable()''')


def append(connect,job_id,kind,actor,payload,parent_id=None):
    record={'id':str(uuid4()),'job_id':job_id,'kind':kind,'created_at':datetime.now(timezone.utc).isoformat(),
            'actor':actor,'parent_id':parent_id,'payload':payload}
    with connect() as c:
        c.execute('INSERT INTO waf_blueprint_revisions VALUES (%s,%s,%s,%s,%s,%s,%s)',
                  (record['id'],job_id,kind,record['created_at'],actor,parent_id,Jsonb(payload)))
    return record


def get(connect,identifier):
    with connect() as c:
        row=c.execute('SELECT id,job_id,kind,created_at,actor,parent_id,payload FROM waf_blueprint_revisions WHERE id=%s',(identifier,)).fetchone()
    if not row:return None
    record=dict(zip(['id','job_id','kind','created_at','actor','parent_id','payload'],row));record['created_at']=record['created_at'].isoformat();return record


def listing(connect,job_id):
    with connect() as c:
        rows=c.execute('SELECT id,kind,created_at,actor,parent_id FROM waf_blueprint_revisions WHERE job_id=%s ORDER BY created_at,id',(job_id,)).fetchall()
    return [dict(id=r[0],kind=r[1],created_at=r[2].isoformat(),actor=r[3],parent_id=r[4]) for r in rows]
