"""Additive metadata-only run policy, lifecycle and safe-GET checkpoint ledger."""
import hashlib
import json
from urllib.parse import urlparse,urlunparse
from psycopg.types.json import Jsonb


def safe_target(url):
    p=urlparse(url)
    return urlunparse((p.scheme,p.netloc.split('@')[-1],p.path or '/','','',''))


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def policy(scope):
    p=urlparse(scope['seed_url'])
    return {'schema_version':'1.0.0','origin':f'{p.scheme}://{p.netloc}',
        'allowed_paths':scope['allowed_paths'],'max_pages':scope['max_pages'],
        'rate_limit_per_second':scope['rate_limit_per_second'],
        'actions':['navigation_read','asset_inspection','passive_exposure_checks'],
        'state_changing_actions':False,'role':'anonymous','evidence_class':'benign_discovery'}


def initialize(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS discovery_run_policies (
        run_id TEXT PRIMARY KEY REFERENCES discovery_runs(id) ON DELETE CASCADE,
        snapshot JSONB NOT NULL, fingerprint TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
    connection.execute('''CREATE TABLE IF NOT EXISTS discovery_run_events (
        id BIGSERIAL PRIMARY KEY,run_id TEXT NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
        status TEXT NOT NULL,metadata JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
    connection.execute('''CREATE TABLE IF NOT EXISTS discovery_checkpoints (
        run_id TEXT PRIMARY KEY REFERENCES discovery_runs(id) ON DELETE CASCADE,
        payload JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT now())''')
    connection.execute('''CREATE OR REPLACE FUNCTION discovery_policy_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'run permission snapshots are immutable'; END; $$''')
    connection.execute('DROP TRIGGER IF EXISTS discovery_policy_no_update ON discovery_run_policies')
    connection.execute('''CREATE TRIGGER discovery_policy_no_update BEFORE UPDATE ON discovery_run_policies
        FOR EACH ROW EXECUTE FUNCTION discovery_policy_immutable()''')


def event(connection,run_id,status,**metadata):
    safe={k:v for k,v in metadata.items() if k in {'phase','pages_visited','assets_fetched','evidence_count','error'}}
    connection.execute('INSERT INTO discovery_run_events(run_id,status,metadata) VALUES (%s,%s,%s)',(run_id,status,Jsonb(safe)))


def save_policy(connection,run_id,scope):
    value=policy(scope);key=fingerprint(value)
    existing=connection.execute('SELECT fingerprint FROM discovery_run_policies WHERE run_id=%s',(run_id,)).fetchone()
    if existing and existing[0]!=key:raise ValueError('Run permissions cannot change')
    connection.execute('INSERT INTO discovery_run_policies(run_id,snapshot,fingerprint) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',(run_id,Jsonb(value),key))


def checkpoint_payload(queue,visited,pages,assets):
    safe=[];withheld=0
    for url in queue:
        p=urlparse(url)
        if p.query or p.fragment or p.username or p.password:
            withheld+=1;continue
        safe.append(safe_target(url))
    return {'schema_version':'1.0.0','pending_get_urls':list(dict.fromkeys(safe)),
            'visited':list(dict.fromkeys(safe_target(x) for x in visited)),
            'pages_visited':pages,'assets_fetched':assets,'withheld_urls':withheld,
            'replays_submissions':False}


def save_checkpoint(connect,run_id,payload):
    with connect() as c:
        c.execute('''INSERT INTO discovery_checkpoints(run_id,payload) VALUES (%s,%s)
            ON CONFLICT(run_id) DO UPDATE SET payload=EXCLUDED.payload,updated_at=now()''',(run_id,Jsonb(payload)))


def report(connect,run_id):
    with connect() as c:
        snapshot=c.execute('SELECT snapshot,fingerprint FROM discovery_run_policies WHERE run_id=%s',(run_id,)).fetchone()
        events=c.execute('SELECT id,status,metadata,created_at FROM discovery_run_events WHERE run_id=%s ORDER BY id',(run_id,)).fetchall()
        checkpoint=c.execute('SELECT payload FROM discovery_checkpoints WHERE run_id=%s',(run_id,)).fetchone()
        observations=c.execute('SELECT id,source_url,status_code,observation FROM discovery_observations WHERE run_id=%s',(run_id,)).fetchall()
        run=c.execute('SELECT status FROM discovery_runs WHERE id=%s',(run_id,)).fetchone()
        discovered=c.execute("SELECT source_url FROM discovery_evidence WHERE run_id=%s AND evidence_type IN ('route_discovered','route_candidate')",(run_id,)).fetchall()
    failures=[];visited=set();success=0
    for oid,url,status,observation in observations:
        visited.add(safe_target(url))
        ref=f'discovery:{run_id}:observation:{oid}'
        asset=observation.get('asset') or {}
        headers=(observation.get('response') or {}).get('headers') or {}
        kind='fetch_failed' if status is None else 'http_error' if status>=400 else 'asset_redirect' if asset and 300<=status<400 else 'mime_mismatch' if asset and str(headers.get('content-type','')).startswith('text/html') else 'truncated' if asset.get('truncated') else None
        if kind:failures.append({'kind':kind,'target':safe_target(url),'evidence_ref':ref})
        elif not asset and 200<=status<300:success+=1
    pending=sorted({safe_target(x[0]) for x in discovered}-visited)
    if pending:failures.append({'kind':'unreached_routes','count':len(pending)})
    status='failed' if not success else 'partial' if failures or not run or run[0]!='completed' else 'complete'
    return {'run_id':run_id,'policy':snapshot[0] if snapshot else None,
        'policy_fingerprint':snapshot[1] if snapshot else None,'legacy_policy_unknown':snapshot is None,
        'events':[dict(id=r[0],status=r[1],metadata=r[2],at=r[3].isoformat()) for r in events],
        'checkpoint':checkpoint[0] if checkpoint else None,
        'coverage':{'status':status,'explored':status=='complete','successful_pages':success,
                    'failures':failures,'unreached_routes':pending,'role_coverage':['anonymous'] if snapshot else []}}
