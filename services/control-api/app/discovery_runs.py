"""Durable discovery runs: one row per browsing run with its immutable permission snapshot and
coverage report. Metadata only. Kept in its own module so main.py needs just a few hook lines."""

from __future__ import annotations

import threading
from typing import Any, Callable

from fastapi import APIRouter, HTTPException
from psycopg.types.json import Jsonb

from app.discovery_policy import PRESETS, build_policy, describe_catalog, policy_fingerprint

_ready = False
_lock = threading.Lock()
RUN_COLUMNS = (
    "run_id", "kind", "hostname", "mode", "actor", "started_at", "ended_at", "policy_fingerprint", "policy_snapshot",
    "coverage_status", "coverage", "permission_counts", "permission_events", "budget", "source_ref",
)


def ensure_table(db_connect: Callable[[], Any]) -> None:
    global _ready
    if _ready:
        return
    with _lock:
        if _ready:
            return
        with db_connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS browser_discovery_runs (
                    run_id TEXT PRIMARY KEY, kind TEXT NOT NULL, hostname TEXT NOT NULL, mode TEXT NOT NULL,
                    actor TEXT NOT NULL, started_at TIMESTAMPTZ NOT NULL, ended_at TIMESTAMPTZ NOT NULL,
                    policy_fingerprint TEXT NOT NULL, policy_snapshot JSONB NOT NULL, coverage_status TEXT NOT NULL,
                    coverage JSONB NOT NULL, permission_counts JSONB NOT NULL, permission_events JSONB NOT NULL,
                    budget JSONB NOT NULL, source_ref TEXT NOT NULL)"""
            )
            # A distinct index name: a legacy discovery_runs table may already own idx_discovery_runs_ended.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_browser_discovery_runs_ended ON browser_discovery_runs (ended_at DESC)")
            columns = {r[0] for r in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='discovery_runs'").fetchall()}
            if set(RUN_COLUMNS) <= columns:
                # Copy only a legacy browser-shaped table, by column name rather than position. The crawler's
                # discovery_runs table has a different shape and is never reinterpreted.
                names = ", ".join(RUN_COLUMNS)
                conn.execute(f"INSERT INTO browser_discovery_runs ({names}) SELECT {names} FROM discovery_runs ON CONFLICT (run_id) DO NOTHING")
            conn.execute("""CREATE OR REPLACE FUNCTION browser_run_policy_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.policy_snapshot IS DISTINCT FROM OLD.policy_snapshot OR NEW.policy_fingerprint IS DISTINCT FROM OLD.policy_fingerprint
                    THEN RAISE EXCEPTION 'browser run policy is immutable'; END IF; RETURN NEW; END; $$""")
            conn.execute("DROP TRIGGER IF EXISTS browser_run_policy_guard ON browser_discovery_runs")
            conn.execute("""CREATE TRIGGER browser_run_policy_guard BEFORE UPDATE ON browser_discovery_runs
                FOR EACH ROW EXECUTE FUNCTION browser_run_policy_immutable()""")
            conn.commit()
        _ready = True


def run_from_capture(capture: dict[str, Any]) -> dict[str, Any] | None:
    """Build the run record from a live capture. Returns None for captures that predate policies."""
    policy = capture.get("policy")
    if not isinstance(policy, dict):
        return None
    coverage = capture.get("coverage") or {}
    return {
        "run_id": f"run-{capture['id']}", "kind": "live_browser", "hostname": str(capture.get("hostname", ""))[:253],
        "mode": str(capture.get("mode", ""))[:16], "actor": str(policy.get("actor", "operator")),
        "started_at": capture.get("started_at"), "ended_at": capture.get("ended_at"),
        # The fingerprint is recomputed here so a tampered capture cannot claim a different policy.
        "policy_fingerprint": policy_fingerprint(policy), "policy_snapshot": policy,
        "coverage_status": str(coverage.get("status", "unknown")), "coverage": coverage,
        "permission_counts": capture.get("permission_counts", {}), "permission_events": capture.get("permission_events", [])[:200],
        "budget": capture.get("budget", {}), "source_ref": str(capture["id"]),
    }


def save_run(db_connect: Callable[[], Any], capture: dict[str, Any]) -> bool:
    record = run_from_capture(capture)
    if record is None:
        return False
    ensure_table(db_connect)
    with db_connect() as conn:
        original=conn.execute("SELECT policy_fingerprint FROM browser_discovery_runs WHERE run_id=%s",(record['run_id'],)).fetchone()
        if original and original[0]!=record['policy_fingerprint']:
            raise ValueError("Existing browser permission snapshot does not match this capture")
        # A run's policy snapshot is immutable: a re-save may only extend the end time and results.
        conn.execute(
            """INSERT INTO browser_discovery_runs (run_id, kind, hostname, mode, actor, started_at, ended_at, policy_fingerprint, policy_snapshot,
                   coverage_status, coverage, permission_counts, permission_events, budget, source_ref)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (run_id) DO UPDATE SET ended_at = EXCLUDED.ended_at, coverage_status = EXCLUDED.coverage_status,
                   coverage = EXCLUDED.coverage, permission_counts = EXCLUDED.permission_counts,
                   permission_events = EXCLUDED.permission_events, budget = EXCLUDED.budget""",
            (record["run_id"], record["kind"], record["hostname"], record["mode"], record["actor"], record["started_at"], record["ended_at"],
             record["policy_fingerprint"], Jsonb(record["policy_snapshot"]), record["coverage_status"], Jsonb(record["coverage"]),
             Jsonb(record["permission_counts"]), Jsonb(record["permission_events"]), Jsonb(record["budget"]), record["source_ref"]),
        )
        conn.commit()
    return True


def build_router(db_connect: Callable[[], Any]) -> APIRouter:
    router = APIRouter(prefix="/api/discovery")

    @router.get("/policy/catalog")
    def catalog() -> dict[str, Any]:
        return {
            "categories": describe_catalog(),
            "presets": {name: build_policy(name) for name in PRESETS},
            "note": "State-changing and probe categories are off unless a preset or administrator enables them. A policy can only narrow the session mode.",
        }

    @router.post("/policy/preview")
    def preview(body: dict[str, Any]) -> dict[str, Any]:
        try:
            policy = build_policy(body.get("preset"), body.get("overrides"))
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"policy": policy, "fingerprint": policy_fingerprint(policy)}

    @router.get("/runs")
    def list_runs() -> list[dict[str, Any]]:
        ensure_table(db_connect)
        with db_connect() as conn:
            rows = conn.execute(
                "SELECT run_id, kind, hostname, mode, actor, started_at, ended_at, policy_fingerprint, coverage_status, coverage->'failure_counts' FROM browser_discovery_runs ORDER BY ended_at DESC LIMIT 100"
            ).fetchall()
        return [
            {"run_id": r[0], "kind": r[1], "hostname": r[2], "mode": r[3], "actor": r[4], "started_at": r[5].isoformat(), "ended_at": r[6].isoformat(),
             "policy_fingerprint": r[7], "coverage_status": r[8], "failure_counts": r[9] or {}}
            for r in rows
        ]

    @router.get("/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        ensure_table(db_connect)
        with db_connect() as conn:
            row = conn.execute(
                "SELECT run_id, kind, hostname, mode, actor, started_at, ended_at, policy_fingerprint, policy_snapshot, coverage, permission_counts, permission_events, budget, source_ref FROM browser_discovery_runs WHERE run_id = %s",
                (run_id[:80],),
            ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Run not found")
        keys = ["run_id", "kind", "hostname", "mode", "actor", "started_at", "ended_at", "policy_fingerprint", "policy_snapshot", "coverage", "permission_counts", "permission_events", "budget", "source_ref"]
        out = dict(zip(keys, row))
        out["started_at"], out["ended_at"] = out["started_at"].isoformat(), out["ended_at"].isoformat()
        return out

    return router
