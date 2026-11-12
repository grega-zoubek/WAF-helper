# Evidence and blueprint increment

Implemented in this increment:
- Data-driven numeric readiness thresholds and separate promotion-review gates.
- Explicitly unknown exact-build capability registry entries; no invented verification.
- Authenticated policy/capability/readiness APIs under the existing control middleware.
- Additive append-only PostgreSQL blueprint revision storage with review ancestry.
- Blueprint generation using the existing positive-model builder, signature selection gate, and M4 recommendations.
- Frontend creation, review and JSON export in the current single-file interface.

Legacy evidence is not assigned invented independent-session counts or role coverage. Review acceptance never grants deployment authority. The registry contains no runtime-verified entries yet.

The live ADC identity attempt returned credentials_not_configured. No ADC mutations were attempted.

Still required from the full plan: immutable run permission snapshots, cross-service evidence provenance and checkpoints, complete source imports, role/run diffs, offline CVE bundles, pre-call AI redaction and Ollama analysis, deterministic AI replay, runtime-enforced agent/action permissions, authorization records and kill switch, feedback ingestion/correlation, full readiness integration per-field, and regression scoreboard. This increment is a foundation, not completion of those phases.


## Crawler evidence ledger increment

The crawler now stores fixed read-only permission snapshots, lifecycle events, privacy-aware GET checkpoints and stable evidence/observation references. Resume is permitted only for interrupted/cancelled/failed runs with a matching original snapshot. Query-bearing and fragment URLs are withheld from replay. Prior evidence is retained rather than replaced by runtime inspection. Coverage reports identify failed requests, asset redirects/MIME mismatches, truncation and unreached routes; blueprints include those reports.

The existing browser discovery ledger has been moved to browser_discovery_runs to avoid its incompatible schema colliding with the crawler's discovery_runs table. Existing browser-shaped discovery_runs rows are copied only when the schema matches; crawler rows are never reinterpreted. Original source tables remain intact.

Authenticated API additions:
- GET /api/discovery/jobs/{job_id}/evidence-report
- POST /api/discovery/jobs/{job_id}/resume

The frontend exposes Run evidence & coverage and Resume safe discovery in the blueprint workbench. Browser coverage now counts successful document responses, not redirects, and degraded loads are not labeled fully explored.

Still pending: versioned declared/observed/inferred/reviewed model evolution across every collector, stable evidence integration into all legacy field references, source imports/diffs, AI analysis, probe authorization and agent execution, and feedback ingestion. Independent session/role counts remain unknown for legacy evidence. Full cross-service distributed resumability is not claimed.


## Local AI evidence review increment

Implemented: an evidence-only analysis pass against a local Ollama model (`WAF_AI_BASE_URL`, `WAF_AI_MODEL`; see the README). The control API builds a whitelisted structural packet (technologies, route paths, form and field shapes, cookie names, external dependency hosts, check candidates, coverage), sends it to the local model, and persists the request, result or failure as append-only blueprint records (`ai_requested`, `ai_result`, `ai_failed`). Results are schema-validated, must cite fact references that exist in the packet, and are re-validated every time they are read. Technology assertions the packet does not support are discarded and the discard is recorded as a limitation. Output is labeled `inferred`; it cannot change observations, signature selection, permissions or deployment approval. The frontend exposes this as "AI evidence review".

Not done: automatic recovery of AI analysis tasks interrupted by a control-API restart (they stay "requested" with no result), deterministic replay of a stored result against a pinned model, and any hosted-provider path (deliberately absent).

The "AI analysis" item in the pending list of the crawler section above is therefore only partly outstanding: replay and recovery remain.

## Verification

Unit tests run one file per process (every service names its package `app`), exactly as CI does. Two files need a disposable PostgreSQL and skip themselves otherwise:

- `tests/test_worker_ledger_integration.py` — crawler policy snapshot, lifecycle events, checkpoints, coverage report, restart reconciliation and resume.
- `tests/test_control_api_records_integration.py` — the `browser_discovery_runs` migration (legacy copy, crawler-shaped table left alone, index created, policy immutability) and append-only blueprint revisions.

```bash
docker run -d --rm --name waf-itest -e POSTGRES_DB=waf -e POSTGRES_USER=waf -e POSTGRES_PASSWORD=itest -p 127.0.0.1:55432:5432 postgres:16-alpine
WAF_LEDGER_DATABASE_TEST=1 DATABASE_URL=postgresql://waf:itest@127.0.0.1:55432/waf \
  python -m unittest discover -s tests -p test_control_api_records_integration.py
WAF_LEDGER_DATABASE_TEST=1 DATABASE_URL=postgresql://waf:itest@127.0.0.1:55432/waf \
  python -m unittest discover -s tests -p test_worker_ledger_integration.py
docker stop waf-itest
```

Both tests create and drop their own schema. Never point `DATABASE_URL` at the live deployment database. CI does not run them yet because it has no PostgreSQL service.
