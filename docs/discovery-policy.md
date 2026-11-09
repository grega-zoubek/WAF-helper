# Discovery policy, runs and coverage

Every live browsing run carries an **immutable permission snapshot** and produces a **coverage report**.

## Action catalog
Eleven individually selectable categories (`GET /api/discovery/policy/catalog`): navigation/read, search/filter,
auth/session, form submit, registration, file transfer, record write, checkout, external effect,
boundary test, security probe. State-changing and probe categories are off unless a preset or an administrator enables them.

Presets: `read_only`, `automated_default` (both read + search), `operator_free` (a person is driving; every request-detectable
category on, probes off, ambiguous requests allowed).

Start a session with `policy_preset` and optional `policy_overrides` (`enabled`, `route_scopes`, `budgets`, `ambiguous`).
`POST /api/discovery/policy/preview` validates and fingerprints a policy without starting anything.

## Enforcement
* Every outgoing request is classified deterministically (method, path tokens, content type, body *shape*) and judged by the policy,
  including requests fired by page scripts. Page content and model output never take part in the decision.
* A policy only narrows the session mode and the target guard; it never widens them.
* Requests that cannot be classified are **paused** (blocked and listed for the operator) for automated runs. Automated runs cannot be
  configured to allow ambiguity.
* Budgets (`max_requests`, `max_actions`, `max_seconds`) are enforced; exhaustion is reported as a coverage failure.
* `boundary_test` and `security_probe` are tool-declared: no traffic is ever classified into them, so they are not enabled by any preset.

## Runs and coverage
`GET /api/discovery/runs` and `/runs/{id}` return the stored run: policy snapshot and fingerprint, permission decisions
(path only, never query values), budget, and coverage.

Coverage status is `complete`, `degraded` or `failed`. A run with a load error or no successful page load is `failed` and
`explored: false`. Failure kinds: `load_error`, `no_document`, `asset_redirect` (e.g. an ADC answering JS/CSS with 302),
`mime_mismatch`, `failed_asset`, `application_error`, `blocked_request`, `permission_denied`, `needs_classification`, `budget_exhausted`.

## Not done yet
Per-action permission checks for an AI agent, SSE progress, run pause/resume/cancel, and attaching a run to automatic (crawler) discovery.
