# Positive Security Model Contract v1

Status: schema plus metadata-only dry-run validator and guided-browser MVP. The
workbench does not persist positive models, enforce requests, or write
configuration to NetScaler.

The canonical typed contract is implemented in
`services/control-api/app/positive_model.py`. `PositiveModelDocument` rejects
unknown fields and exports JSON Schema through `positive_model_json_schema()`.
Breaking changes require a new `schema_version`; older versions must remain
readable through an explicit migration rather than being silently reinterpreted.

## Model contents

- Application identity, hostname, environment, revision, and lifecycle.
- Endpoint path template, method, request/response media types, and
  authentication state.
- Field identity and location (path, query, form, JSON, XML, header, or cookie),
  sensitivity classification, aggregate shape, and proposed constraints.
- Opaque evidence references, source, observation time, sample counts, and
  confidence metadata.
- Endpoint lifecycle and decision mode. New entries default to `discovered` /
  `observe`; `block` is rejected until an endpoint is staged or enforced.

The contract models aggregate facts (counts, length ranges, observed types, and
character classes), not request/response samples. `FieldConstraints` are
candidate or administrator-authored policy intent. They are not evidence that a
constraint is safe to enforce.

## Privacy requirements

1. Never persist raw request/response bodies or observed field values in the
   positive-model record. The schema intentionally has no sample-value property
   and rejects undeclared properties.
2. Redact credentials, authorization values, session cookies, CSRF tokens, API
   keys, and classified personal data before persistence, logs, exports, or any
   future AI-assisted explanation. Names and structural metadata may be kept;
   values may not.
3. Store query parameter names, not query values. Store normalized path
   templates, not concrete identifiers or secrets embedded in path segments.
4. Store only allowlisted header metadata and cookie names/attributes; never
   their values. Treat unknown fields as sensitive until classified.
5. Keep browser credentials and authenticated browser state ephemeral. Persisting
   browser storage or session state requires a separate explicit authorization,
   encryption, expiry, and access-control design.
6. Keep evidence references opaque. Do not place raw payloads, free-form copied
   application text, or secrets in evidence identifiers.
7. The Pydantic contract is a validation boundary, not a redaction engine. Any
   future ingestion path must redact before constructing or persisting a model;
   validation failures must fail closed and must not log the rejected payload.

## Confidence and lifecycle

Confidence records sample count, independent-session count, source count, and
time bounds without retaining client identifiers. Sources distinguish passive
crawling, headless and guided browser sessions, OpenAPI, HAR, access logs,
NetScaler learning, and manual input. Confidence must not be derived from sample
count alone; later learning work must combine source trust, diversity, coverage,
freshness, and reviewer decisions.

The declared lifecycle is `discovered → candidate → reviewed → staged →
enforced → retired`, with explicit transitions and audit to be added in later
phases. GPT is not represented as an evidence authority or runtime decision
source.

## Phase boundary

The deterministic dry-run endpoint is `POST /api/positive-model/validate`.
It compares a typed model to a metadata-only transaction descriptor in memory:
route and method, media type, authentication context, field presence, declared
type, and observed length. Unknown routes/methods and constraint mismatches are
findings; unknown request properties are rejected without echoing their values.
Format and numeric-content constraints are explicitly marked not evaluated
because the validator never receives raw values. The schema is also available
from `GET /api/positive-model/schema`.

The Guided Browser Lab uses isolated Playwright contexts, an in-memory
15-minute session, a same-host/path scope, context-wide GET/HEAD-only network
routing, WebSocket/download blocking, and metadata-only capture. The GUI shows a
temporary screenshot with coordinate-based selection and a visual highlight.
Explicit focus and non-submit click observations, plus a fixed benign synthetic
probe for empty, non-sensitive text inputs, can produce DOM-to-request
correlation evidence. Form submit events and native form submission APIs are
blocked. Query/fragment values are redacted; request header names and safe
response metadata are recorded without header values; cookie names and
attributes are exposed without cookie values. Raw request/response bodies and
field values are never returned or persisted. Candidate generation produces a
schema-validated, low-confidence `discovered`/`observe` PositiveModelDocument in
memory only; it does not persist or enforce the candidate.

Credential entry and authenticated journeys remain disabled because the current
GUI/control API uses HTTP and has no operator authentication. Do not enter
credentials into the Browser Lab until TLS and operator access control are in
place. Synthetic inputs and explicit clicks can trigger application-side GET
behavior, so use them only on an approved test scope.

No policy compiler, request enforcement, profile synthesis, or ADC writes were
added. Later phases must map only to controls supported by the detected
NetScaler version; unsupported observations remain analytics-only.
