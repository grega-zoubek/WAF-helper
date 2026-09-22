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
15-minute session, a same-host/path scope, GET/HEAD-only network routing,
download blocking, redacted query values, and metadata-only request capture.
The GUI shows a temporary page screenshot and a selectable DOM control list.
Selection reads field metadata only; it does not click or submit a control. No
browser state or capture is persisted. The current MVP does not yet support
authenticated user journeys or arbitrary pointer interaction. It reports only
a low-confidence name/id-to-query-key heuristic when a selected DOM control
matches an already observed safe GET; event/time/body-based DOM-to-request
correlation, candidate-model generation, and model persistence are not
implemented.

No policy compiler, request enforcement, profile synthesis, or ADC writes were
added. Later phases must map only to controls supported by the detected
NetScaler version; unsupported observations remain analytics-only.
