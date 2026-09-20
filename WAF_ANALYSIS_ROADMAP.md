# WAF Analysis Roadmap

Purpose: build a generic WAF scanner that analyses any web application, inventories
the provider's Web App Firewall catalog, derives evidence-backed generic protection
intents, and creates an applicable-signature proposal. Product fingerprints are
optional enrichment; Juice Shop is a lab target, not the scanner's design boundary.
This roadmap deliberately stops before any ADC change. Other WAF security checks are
a separate later workstream.

## Safety boundaries

- Discovery is passive and bounded: ordinary `GET` requests only, no attack
  payloads, form submissions, authentication attempts, or state changes.
- NetScaler inventory and target-path resolution are read-only.
- A proposal is not an implementation. No signature object, binding, profile,
  action, or policy is changed without explicit approval and preflight.
- Credentials remain in protected server-side runtime configuration and are
  never copied into this file, Git, the GUI, or chat.

## Generic scanner architecture

- Discovery layer: bounded passive HTTP observations and technology/surface evidence.
- Policy layer: versioned provider-neutral protection intents derived from evidence.
- Provider layer: resolves intents against the installed NetScaler catalog and exact
  rule IDs; it must fail closed when rule-level catalog data is unavailable.
- Decision layer: predefined rules are authoritative; AI is optional advisory input
  only and cannot invent, broaden, or apply rules.
- Change layer: proposal, approval, drift check, preflight, guarded apply, verification,
  audit, and rollback. Default mode remains proposal-only.

The generic policy layer is implemented in
`services/analysis-service/app/generic_protection.py` and covered by tests. It does
not yet replace the provider catalog resolver or enable automatic ADC writes.

## Workflow

### 1. Discover the web application

For each target:

1. Record the exact seed URL, allowed paths, page limit, rate limit, and UTC start time.
2. Run the passive discovery job.
3. Save the job ID, status, detector version, technology profile, route inventory,
   form/field surfaces, headers, cookies, and evidence references.
4. Review product identification and false positives. Treat a generic platform
   label as unresolved until generator metadata, assets, headers, or another
   independent signal supports a named product.
5. Record authenticated and unauthenticated coverage separately.

Current completed discovery:

- Target: `https://trgdela.si/`
- Job: `9ee7ec26-9c8d-4932-96de-fad33943e2c0`
- Result: 10 pages, 122 evidence records, 33 routes, 118 fields
- Detected: TYPO3 exposed as `Generated platform`, Bootstrap, reverse proxy/cache,
  HTML forms, and a review-needed authentication signal
- No ADC changes made

Current test target discovery:

- Target: `http://192.168.11.91/` (Juice Shop test application)
- Job: `6a06abe1-2986-4e87-9d6d-7cffc6cd699d`
- Result: 10 pages, 82 evidence records, 61 routes, Angular detected
- Application analysis: JavaScript client/server-rendered frontend; proposed
  logical groups are `web-baseline` and `spa-client`
- No authenticated testing, form submission, attack payload, or WAF change

### 2. Inventory the live NetScaler signature catalog

Read-only checks only:

1. Resolve the target hostname through the configured content-switch/LB path.
2. Identify the AppFW profile and currently bound signature object.
3. Enumerate available signature objects and catalog versions/update state.
4. Enumerate categories, rule IDs, descriptions, references, enabled state,
   and current actions for the candidate signature object.
5. Capture the current profile/signature binding as the rollback baseline.
6. Record missing capabilities or catalog limitations instead of guessing names.

The inventory output must be a redacted snapshot with a timestamp and a stable
fingerprint. It must not contain passwords, session headers, or raw sensitive
ADC responses.

Current completed inventory:

- ADC target: `192.168.11.101`
- ADC version: `NetScaler NS14.1 Build 73.33.nc` (17 Aug 2026)
- Signature catalogs: `*Default Signatures` (`default_signatures.xml`, base
  version `175`) and `*Xpath Injection Patterns`
- AppFW profiles: 10 enumerated; all were `DISABLED` and had no signature binding
- AppFW policies: 0 returned
- Content-switch policies: 2 returned; neither references `trgdela.si`
- LB vServers: 10 returned
- Inventory timestamp: `2026-09-20T18:52:54Z`
- Inventory fingerprint: `e81cc2c1abd26079bea33e6bd5af1ba2f7ac14a2dc512bf7c2e02c02de2c51fd`
- Limitation: the current read-only adapter exposes signature catalog objects,
  metadata, and rule-selection fields, but not the individual rules inside
  `default_signatures.xml`. Rule-level applicability requires a safe read-only
  method to inspect that catalog or a vendor-supported export.

Juice Shop path resolution:

- LB vServer: `lb_vs_juice_shop` at `192.168.11.91:80`, HTTP, state `UP`
- Backend service: `lb_svc_juice_shop_3000` -> `web-mcp:3000`
- Content-switch policy for this IP/target: none required; the LB is direct
- AppFW policy: none returned
- AppFW signature binding: none on the candidate disabled profile or LB path
- Candidate profile: `ns-web-default-appfw-profile`, disabled, no signature binding
- Conclusion: the test website is reachable through the ADC, but is not currently
  protected by an active AppFW policy/signature binding.

### 3. Map evidence to applicable signatures

Create an explicit decision for every candidate category or rule:

- `include`: supported by observed application/runtime/request evidence;
- `conditional`: plausible but requires runtime or traffic confirmation;
- `exclude`: no evidence, wrong technology, duplicate coverage, or excessive
  false-positive risk;
- `unresolved`: the ADC catalog or target path did not provide enough information.

For `trgdela.si`, the initial mapping should consider:

- generic web attack signatures and the current Default Signatures object;
- SQL injection and XSS coverage for observed form and data fields;
- buffer-overflow baseline coverage;
- PHP-related signatures only after the runtime is confirmed;
- form-field, start-URL, and related positive-security checks only in the
  later security-check workstream.

Do not select Exchange OWA, WordPress, IIS, Apache Struts, XML/XPath, file-upload,
or other technology-specific groups without supporting evidence.

### 4. Build the signature proposal

The proposal must contain:

- target hostname and resolved application path;
- discovery job ID and detector version;
- ADC host, AppFW profile, signature object, and catalog fingerprint;
- exact included category/rule IDs;
- rationale and evidence reference for each inclusion;
- excluded and conditional rules with reasons;
- proposed initial action (`LOG`, `LEARN`, or `BLOCK`), with `LOG`/`LEARN`
  preferred for the first stage;
- expected false-positive areas;
- validation traffic plan;
- current-state snapshot, plan fingerprint, expiry, approval state, and rollback plan.

The proposal remains editable and proposal-only until explicitly approved.

### 5. Review and preflight

Before implementation:

1. Present the proposal diff for review.
2. Confirm the target path and current signature binding have not drifted.
3. Confirm every selected rule exists in the live catalog.
4. Confirm the proposal does not include unrelated security checks.
5. Confirm write mode is disabled.
6. Require the exact approval phrase used by the platform.

No apply operation is part of the current objective.

### 6. Later implementation and separate security-check workstream

Only after approval and preflight should a later action create or modify a
signature object, bind it, verify it, audit it, and retain rollback data. After
the signature proposal is settled, analyse positive-security checks separately:
start URL, cookie consistency, form-field consistency, field formats, CSRF,
file upload, XML/JSON, and response/header checks.

## Recovery and checkpoint protocol

At the end of every action, update this file's checkpoint section with:

- action completed and UTC timestamp;
- local commit/revision and server revision, if applicable;
- job IDs, snapshot filenames, proposal IDs, or fingerprints;
- exact next action;
- whether the action was read-only or changed state;
- any blocker or unresolved assumption;
- the exact re-entry command or API route needed to resume safely.

If connectivity is lost or a machine reboots:

1. Read this file before doing anything else.
2. Do not repeat discovery or apply changes until the latest checkpoint is verified.
3. Verify local Git status and the server checkout revision.
4. Verify SSH connectivity and Docker Compose service health.
5. Query existing job/proposal IDs before creating duplicates.
6. Re-run only the last incomplete read-only action.
7. Re-check the current ADC state and plan fingerprint before any future approval.

## Current checkpoint

- Timestamp: 2026-09-20
- Last action: passive Juice Shop discovery plus read-only ADC path resolution
- State: complete; no ADC mutation
- Result: Juice Shop maps directly to `lb_vs_juice_shop` -> `web-mcp:3000`, but no active AppFW policy or signature binding exists
- Next action: deploy and verify the generic policy layer, then design the provider rule-catalog resolver for Juice Shop evidence
- Resume instruction: verify server/API health, confirm job `6a06abe1-2986-4e87-9d6d-7cffc6cd699d` and inventory fingerprint `e81cc2c1abd26079bea33e6bd5af1ba2f7ac14a2dc512bf7c2e02c02de2c51fd`; do not enable the disabled profile or create an AppFW binding.
