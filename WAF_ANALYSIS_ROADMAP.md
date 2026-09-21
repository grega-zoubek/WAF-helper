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

## Current signature-only phase

The first five generic recommendations are now explicit and resolve against the local
normalized catalog:

1. HTTP protocol compliance
2. Canonicalization and evasion
3. Injection attacks
4. Cross-site scripting
5. Path and file attacks

The resolver selects exact untagged rule IDs, preserves match reasons, excludes
technology-tagged rules from generic groups, and requires upload evidence before adding
file-upload rules. Positive-model, schema, allowlist, behavioral, bot, and rate-limit
controls remain deferred. Every proposal remains LOG/BLOCK reviewable and proposal-only.

The generic policy layer is implemented in
`services/analysis-service/app/generic_protection.py` and covered by tests. It does
not yet replace the provider catalog resolver or enable automatic ADC writes.

Generic policy layer verification:

- Commit: `0a9c7b4`
- Tests: 10 passing
- Deployed to the analysis service on the lab server
- Juice Shop output: generic web attack signatures included; XSS signatures included;
  runtime-specific and technology-specific signatures conditional
- Automation state: proposal-only; predefined rules enabled; AI advisory disabled;
  automatic apply disabled

Provider catalog resolver verification:

- Commit: `e226e45`
- Read-only adapter endpoint: `/api/adc/signatures/rules`
- Input contract: administrator-mounted JSON or XML rule-level export at
  `/run/catalogs/netscaler_rule_catalog.json`
- Current live status: `configured-file-missing`, 0 normalized rules
- Juice Shop proposal: `71893d1c-83b2-4b62-a445-ae3ae6e10d35`
- Proposal status: `blocked-missing-rule-level-catalog`, 0 selected catalogs,
  no ADC changes
- Raw catalog payloads are not retained by the adapter or database

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
- Next action: provide an administrator-approved rule-level export, validate it
  against Juice Shop intents, and then implement guarded automation-mode checks
- Resume instruction: verify server/API health, query `/api/adc/signatures/rules`,
  confirm proposal `71893d1c-83b2-4b62-a445-ae3ae6e10d35`, and do not enable ADC
  writes while the catalog status is not `enumerated`.
- Resume instruction: verify server/API health, confirm job `6a06abe1-2986-4e87-9d6d-7cffc6cd699d` and inventory fingerprint `e81cc2c1abd26079bea33e6bd5af1ba2f7ac14a2dc512bf7c2e02c02de2c51fd`; do not enable the disabled profile or create an AppFW binding.

## Next-Gen API integration checkpoint

- Timestamp: 2026-09-20 UTC
- Action: replaced the ADC adapter's management calls with the supplied NetScaler Next-Gen API contract; added cookie-login client, application topology normalization, explicit unsupported-capability responses, contract documentation, and tests.
- OAS source: `C:\Users\G.Zoubek\Downloads\Nextgen-API-Spec.yaml`
- OAS SHA-256: `88006C4D59EB0C0E4344458CAA5CEB130EEFF41AF325087221536260319FDD8F`
- OAS contract: `NetScaler Next-Gen API` version `0.1.10`, base path `/mgmt/api/nextgen/v1`, login `POST /login`, cookie `sessionid`.
- Local/server checkout revision: `42f64f5`; changed service images were built from `ea306bb` and the later commit only updates this checkpoint document.
- Validation: 16 repository tests passed; changed adapter and control images built; adapter, control API, and frontend are running in Compose project `waf-intelligence`.
- Live ADC result: adapter health reached `192.168.11.101` but Next-Gen login returned HTTP 403 from Apache. Application discovery is therefore blocked with no fallback and no ADC mutation.
- AppFW result: the supplied OAS has no AppFW profile, policy, or signature operation; those endpoints return `unsupported-by-oas`, and old AppFW write routes return HTTP 501.
- State: implementation deployed; read-only ADC discovery blocked by external API exposure/access policy; write mode remains disabled.
- Next action: enable/expose the Next-Gen API on the ADC or correct its access policy, then rerun only the read-only login and `/applications` checks. After successful application discovery, connect detected web applications to the provider-neutral protection plan; keep signature catalog import administrator-supplied until the OAS exposes a signature operation.
- Recovery after connectivity loss or reboot: read this checkpoint, verify `git rev-parse --short HEAD` in `C:\Users\G.Zoubek\Projects\waf-intelligence` and `/home/grega/waf-intelligence-repo`, verify `docker compose -p waf-intelligence ps` on `192.168.11.90`, query `http://192.168.11.90:8110/healthz`, query the adapter health through `waf-intelligence-netscaler-adapter-1`, then retry `POST https://192.168.11.101/mgmt/api/nextgen/v1/login` only after confirming the 403 condition changed. Do not enable writes or create duplicate jobs.
- Cleanup: removed the unused transient `waf-intelligence-repo_postgres-data` volume created by the failed full rebuild attempt; the active `waf-intelligence` Postgres volume was not changed.
- Retest: 2026-09-20 19:47:57 UTC, direct Next-Gen `POST /login` from `192.168.11.90` returned HTTP 403 over both HTTPS and HTTP; control API `/api/adc/applications` returned HTTP 502 as designed. No credentials, cookies, or ADC state were changed.
- Resume instruction: an ADC administrator must first verify `mcp_user` API management-interface permission and any management ACL/Apache policy; after that, rerun the same read-only login test before changing scanner code or enabling writes.
- Retest success: 2026-09-20 19:49:23 UTC, direct Next-Gen login and `/applications` returned HTTP 200 over HTTPS and HTTP; adapter health reported authenticated; control API `/api/adc/applications` returned HTTP 200. Sanitized inventory contained zero applications.
- Resume instruction: treat Next-Gen connectivity/authentication as resolved. Before analyzing ADC-backed application topology, configure/import the intended application objects on the ADC or confirm that this endpoint is expected to expose classic LB objects; then rerun the read-only inventory and topology checks. Keep AppFW/signature writes disabled.
- Generic scanner checkpoint: 2026-09-20 19:51:17 UTC, existing Juice Shop job `6a06abe1-2986-4e87-9d6d-7cffc6cd699d` returned HTTP 200 for analysis and ADC-plan generation. The plan remained `proposal-only`; generic protection intents were generated, but `target_match=false`, no LB target was returned, and ADC matching was `blocked-appfw-unavailable` because the Next-Gen OAS exposes no AppFW/signature resources.
- Resume instruction: use the existing job ID for repeatable validation; do not create an ADC application or enable writes until the application-object model and target ownership are explicitly approved. The safe implementation next step is a read-only classic-to-Next-Gen correlation/reporting layer or an administrator-approved Next-Gen application object.
- Correlation implementation: added `/api/discovery/jobs/{job_id}/nextgen-correlation`, which generically correlates a scan hostname to a Next-Gen application name or virtual IP and fails closed with `matched`, `no-match`, or `empty-inventory`.
- Validation/deployment: revision `ba60f65`; 18 tests passed; control API rebuilt and restarted; Juice Shop correlation returned HTTP 200 with `status=empty-inventory`, `application_count=0`, and `automatic_apply_allowed=false`.
- Resume instruction: use `GET /api/discovery/jobs/6a06abe1-2986-4e87-9d6d-7cffc6cd699d/nextgen-correlation` after Next-Gen application objects are present. Do not infer or create ADC objects from an empty inventory.

### Inventory semantics correction checkpoint

- Timestamp: 2026-09-20 UTC
- Action: corrected WAF inventory reporting so unsupported AppFW/profile/signature operations are not presented as an empty WAF inventory; added capability-aware adapter/control inventory route and explicit UI status.
- State: deployed and verified.
- Read-only scope: the change only reads `/applications` through the supplied Next-Gen OAS. It does not call legacy APIs, mutate the ADC, enable writes, or retain credentials/raw provider payloads.
- Expected live result: applications are enumerated independently; WAF resources report `unsupported-by-oas` with `automatic_apply_allowed=false`; this is not equivalent to an empty catalog.
- Validation/deployment: revision `b3f4f58`; 18 tests passed in the control image; adapter and control API were rebuilt and restarted; frontend serves the updated inventory route.
- Live result: adapter and control `GET /api/adc/inventory` returned HTTP 200 with `applications.status=enumerated`, `applications.record_count=0`, `waf.status=unsupported-by-oas`, `waf.automatic_apply_allowed=false`, `capabilities.appfw_profiles=false`, `capabilities.appfw_policies=false`, `capabilities.signature_catalog=false`, `rule_catalog.status=configured-file-missing`, and `write_enabled=false`.
- Compatibility result: existing profile and signature-catalog routes now preserve `unsupported-by-oas` instead of implying an empty inventory.
- Next action: obtain an administrator-approved AppFW/signature inventory source compatible with the Next-Gen integration, or extend the supplied OAS through an approved provider contract. Do not treat the current zero application count or unsupported WAF status as proof that the ADC has no classic WAF configuration.
- Recovery after connectivity loss or reboot: verify local/server `git rev-parse --short HEAD`, SSH to `grega@192.168.11.90`, run `docker compose -p waf-intelligence ps`, query `http://192.168.11.90:8110/healthz`, then query `http://192.168.11.90:8110/api/adc/inventory`. Do not re-run discovery or enable writes; resume from the inventory verification step.

### Read-only ADC CLI WAF inventory checkpoint

- Timestamp: 2026-09-20 20:30:37 UTC
- Action: authenticated to `mcp_user@192.168.11.101` through the Ubuntu jump host and executed only verified read-only `show` commands over SSH. No configuration command was sent.
- Commands: `show ns feature`, `show appfw profile`, `show appfw policy`, `show appfw signatures`, `show appfw settings`, and `show appfw policylabel`.
- Result: `Application Firewall AppFw OFF`; policy and policy-label queries reported `Feature(s) not enabled [AppFw]`; ten built-in/default profiles were listed; two built-in signature objects were listed (`*Default Signatures` and `*Xpath Injection Patterns`). No custom WAF profile, active policy, or enabled AppFW enforcement was evidenced by this read-only pass.
- Settings evidence: default profile `APPFW_BYPASS`; `UndefAction=APPFW_BLOCK`; signature auto-update `OFF`; malformed-request actions `block log stats`; learning `ON`. These settings do not imply active enforcement while the AppFW feature is OFF.
- State: complete; read-only; no ADC mutation.
- Next action: add an SSH CLI inventory source to the scanner with explicit states such as `feature-disabled`, `built-in-only`, and `not-enumerated`, then correlate CLI WAF objects with the Next-Gen application inventory. Do not propose or apply WAF changes while AppFW is disabled and no target policy binding is confirmed.
- Recovery after connectivity loss or reboot: verify SSH to `grega@192.168.11.90`, verify ADC TCP/22, retry one read-only CLI inventory pass only after confirming the account still reaches the CLI prompt, and check this checkpoint before creating any scanner job or change plan.

### CLI-backed WAF inventory implementation checkpoint

- Timestamp: 2026-09-20 20:39:19 UTC
- Action: added a read-only Paramiko SSH transport and sanitized AppFW CLI parser to the NetScaler adapter; retained Next-Gen API for application topology and used CLI only for WAF inventory.
- Commits: `325342a` added CLI inventory integration; `919854d` preserved CLI signature sizes in the control parser. Server checkout is synchronized at `919854d`.
- Validation: 22 repository tests passed in the adapter image; adapter rebuilt and restarted; control API rebuilt and restarted.
- Live result: `GET /api/adc/inventory` returned HTTP 200 with `waf.status=enumerated`, provider `netscaler-cli-over-ssh`, AppFw enabled, 10 profiles, 0 policies, 2 signature catalogs, and `automatic_apply_allowed=false`. `GET /api/adc/signatures/catalog` returned HTTP 200 with signature sizes `2879756` and `2621` bytes.
- State: implementation complete; inventory read-only; no WAF configuration was changed.
- Interpretation: the WAF feature is enabled and built-in profiles/signatures are visible, but no active AppFW policy was enumerated. Built-in profiles must not be treated as protection applied to a discovered application.
- Next action: enumerate classic ADC application endpoints/bindings through read-only CLI, correlate them with discovery targets such as Juice Shop, then prepare a guarded lab-only policy/profile proposal. Keep writes behind explicit plan, preflight, drift check, confirmation, audit, and rollback.
- Recovery after connectivity loss or reboot: verify local/server revision `919854d`, `docker compose -p waf-intelligence ps` on `192.168.11.90`, query `http://192.168.11.90:8110/api/adc/inventory`, and retry the CLI-backed inventory only after confirming SSH reaches the ADC prompt. Do not create a policy or bind a profile from an empty correlation result.

### Classic ADC topology correlation checkpoint

- Timestamp: 2026-09-20 20:48 UTC
- Action: extended the read-only SSH CLI inventory with generic classic ADC topology discovery. The adapter now enumerates LB vservers, services, service groups, vserver-to-service bindings, and any vserver-level AppFW profile evidence. Added `/api/adc/classic-inventory` and `/api/discovery/jobs/{job_id}/classic-correlation`.
- Implementation: revision `0501e67`, pushed to GitHub and deployed on `192.168.11.90`. Focused parser/correlation tests passed: 8 tests. The deployment required loading the existing Postgres container password into the server-side Compose environment; the password was not printed or stored in source.
- Live ADC result: classic inventory `enumerated`; 10 vservers, 5 services, 5 service groups, and 9 bindings. `lb_vs_juice_shop` is `UP` at `192.168.11.91:80`, bound to `lb_svc_juice_shop_3000` at `192.168.11.90:3000`.
- Live discovery result: new read-only Juice Shop job `913c5f59-1fd9-4705-8028-a774a4102622` completed with 10 pages, 4 assets, and 82 evidence rows.
- Live correlation result: `status=matched`, `match_reason=exact-vserver-address`, `protection_status=feature-enabled-no-policy-binding-evidenced`, and `appfw_policy_count=0`. The result is not evidence of active WAF protection.
- Proposal result: `proposal-only`; candidate source `ns-web-default-appfw-profile`; proposed custom name `waf-scan-lb_vs_juice_shop-lab`; signature candidates `*Default Signatures` and `*Xpath Injection Patterns`; initial mode `log-first`; `automatic_apply_allowed=false`. No ADC configuration was changed.
- Interpretation: this is now generic target ownership and protection-gap evidence, not a Juice-Shop-specific rule set. The next implementation phase is to turn the proposal into an explicit, reviewable plan with a configuration fingerprint, exact CLI/API actions, preflight, confirmation, audit, and rollback. Do not apply it yet.
- Recovery after connectivity loss or reboot: verify `git rev-parse --short HEAD` locally and on `/home/grega/waf-intelligence-repo`; SSH to `grega@192.168.11.90`; run `docker compose -p waf-intelligence ps`; query `http://192.168.11.90:8110/healthz` and `/api/adc/classic-inventory`; if the scan result is needed, query job `913c5f59-1fd9-4705-8028-a774a4102622` and then `/classic-correlation`. Re-run only read-only discovery/inventory checks. Do not create, bind, enable, or delete AppFW objects until an exact change plan has been approved and preflight has passed.

### GUI synchronization verification checkpoint

- Timestamp: 2026-09-20 UTC
- Action: refreshed the running Chrome WAF Intelligence dashboard at `http://192.168.11.90:8180/`, reconnected using the existing encrypted saved connection, and pressed `Reload WAF inventory`.
- Result: GUI did not reflect the deployed inventory. It displayed `0` AppFW profiles, `0` signature catalogs, and `status: not available`, while the live API returned 10 profiles, 2 signature catalogs, `waf.status=enumerated`, and 10 classic vservers with 9 bindings.
- Root cause: the current frontend renderer still reads the legacy fields `profiles.appfwprofile`, `policies.appfwpolicy`, and `signatureCatalog`. The current `/api/adc/inventory` response uses `waf.resources.appfw_profiles`, `waf.resources.appfw_policies`, `waf.resources.signature_catalog`, and adds `classic`; the frontend also has no classic topology/correlation view.
- State: verification complete; no ADC or GUI configuration was changed. A frontend compatibility/update task is required before the GUI can be considered consistent with the backend.
- Recovery after connectivity loss or reboot: verify server revision with `git rev-parse --short HEAD`, run `docker compose -p waf-intelligence ps`, query `/api/adc/inventory` and `/api/adc/classic-inventory`, then refresh the dashboard and reconnect the saved ADC connection. Treat the GUI as stale until it shows the enumerated WAF counts and classic topology evidence.

### GUI inventory synchronization fix checkpoint

- Timestamp: 2026-09-20 UTC
- Action: updated `frontend/index.html` to normalize the current `waf.resources.*` inventory shape while retaining compatibility with legacy fields. Added classic ADC vserver/service/binding rendering and a read-only `Check ADC path` action for completed discovery jobs.
- Revision: `48cbd5f`, pushed to GitHub and synchronized to `/home/grega/waf-intelligence-repo`. The frontend uses a bind mount, so the running Nginx container served the updated file without an image rebuild.
- Live GUI result after refresh and reconnect: AppFW profiles `10`, policies `0`, signature catalogs `2`, inventory status `enumerated`; classic topology `10` vservers, `5` services, `5` service groups, `9` bindings; AppFW feature `enabled`; vserver profile bindings `0`.
- Live GUI correlation result for job `913c5f59-1fd9-4705-8028-a774a4102622`: target `192.168.11.91:80`, status `matched`, vserver `lb_vs_juice_shop`, backend `192.168.11.90:3000`, protection `feature-enabled-no-policy-binding-evidenced`, proposal `proposal-only`, automatic apply `disabled`.
- State: complete; no ADC configuration changed.
- Recovery after connectivity loss or reboot: verify server revision `48cbd5f` or later, run `docker compose -p waf-intelligence ps frontend`, refresh `http://192.168.11.90:8180/`, reconnect the saved ADC connection, press `Reload WAF inventory`, and use `Check ADC path` on a completed discovery job. If the GUI regresses to zero/not-available inventory, compare the served frontend revision and `/api/adc/inventory` before changing ADC state.

### Typed vserver selector, pagination, and search checkpoint

- Timestamp: 2026-09-20 UTC
- Action: extended the generic classic ADC inventory view with a vserver-type selector (`LB`, `CS`, `GW`, `Global`), page-size options (`10`, `50`, `100`), and case-insensitive search across the complete sanitized vserver record, including enumerated parameters.
- Implementation: parser revisions `ad4b6e1` and `36f73a1` added typed LB/CS/GW inventory and sanitized searchable parameters; frontend revision `88586c3` defaults to LB, preserves the selected type during inventory refresh, and keeps the UI read-only.
- Live inventory: `10` LB vservers, `2` CS vservers, `1` Gateway vserver, `13` Global records. The live dashboard shows `Showing 10 of 10 matching vservers · page size 10` on the default LB view.
- Live GUI validation: page size `50` and `100` both displayed all `13` Global records; searching `192.168.11.91` returned only `lb_vs_juice_shop`; searching the CS inventory for `vpn_vs_remote` matched `external_cs_vs` through a sanitized vserver parameter. The dashboard source served by `192.168.11.90:8180` contains the deployed selector, default-LB logic, page sizes, and parameter-search implementation.
- State: complete; read-only; no ADC configuration changed. The failed standalone `docker compose ps` check on the server was caused by the shell not loading the server-side `WAF_DB_PASSWORD`; no service restart was required because the frontend is bind-mounted.
- Next action: use this inventory view as the generic input to technology detection and signature applicability proposals. Keep proposals review-only until target ownership, WAF policy binding, exact signature applicability, preflight, confirmation, audit, and rollback are all present.
- Recovery after connectivity loss or reboot: verify local and server `git rev-parse --short HEAD` are `88586c3` or later, SSH to `grega@192.168.11.90`, run `docker compose -p waf-intelligence ps` only after loading the existing server-side Compose environment, query `http://192.168.11.90:8110/healthz` and `/api/adc/classic-inventory`, then refresh `http://192.168.11.90:8180/` and reconnect the saved ADC connection. If the UI is stale, first compare the served frontend source for `vserver-type-filter` and the API counts; do not enable writes or alter ADC configuration.

### Safe runtime application-surface inspection checkpoint

- Timestamp: 2026-09-21 UTC
- Action: enhanced the browser-based, render-and-inspect-only scanner to classify authentication screens, record visible headings/button labels and field metadata, observe same-host XHR/fetch/API response status and selected security headers, retain storage key names only, and aggregate duplicate API endpoints. No form values, request bodies, cookies, tokens, or submit actions are retained or executed.
- Implementation: revisions `187724a`, `bf0c7a8`, and `6028aab`; runtime package download timeout was raised to 120 seconds for the constrained lab link. The frontend now presents authentication surfaces and observed browser API requests in the technology profile.
- Deployment: server checkout is synchronized at `6028aab`; discovery-worker, control-api, and runtime-inspector active containers were restarted after copying the synchronized application files. A full Chromium image rebuild was attempted but the 9.8 GB Ubuntu root filesystem could not hold the second image; failed build cache was pruned without touching active containers or volumes. The active runtime image and dependencies remain in use.
- Live Juice Shop result for job `57a6b8f1-461f-4f30-a20e-2bd6377efada`: 50 routes rendered, 1,165 controls observed, 10 authentication-related surfaces, and 34 deduplicated same-host API endpoints. The login route `http://192.168.11.91/#/login` was classified as `login` with 1 password field, 2 identifier fields, Login heading, and Log in control. Registration, forgot-password, change-password, and 2FA surfaces were also identified.
- Safety result: runtime inspection returned `values_submitted=false`; no request body or post-data fields were stored. The login API POST was intentionally not generated because the scanner does not fill or submit credentials; only passive browser-load requests were observed.
- State: complete for the current safe runtime-inspection phase; no ADC configuration changed.
- Next action: enhance static JavaScript endpoint extraction and application-specific surface classification for routes where authentication calls are only reachable after a user action, while preserving the no-submit/no-credential boundary. Then feed the authenticated-surface metadata into generic WAF technology and signature applicability analysis.
- Recovery after connectivity loss or reboot: verify local and server `git rev-parse --short HEAD` are `6028aab` or later, confirm `waf-intelligence-runtime-inspector-1`, `waf-intelligence-discovery-worker-1`, `waf-intelligence-control-api-1`, and `waf-intelligence-postgres-1` are running, query `http://192.168.11.90:8110/healthz`, then rerun `POST /api/discovery/jobs/57a6b8f1-461f-4f30-a20e-2bd6377efada/runtime-inspection`. Do not recreate the runtime container on the 9.8 GB host until Docker has at least 1.5 GB free and the server checkout is synchronized; if containers were recreated, rebuild with the repository Dockerfile timeout setting and avoid deleting Postgres volumes.

### Static JavaScript authentication/API candidate checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added generic, passive extraction of URL literals from JavaScript bundles when they contain API or authentication markers. Candidates are normalized to the discovered same-host scope, query values are redacted, and the scanner records `candidate_only=true`, `not_fetched=true`, and `values_submitted=false`. The UI now separates these candidates from API calls observed during browser rendering.
- Implementation: revision `9969c3d`, pushed to GitHub and synchronized to `/home/grega/waf-intelligence-repo`. The discovery-worker application file was copied into the active container and restarted; Python compilation passed. The frontend is bind-mounted and serves the synchronized source without an image rebuild.
- Live validation: passive Juice Shop job `416d9885-a08e-4696-bf17-fa82ebd6dfda` completed with 25 pages, 4 assets, 158 evidence rows, and 46 static authentication/API endpoint candidates. Examples included `/rest/user/login`, `/rest/user/change-password?current=REDACTED`, `/api/Products`, `/api/Cards`, `/login`, `/register`, and `/forgot-password`. No candidate endpoint was fetched by this feature; no authentication surface was submitted.
- State: complete for static candidate extraction; no ADC configuration changed and no credentials were used. This complements, but does not replace, runtime inspection: static candidates may include routes reachable only after user interaction and require later approved, read-only verification.
- Disk status: the Ubuntu host has approximately 700 MB free on its 9.8 GB root filesystem after failed build-cache cleanup. A clean rebuild of the Chromium runtime image should wait until at least 4 GB additional root space is available; 8 GB additional is preferred for future rebuilds and cache headroom. The current active containers were not removed.
- Next action: combine static candidates, passive runtime API metadata, authentication-surface metadata, technology signals, and ADC topology into generic WAF applicability scoring. Keep endpoint verification passive and keep signature/profile changes proposal-only until target ownership and guarded write controls are explicitly approved.
- Recovery after connectivity loss or reboot: verify local and server `git rev-parse --short HEAD` are `9969c3d` or later, SSH to `grega@192.168.11.90`, run `docker compose -p waf-intelligence ps` only after loading the existing server-side Compose environment, query `http://192.168.11.90:8110/healthz`, then query job `416d9885-a08e-4696-bf17-fa82ebd6dfda` and its `/profile`. If the worker was recreated, restore the repository checkout first and rebuild only after extending disk; do not delete active Postgres volumes. Do not fetch the reported candidate endpoints or enable ADC writes as part of recovery.

### Generic applicability, clean rebuild, and proposal validation checkpoint

- Timestamp: 2026-09-21 UTC
- Clean rebuild: after extending the Ubuntu root filesystem to 57 GB, rebuilt all application images from the repository with `docker compose -p waf-intelligence build --pull --no-cache`, including the Chromium runtime image. Increased pip install timeouts on all Python service Dockerfiles after the first rebuild hit a slow PyPI read timeout. Recreated the Compose project with `--force-recreate`; all seven WAF Intelligence services are running and Postgres is healthy.
- Scoring implementation: revision `bd3a18c` adds provider-neutral applicability scores, confidence labels, and scoring evidence to generic protection intents. It uses technology, routes, fields, runtime auth surfaces, runtime API endpoints, static API/auth candidates, cookies, and protocol evidence. The GUI displays this scoring table. Four generic protection unit tests pass.
- ADC plan fix: revision `dfe9b94` makes proposal target correlation use the verified classic CLI inventory and handles null ADC profile type metadata. This corrected the proposal from an uncorrelated target to `lb_vs_juice_shop` at `192.168.11.91:80`.
- Live combined evidence for job `416d9885-a08e-4696-bf17-fa82ebd6dfda`: 208 evidence rows; 50 passive runtime rows; 10 authentication surfaces; 34 deduplicated runtime API endpoints; 46 static JavaScript API/auth candidates; `values_submitted=false`. Applicability scores: session/auth `0.95`, injection/input `0.92`, XSS `0.90`. No credentials, request bodies, or attack payloads were used.
- Proposal result: ADC plan status `proposal-only`, target match `true`, vserver `lb_vs_juice_shop`, no blocking target-ownership condition, two installed signature catalogs, changes applied `false`, approval required `true`. The selected generic catalog groups are web baseline, SPA client, and form input, all still proposal-only and Log mode.
- Signature validation: `GET /api/adc/inventory`, `/api/adc/signatures/catalog`, and `/api/adc/signatures/rules` were read-only. The ADC exposes `*Default Signatures` (`default_signatures.xml`, 2,879,756 bytes) and `*Xpath Injection Patterns` (`xpath_injection_patterns.xml`, 2,621 bytes). Rule-level metadata status is `configured-file-missing`, so the prepared signature set `a7a40a3e-6efe-447f-b140-5c1b9da71043` is `blocked-missing-rule-level-catalog`, with no selected rules and `changes_applied=false`. This is an intentional fail-closed result; catalog filenames are not treated as rule IDs.
- State: steps 1-5 complete for read-only/proposal validation. No ADC profile, policy, binding, signature catalog, or enforcement setting was changed. `NETSCALER_WRITE_ENABLED=false` remains in effect.
- Next action: supply an administrator-approved normalized rule-level catalog for the installed signature files, then rerun the signature-set proposal and review the selected rule IDs. After approval, preflight must verify target ownership, catalog fingerprint, source profile state, and rollback snapshot; only then can a separately confirmed lab write be considered.
- Recovery after connectivity loss or reboot: verify local and server revision `dfe9b94` or later; SSH to `grega@192.168.11.90`; load the existing server-side `WAF_DB_PASSWORD`; run `docker compose -p waf-intelligence ps`; query `http://192.168.11.90:8110/healthz`; then query the combined job profile, `/api/discovery/jobs/416d9885-a08e-4696-bf17-fa82ebd6dfda/analysis`, `/adc-plan`, `/api/adc/inventory`, and signature-set `a7a40a3e-6efe-447f-b140-5c1b9da71043`. Do not approve the set, enable writes, or retry with guessed rule IDs. If the runtime image needs rebuilding, use the repository Dockerfiles with the 120-second pip timeout and preserve the Postgres volume.

### Rule-level catalog capability checkpoint

- Timestamp: 2026-09-21 UTC
- Action: executed the next guarded signature phases against the live lab: rechecked the rule inventory and prepared set, then queried the ADC's verified CLI help and each installed catalog filename using read-only SSH commands.
- Evidence: `show appfw signatures ?` exposes only the catalog summary and a `<name>` lookup. The ADC returned catalog metadata for `default_signatures.xml` and `xpath_injection_patterns.xml`, but querying those names returned `ERROR: Signature does not exist`; no rule IDs, categories, attack classes, or technology tags were exposed.
- Result: the live rule inventory remains `configured-file-missing` with `rule_count=0`; signature set `a7a40a3e-6efe-447f-b140-5c1b9da71043` remains `blocked-missing-rule-level-catalog`, with no selected rules, no approval, no preflight, and `changes_applied=false`.
- State: phases 1-2 are complete for verified catalog discovery and applicability review. Phases 3-5 are intentionally blocked because exact rule-level applicability cannot be proven. No ADC configuration changed and `NETSCALER_WRITE_ENABLED=false` remains in effect.
- Required input: place an administrator-approved normalized export containing the actual rule IDs from the installed catalogs at `catalogs/netscaler_rule_catalog.json` (or provide an equivalent XML export). Do not fabricate IDs or commit proprietary raw signature files. Once present, rerun rule resolution, review the exact selected rules, approve the exact fingerprint, run preflight, and only then consider a separately confirmed lab Log-mode write.
- Recovery after connectivity loss or reboot: verify local and server revision `be8893e` or later; query `/healthz`, `/api/adc/signatures/rules`, and signature set `a7a40a3e-6efe-447f-b140-5c1b9da71043`; verify the ADC read-only command `show appfw signatures`; do not approve, enable writes, or retry guessed rule IDs. If the export is supplied, synchronize only that normalized metadata file before rebuilding or restarting the adapter.

### Local signature export and indexing checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added a local export/index workflow for NetScaler native signature XML. The adapter parser now recognizes `SignatureRule` metadata and derives rule IDs, categories, versions, enabled state, actions, descriptions, references, pattern locations, match types, attack classes, and technology tags without retaining pattern payloads.
- Tooling: revision `771437a` adds `tools/index_netscaler_signatures.py`, Git-ignores raw exports and generated catalog indexes, and documents the local workflow in `catalogs/README.md`.
- Validation: four rule-catalog tests pass in the rebuilt adapter image. The server checkout is synchronized to `771437a`; the adapter was rebuilt and recreated; `/healthz` is healthy. Because no export has been supplied yet, `/api/adc/signatures/rules` remains `configured-file-missing`, `rule_count=0`, and no signature rules are selected.
- Acquisition: Citrix documents exporting a signatures object from the Web App Firewall GUI. Export `*Default Signatures` and `*Xpath Injection Patterns` into the local `signature-cache/raw/` directory, then run the indexing tool. Keep raw XML local and transfer only the normalized index to the server's `catalogs/` mount.
- State: no ADC configuration changed, no signature object was modified, and `NETSCALER_WRITE_ENABLED=false` remains in effect.
- Recovery after connectivity loss or reboot: verify local and server revision `771437a` or later, run `docker compose -p waf-intelligence ps` only after loading the existing server-side database password environment, query `/healthz` and `/api/adc/signatures/rules`, and rerun the indexer only from the preserved local raw exports. Do not delete raw exports before the normalized index fingerprint and rule count have been verified.

### WAF_Default signature export and exact rule inventory checkpoint

- Timestamp: 2026-09-21 UTC
- Acquisition: authenticated read-only ADC shell/SFTP retrieval copied the user-defined `WAF_Default` object from `/var/tmp/waf_default` and the appliance files `/netscaler/default_signatures.xml` and `/netscaler/xpath_injection_patterns.xml`. Raw files are stored only in the ignored local/server `signature-cache/raw/` directories.
- Exact counts: `WAF_Default` contains `3,208` `SignatureRule` elements with `3,208` unique rule IDs and no duplicate IDs. All `3,208` exported rules have `enabled=OFF`; this is separate from the GUI object's Auto Enable New Signatures setting.
- WAF_Default categories: `web-misc=1,937`, `web-cgi=362`, `web-wordpress=353`, `web-php=190`, `web-iis=151`, `web-client=62`, `web-coldfusion=43`, `web-struts=31`, `llm=26`, `web-frontpage=38`, `drupal=6`, `web-shell-shock=4`, `web-activex=2`, `cve-2024=2`, and `http.sys=1`.
- Built-in comparison: `default_signatures.xml` contains `3,156` unique rules. `WAF_Default` contains all of them plus `52` new IDs (`998078` through `998129`) and no removals. The additions are primarily current CVE entries in `web-misc`, `web-wordpress`, `llm`, and `cve-2024` categories.
- XPath object: `xpath_injection_patterns.xml` is `2,621` bytes and contains `47` keyword patterns plus `10` special-string patterns, but no `SignatureRule` IDs; it is indexed as a pattern catalog rather than a rule-level catalog.
- Live normalized inventory: adapter status `enumerated`, `rule_count=3208`, catalog fingerprint `2c5eda9d7479a3d282e568aedb25ed77bcabf2514d38a26f83852816ac14d1e2`. The normalized index is available locally and at the server's read-only `catalogs/netscaler_rule_catalog.json` mount.
- Proposal validation: new signature set `e216dc67-a9de-402a-a666-b9a70ed45256` is `draft`, plan fingerprint `af369986d902b6280ce6f30b9280e2496e6013b815046db2c7bef5b9bacc6bfa`, and selects `1,327` exact rule IDs for proposal-only Log mode: `684` generic web, `461` injection/input, and `182` XSS. Session/auth remains unresolved; runtime-specific and technology-specific intents remain conditional. No ADC configuration changed and writes remain disabled.
- Recovery after connectivity loss or reboot: verify raw-file SHA-256 for `WAF_Default.xml` as `cb620670866f49f7d729b4f5512e0de2578e4f0796b2588e3510f9d3270b8cdc`, verify server/local normalized index count `3208` and fingerprint `2c5eda9d7479a3d282e568aedb25ed77bcabf2514d38a26f83852816ac14d1e2`, query `/api/adc/signatures/rules`, and retrieve signature set `e216dc67-a9de-402a-a666-b9a70ed45256`. Do not approve or apply the draft until rule scope and false-positive strategy are reviewed.

### Signature proposal schema alignment checkpoint

- Timestamp: 2026-09-21 UTC
- Action: aligned the control API rule-catalog schema to `1.1.0`, rebuilt/recreated control-api, and regenerated the proposal after the WAF_Default index was mounted.
- Current proposal: signature set `2caa377f-55d6-45e1-b16b-85f0fbcb7105`, status `draft`, plan fingerprint `02deaab366fbd177a0a297698d89eb82a95d7d61ab397a03d780c69457e9e9dc`, catalog fingerprint `2c5eda9d7479a3d282e568aedb25ed77bcabf2514d38a26f83852816ac14d1e2`, and `1327` selected exact rules. No changes were applied; writes remain disabled.
- Recovery after connectivity loss or reboot: verify server revision `28d495d` or later, control-api health, rule inventory status `enumerated` with `3208` rules, and signature set `2caa377f-55d6-45e1-b16b-85f0fbcb7105`. Treat the set as review-only until an explicit false-positive review and approval are completed.

### Hourly upstream signature synchronization checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added the `signature-sync` service. It reads Citrix's official `SignaturesMapping.xml`, selects the configured ADC release/build (default `14.1`/`0`), checks the mapped SHA-1, downloads changed signature XML, indexes it with the existing normalized rule parser, and records state/history atomically.
- Safety boundary: the service is read-only with respect to the ADC and does not overwrite or promote the reviewed `WAF_Default` catalog. Upstream raw XML and generated indexes remain under the ignored `signature-cache/upstream/` volume. Existing good data is preserved on an update error.
- Schedule: the container runs an initial check on startup and repeats every `3600` seconds. Configuration is available through `SIGNATURE_SOURCE_URL`, `SIGNATURE_TARGET_RELEASE`, `SIGNATURE_TARGET_BUILD`, `SIGNATURE_SYNC_INTERVAL_SECONDS`, `SIGNATURE_SYNC_VERIFY_SHA1`, and `SIGNATURE_SYNC_DATA_DIR`. Internal endpoints are `/healthz`, `/status`, and `POST /run`.
- Source authority: Citrix documents the mapping-driven hourly signature update process at `https://docs.netscaler.com/en-us/citrix-adc/current-release/application-firewall/signatures/signature-auto-update.html`; the implementation uses the published mapping rather than guessing release filenames.
- State: the first live run correctly failed closed because the mapped `.sha1` file is a Citrix-signed payload rather than a plain 40-character hash. The implementation now verifies the mapped `.digest` RSA signature with the ADC's Citrix public key and records the integrity method; deployment validation continues with the corrected verifier. No ADC configuration change is part of this phase.
- Recovery after connectivity loss or reboot: verify the local/server revision, load the existing server-side `WAF_DB_PASSWORD`, run `docker compose -p waf-intelligence ps`, inspect `signature-cache/upstream/state.json`, and query the service `/status` from inside the Compose network. On a reboot, allow the startup check to run; on a source error, keep the prior `latest.json` and investigate the recorded `error_type`/`error` before retrying. Do not delete the cache or enable ADC writes as recovery actions.

### Hourly signature sync live validation checkpoint

- Timestamp: 2026-09-21 UTC
- Revision: `8aac578` is pushed to GitHub and deployed to `/home/grega/waf-intelligence-repo` on `192.168.11.90`.
- Live result: service `waf-intelligence-signature-sync-1` is running; `/healthz` is healthy; Citrix ADC 14.1 build 0 resolved to version `183`, source file `sigs/sig-r14.1b0v183s8.xml`, and `3,208` indexed rules. The `.digest` payload was verified with the ADC's Citrix public key (`integrity_status=citrix-rsa-sha1`).
- No-change result: a second manual `POST /run` returned `last_result=not-modified`; it rechecked the mapping/checksum metadata without re-downloading or re-indexing the unchanged XML.
- Tests: the two signature-sync unit tests pass in the built service image. The first incorrect parser implementation failed closed and did not replace the cache; the corrected verifier then completed the update safely.
- State: complete for hourly upstream acquisition and indexing. The upstream cache is separate from the reviewed `WAF_Default` catalog; no ADC configuration was changed and `NETSCALER_WRITE_ENABLED=false` remains in effect.
- Recovery after connectivity loss or reboot: verify local/server revision `8aac578` or later, confirm `signature-sync` is running, load the existing server-side `WAF_DB_PASSWORD` before Compose commands, query `/status` from inside the container network, and inspect `signature-cache/upstream/state.json`. A reboot restarts the container and runs the startup check. If the key is missing or verification fails, the service records an error and preserves the prior index; restore the administrator-approved key at `signature-cache/citrix_public.pem` before retrying. Do not delete the cache or enable ADC writes.

### Signature-backed technology context checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added a generic correlation layer that reads the reviewed `WAF_Default` normalized index and attaches matching signature tags, categories, rule counts, and example rule IDs to technologies already detected from passive HTTP evidence. Web-application and server/runtime matches are separated in the analysis response and GUI.
- Safety boundary: signature metadata is explicitly marked `is_detection_evidence=false`; it cannot independently promote WordPress, IIS, PHP, Exchange, or another technology. This prevents false positives from a catalog that merely contains rules for a product.
- Live validation: revision `7af4085` is deployed. Focused discovery and technology tests pass (`9` tests). Existing Juice Shop profile `416d9885-a08e-4696-bf17-fa82ebd6dfda` reports `catalog_rule_count=3208`, fingerprint `bf4673499046ebdf75769b43063715702e385acc2677d2f97669a62fe83c2acd`, and `status=no-technology-tag-match` because the observed technology is Angular and the current NetScaler catalog has no Angular tag. No technology was falsely added.
- Recovery after connectivity loss or reboot: verify revision `7af4085` or later, confirm discovery-worker has `/run/signature-index/WAF_Default.json` mounted read-only, query the job profile, and check `signature_technology_context.status`. If the index is unavailable, the scanner remains functional and reports `configured-file-missing` or `invalid-index`; restore the preserved normalized index before rebuilding. Do not treat catalog tags as independent detection evidence.

### Public-site detection comparison checkpoint

- Timestamp: 2026-09-21 UTC
- Action: ran two passive, same-host discovery tests through the deployed scanner with `max_pages=25`, `rate_limit_per_second=1.0`, and no form submission or credentials.
- RTVSLO job `494fc702-4974-4a6e-ac31-41edc95730ef`: completed with `25` pages, `1` fetched asset, and `797` evidence rows. Detected high-confidence `nginx`, Bootstrap, jQuery, HTML forms, file-upload surface, and state-changing form surface; authentication boundary was medium confidence. The normalized catalog correlated `nginx` to `4` server rules in `web-misc` (`998130`, `998312`, `998315`, `998319`).
- ESS job `bdac3c4c-32c9-4f09-aaf0-8bb65ea2ebd0`: completed with `25` pages, `16` fetched assets, and `619` evidence rows. Detected high-confidence WordPress, Angular, Bootstrap, jQuery, and HTML forms; medium-confidence generated platform, XML/SOAP, and reverse-proxy/cache signals. The generated-platform evidence explicitly reported `TYPO3 CMS`; the WordPress evidence came from a `/wp-content/` or `/wp-includes/` marker. The catalog correlated WordPress to `400` web-application rules across `web-misc`, `web-php`, and `web-wordpress`.
- Analysis output: RTVSLO produced `642` route-inventory entries and `1,323` fields; ESS produced `289` routes, `562` fields, `15` route candidates, and `23` authentication/API candidates. Both produced generic baseline, injection/input, and XSS protection intents as proposal-only `LOG` decisions. ESS additionally produced XML/SOAP protection intent and API/client-platform architecture indicators.
- Quality findings: passive detection is meaningfully stronger than a single-header check because it aggregates repeated page, asset, HTML, URL, and metadata signals and then resolves signature applicability. However, signature catalog matches remain applicability context only (`is_detection_evidence=false`). The ESS WordPress/TYPO3 coexistence requires corroboration, and the XML/SOAP signals were observed on CSS responses (`content_type=text/css`), so protocol detection must be tightened to avoid promoting a false positive. RTVSLO's repeated password markers also need route/form classification before being treated as an authentication boundary.
- State: tests complete; no target-side changes and no ADC configuration changes. The existing read-only boundary remains in effect.
- Next action: add signal-family/content-type guards and corroboration scoring, then rerun these exact jobs plus Juice Shop as regression fixtures before any technology-driven signature proposal is allowed to change.
- Recovery after connectivity loss or reboot: verify local/server revision `4df1268` or later, query `http://192.168.11.90:8110/healthz`, confirm discovery-worker is running, and retrieve jobs `494fc702-4974-4a6e-ac31-41edc95730ef` and `bdac3c4c-32c9-4f09-aaf0-8bb65ea2ebd0` with `/profile` and `/analysis`. If the jobs are unavailable, rerun the same passive POST requests with the original seed URLs and limits; do not submit forms, use credentials, or enable ADC writes.

### Guarded custom-signature authoring checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added proposal-only local NetScaler signature authoring endpoints. A draft must reference a completed discovery job, include an operator-supplied pattern, and include at least one positive and one negative offline test case. Detection results provide scope/applicability context only; benign technology, route, and field observations are never converted into attack patterns.
- Implementation: revision `3fb86db` adds `/api/custom-signatures/drafts`, persistent draft storage, local rule-ID allocation in `1000000-1999999`, literal/PCRE validation, forced `enabled=false` and `LOG` defaults, stable draft fingerprints, and an explicit native-XML guard. The import command is represented as a template only until an appliance-exported user-defined signature template is validated.
- Validation: 9 focused unit tests pass. Live control API health is `ok`. Harmless ESS authoring smoke test created draft `f79f6bff-eb73-41ef-8ec0-ab85ee89ab92` with local rule ID `1548445`, detector version `1.1.0`, one positive and one negative offline test, `native_xml_status=blocked-until-appliance-template-validation`, `write_enabled=false`, and `changes_applied=false`. No ADC import or write request was sent.
- State: authoring and offline validation complete; native artifact generation and appliance mutation remain blocked pending a verified appliance-exported user-defined signature template and exact import/merge validation.
- Next action: obtain one lab-exported user-defined signatures object containing a local rule, compare its XML structure to the authoring spec, add a schema-preserving exporter, and validate import into a disposable user-defined signature object in Log mode before exposing any write path.
- Recovery after connectivity loss or reboot: verify local/server revision `3fb86db` or later, confirm `waf-intelligence-control-api-1` and Postgres are healthy, query `http://192.168.11.90:8110/healthz`, and retrieve draft `f79f6bff-eb73-41ef-8ec0-ab85ee89ab92`. Do not enable ADC writes, resend an import, or delete the draft as a recovery action.

### Hourly latest-catalog proposal and guarded ADC export checkpoint

- Timestamp: 2026-09-21 UTC
- Action: connected the verified hourly upstream catalog to discovery-worker and control-api. The proposal workflow now reads `/run/upstream-signatures/latest.json`, while the sync service keeps its own verified raw/index cache and preserves the previous good catalog on update errors.
- Workflow: `POST /api/custom-signature-sets/prepare` creates an editable hostname-based signature object proposal; `PATCH` edits exact rule IDs and selects `LOG` or `BLOCK`; `approve` requires `APPROVE CUSTOM SIGNATURE SET`; `preflight` rechecks the latest catalog fingerprint, rule IDs, object-name collision, and action; `export` requires `ENABLE WRITE` and the exact `ENABLE WRITE` phrase. A guarded rollback endpoint removes only an unreferenced exported object.
- Live catalog evidence: signature-sync checks every `3600` seconds, is currently `not-modified`, and reports Citrix RSA-SHA1 integrity, release `14.1`, build `0`, version `183`, and `3,208` rules. The ESS proposal used `/run/upstream-signatures/latest.json`, catalog fingerprint `5ebcbc9f8233d9333c702f762322666488b5ae1bae9ac945bc071733f9755c29`, and selected `963` exact rules by default.
- Admin workflow validation: proposal `a9e26c31-bc42-446a-87d6-e78cb4e8d4fe` defaulted to `waf-www-ess-gov-si-bdac3c4c`; it was edited to `waf-www-ess-gov-si-lab`, five exact rules, and `BLOCK`. Approval succeeded with approval `05c7bb2f-4a82-460e-bcab-876b1bda329f`; preflight passed all catalog, rule, name, and enforcement checks but returned `blocked-write-disabled`. A guarded export attempt returned HTTP 403 and did not contact the ADC.
- Implementation: revisions `cfdf0d4`, `c9dbdee`, and `1e55318`; 21 focused tests pass. The adapter constructs only validated CLI commands from object name, numeric rule IDs, and action; it does not accept arbitrary CLI text. No ADC signature object was created or modified.
- State: hourly acquisition, latest-catalog proposal, admin selection, LOG/BLOCK confirmation, preflight, guarded export path, and rollback path are implemented. Actual ADC export remains intentionally disabled until the administrator enables the write flag for a separately approved lab change.
- Recovery after connectivity loss or reboot: verify local/server revision `1e55318` or later, load the existing server-side `WAF_DB_PASSWORD` before Compose commands, confirm `signature-sync`, `control-api`, `discovery-worker`, `netscaler-adapter`, and Postgres are healthy, query `/healthz`, inspect signature-sync `/status` from inside the Compose network, and retrieve proposal `a9e26c31-bc42-446a-87d6-e78cb4e8d4fe`. Before any export, rerun approval/preflight against the current catalog. Do not bypass the fingerprint, name-collision, action, approval, or `ENABLE WRITE` guards.

### Guarded write-mode enablement checkpoint

- Timestamp: 2026-09-21 UTC
- Action: enabled `NETSCALER_WRITE_ENABLED=true` for the control-api and NetScaler adapter Compose services, then recreated only those two containers. The discovery, sync, and database services were not modified.
- Live verification: control-api and adapter environment inspection report `true`; control-api `/healthz` is `ok`. No signature export was triggered. Replaying the previously approved test export with its stale blocked preflight returned HTTP 403 (`Approved custom signature set and successful preflight are required`).
- State: write mode is available for a separately reviewed lab export, but the existing test proposal has not been re-preflighted or exported. No ADC configuration changed.
- Recovery after connectivity loss or reboot: verify local/server revision `ca55f60` or later, confirm both containers report `NETSCALER_WRITE_ENABLED=true`, query `/healthz`, and rerun the exact proposal preflight before export. To disable writes, set both Compose values back to `false` and recreate control-api and netscaler-adapter; do not use an export request as a connectivity test.

### GUI custom-signature workflow checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added the GUI workflow for detection-driven custom signature proposals. After an analysis completes, the operator can prepare a hostname-based proposal from the latest verified hourly catalog, review the selected rule sample and catalog fingerprint, edit exact rule IDs, choose `LOG` or `BLOCK`, approve with `APPROVE CUSTOM SIGNATURE SET`, run preflight, export with `ENABLE WRITE`, or roll back an exported object.
- Safety boundary: the GUI never accepts arbitrary CLI text and does not send an ADC request during analysis, proposal preparation, editing, or approval. Export is still gated by current-catalog fingerprint validation, exact rule validation, object-name collision checks, successful preflight, approval, and the explicit confirmation phrase.
- Validation: inline frontend JavaScript syntax check and `git diff --check` pass. Deployment uses the existing read-only bind mount of `frontend/index.html`; no container recreation is required for the frontend-only change. No ADC configuration change was made by this GUI phase.
- Recovery after connectivity loss or reboot: verify the server checkout revision, confirm `http://192.168.11.90:8180/` serves the custom-signature controls, and query `http://192.168.11.90:8110/healthz`. If the GUI is stale, run `git pull --ff-only origin main` in `/home/grega/waf-intelligence-repo`; do not export or retry an ADC mutation until the proposal is reloaded and preflight succeeds against the current catalog.

### GUI live smoke-validation checkpoint

- Timestamp: 2026-09-21 UTC
- Live result: after reconnecting the saved lab ADC session, the GUI loaded `13` vservers, `3` signature catalogs, and displayed `Guarded write-enabled` / `Write mode: enabled` from the live inventory response. The existing ESS discovery job generated evidence analysis and exposed the detection-driven custom signature controls.
- Workflow result: the GUI prepared draft object `waf-www-ess-gov-si-bdac3c4c` with catalog version `183`, Citrix RSA-SHA1 integrity, current catalog fingerprint `5ebcbc9f8233d9333c702f762322666488b5ae1bae9ac945bc071733f9755c29`, and `963` selected exact rules in `LOG` mode. It remained a draft; no approval, preflight, export, or ADC mutation was performed.
- Recovery after connectivity loss or reboot: refresh the page, reconnect the saved ADC session, reload WAF inventory, and verify `Guarded write-enabled` only from the live response. If the custom proposal is stale, discard it from the review flow and prepare a new proposal so the current catalog fingerprint is captured before approval.

### Juice Shop end-to-end workflow and GUI refinement checkpoint

- Timestamp: 2026-09-21 UTC
- Live scan: Juice Shop at `http://192.168.11.91` completed with `53` pages, `265` sanitized evidence rows after passive runtime inspection, `105` routes, and `10` authentication surfaces. Angular was detected with high confidence (`0.94`). ADC correlation matched `lb_vs_juice_shop` on `192.168.11.91:80`; WAF feature enablement was evidenced, but no AppFW policy binding was correlated.
- Selection safety: the detection-driven selector produced `408` exact rules from catalog version `183` and excluded `546` technology-tagged rules for technologies not evidenced by the scan, including WordPress, PHP, IIS, Exchange, Nginx, and others. The GUI now shows selected-rule metrics, excluded-rule counts, severity mix, and a four-step selection/approval/preflight/export workflow.
- Export: proposal `bd5636e4-20e1-4425-91c8-69a5c33e6a0a` used object `waf-192-168-11-91-e391fb6c` in `LOG` mode. Approval, stable-fingerprint preflight, catalog integrity, rule selection, object collision, and write-safety checks passed. The object was exported successfully to the lab ADC with `408` enabled rules and configuration saved; the live ADC signature inventory now contains `4` objects.
- Implementation: revisions `709f197`, `d4982b4`, `2c133ce`, `fb18311`, `9405ad1`, and `f520b6f` add technology-aware exclusion, stable preflight fingerprints, GUI workflow metrics, ADC-supported native XML export over temporary SFTP, and sanitized CLI rejection diagnostics.
- Recovery after connectivity loss or reboot: verify server revision `f520b6f` or later, confirm all Compose services and Postgres health, query `http://192.168.11.90:8110/healthz`, retrieve proposal `bd5636e4-20e1-4425-91c8-69a5c33e6a0a`, and re-read the ADC signature inventory before retrying any export. Do not resend an export with stale approval or preflight identifiers; rerun preflight against the current catalog first.

### Simplified GUI landing and on-demand tools checkpoint

- Timestamp: 2026-09-21 UTC
- Action: removed the Platform and Connected ADC summary cards from the landing view. Mode is now one compact line with approval mode and live WAF write state. The first page contains only ADC connection and saved-connection options.
- On-demand behavior: after connection, the GUI presents a small Tools menu. WAF inventory and passive discovery are opened only when selected. AppFW profiles and profile actions are hidden inside an expandable panel rather than shown in the initial inventory view.
- Live validation: server revision `5ecd17f` serves the simplified page. The browser showed the compact landing view, reconnected to `192.168.11.101`, reported `Guarded write-enabled` / `enabled`, loaded WAF inventory on demand, and showed `Show AppFW profiles and profile actions (10)` collapsed. No ADC configuration change was made.
- Recovery after connectivity loss or reboot: verify `/home/grega/waf-intelligence-repo` is at `5ecd17f` or later, reload `http://192.168.11.90:8180/`, reconnect the saved ADC session, and open WAF inventory or application discovery from Tools as needed. If the page is stale, run `git pull --ff-only origin main`; no container recreation is required because the frontend is bind-mounted.

### Discovery action-row layout checkpoint

- Timestamp: 2026-09-21 UTC
- Action: grouped discovery-row controls into a non-wrapping action container so `View profile`, `Check ADC path`, and `Delete` remain on the same line with consistent spacing.
- Live validation: revision `1de6b8e` is deployed and the browser displayed all three controls together for the completed ESS discovery job. No discovery data or ADC configuration was changed.
- Recovery after connectivity loss or reboot: verify the server checkout is at `1de6b8e` or later and reload the GUI. If the old layout remains, run `git pull --ff-only origin main`; no container recreation is required for this frontend-only change.

### Compact discovery summary workflow checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added a direct `Generate analysis` button beside `View profile`, `Check ADC path`, and `Delete` for completed discovery jobs. `View profile` now renders a compact technology summary; `Generate analysis` renders a compact protection summary with architecture, protection areas, intents, and recommended signature groups.
- Live validation: revision `6a4533c` is deployed. The Juice Shop discovery row displayed all four actions on one line. View profile showed one summary card, and Generate analysis showed `54` sanitized observations with compact protection recommendations. No target-side or ADC configuration change was made.
- Recovery after connectivity loss or reboot: verify the server checkout is at `6a4533c` or later and reload the GUI. If the old detailed view remains, run `git pull --ff-only origin main`; no container recreation is required for this frontend-only change.

### Findings and signature-recommendation summary checkpoint

- Timestamp: 2026-09-21 UTC
- Action: expanded View profile into a compact findings summary with metrics, detected technologies, route/form/auth counts, and a parallel Signature applicability panel showing catalog status, rule count, categories, and example rule IDs. Added a same-row `Signature recommendations` button for a focused proposal summary.
- Live validation: revision `02ffe20` is deployed. Juice Shop View profile showed Angular findings plus the signature applicability context (`3208` catalog rules; no Angular tag match), and the Signature recommendations view showed detected platform context, included protection intents, and recommended groups. No ADC or target-side change was made.
- Recovery after connectivity loss or reboot: verify the server checkout is at `02ffe20` or later, reload the GUI, reconnect the saved ADC session, and reopen application discovery. If the old single-line or detailed profile remains, run `git pull --ff-only origin main`; no container recreation is required for this frontend-only change.

### Exact rule-level signature recommendation checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added a read-only `POST /api/custom-signature-sets/recommendations` endpoint that reuses the verified catalog and detection-to-rule resolver without persisting a draft or contacting the ADC. The GUI Signature recommendations action now displays exact selected rule IDs, category counts, attack classes, locations, descriptions, selection sources, catalog version, and an optional editable proposal-draft action.
- Repository state: implementation is pushed as `6583cdf`. Local frontend syntax validation and diff validation pass. Live rebuild and endpoint verification are pending because `192.168.11.90` is currently unreachable on SSH and ICMP.
- Recovery after connectivity loss or reboot: once the server is reachable, run `cd /home/grega/waf-intelligence-repo && git pull --ff-only origin main`, load the existing `WAF_DB_PASSWORD`, rebuild/recreate only `control-api`, query `/healthz`, then POST the completed job ID to `/api/custom-signature-sets/recommendations`. Verify exact rule count and IDs before any proposal approval or export. Do not treat the recommendation endpoint as an ADC write test.

### Guarded LOG-only AppFW binding checkpoint

- Timestamp: 2026-09-21 UTC
- Action: added the guarded profile → signature object → AppFW policy → LB vServer binding workflow. The adapter uses only validated server-generated CLI commands and the live appliance syntax; the control API retains approval, fingerprint, preflight, exact `ENABLE WRITE`, audit, and rollback gates. The GUI now accepts an exported signature object, target LB vServer, and optional policy name.
- Live change: approved and applied profile `waf-scan-lb_vs_juice_shop-lab`, signature object `waf-192-168-11-91-e391fb6c`, policy `waf-juice-lab-policy`, and REQUEST priority `100` on `lb_vs_juice_shop`. The profile is LOG-only; no BLOCK action was enabled. A benign request through `http://192.168.11.91/` returned HTTP `200` and the ADC policy reported one hit.
- Verification: ADC inventory shows the custom profile with the exported signature object; detailed CLI output shows the policy rule `true`, profile association, and binding to `lb_vs_juice_shop`. Policy inventory parsing was extended to retain profile and bound-vServer context. Deployed revisions: `c35274c`, `36980af`, `2e18caa`, and `e1425bf`.
- Recovery after connectivity loss or reboot: verify `/home/grega/waf-intelligence-repo` is at `e1425bf` or later, load the existing `WAF_DB_PASSWORD`, recreate `netscaler-adapter` (and `control-api` if its source changed), check all Compose services plus `/healthz`, then query `/api/adc/appfw/profiles`, `/api/adc/appfw/policies`, and `/api/adc/classic-inventory` before retrying any write. To roll back this exact change, use the stored approval/preflight identifiers and the guarded rollback endpoint; it unbinds the generated policy, removes that policy, then deletes only the generated profile. Do not remove the shared exported signature object as part of profile rollback.
