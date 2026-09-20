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
