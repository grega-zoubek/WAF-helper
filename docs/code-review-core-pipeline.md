# Code review: technology identification to signature recommendation

Reviewed 2026-11-08 against `main` at `3fdcca2`. Scope: the path that turns a scanned application into a
signature proposal, plus the NetScaler write path it feeds. This is **not** a full-repo review.

## 1. Is the stated purpose in place?

| Capability you described | Status | Evidence |
|---|---|---|
| Identify web application technology from passive evidence | **In place, narrow** | `technology_detection.py` fingerprints about 30 technologies from headers, cookies, meta, assets, paths. 7 unit tests pass. |
| Turn detected technology into signature rules | **In place, with no confidence gate** | `signature_technology.py` maps 14 technologies to catalog tags; `signature_workflow.py` adds every rule with a matching tag. See H2. |
| Generic signature groups (5) with exact rule IDs | **In place** | `generic_signature_groups.py`, `rule_catalog.py`; tests pass. |
| Identify search fields | **Partial** | `type=search`, or "search" in name/id/aria-label, a `search-bar` component, and JS markers (`discovery-worker/app/main.py:88-92,301-313`). |
| Identify user/password fields | **Partial** | Only the browser inspector classifies a *page* as login-like (`runtime-inspector/app/main.py:69-99`). No per-field role. |
| Other field roles (email, phone, card, upload, CSRF token, free text) | **Missing** | Raw `type`/`name`/`pattern` are stored and nothing classifies them. Upload is detected only from a `multipart` form (`technology_detection.py:257`), not from `<input type=file>`. |
| Link each field to its form, method and action | **Missing in the crawler and runtime inspector** | `SurfaceParser` keeps `forms` and `controls` as two flat lists. Only the guided Browser Lab records `form_id/form_method/form_action`. |
| Start URLs | **Partial** | The crawled route list is shown as "Start URLs". No entry-point selection, no `sitemap.xml`/`robots.txt`. The compile preview emits exact-path `start_url` rows in observe mode only (`positive_compile.py:47`). |
| Positive model built from a scan | **Partial** | `build_discovery_candidate` (`positive_learning.py:246-348`) models GET/HEAD routes and URL query names only. It never reads `field_formats`, `forms` or `auth_surfaces`, so login and search forms do not reach the model. |
| SQL injection test | **Not in place, by design** | No attack payloads exist anywhere in `services/`. The Browser Lab fills a fixed benign value (`waf-observation`) and never submits. See section 5. |

**Conclusion:** technology identification and signature recommendation exist and are testable. Field
identification and the positive model are only partly there. The findings below affect the first two
directly, so I recommend fixing the High items before building on them.

## 2. Method and limits

- Read in full: detector, discovery worker, signature-to-technology mapping, confidence, generic protection,
  analysis service, signature workflow, rule catalog, positive learning and compile (about 3,000 lines).
- Read in part: runtime inspector, NetScaler adapter write path, SSH execution, signature-sync, group matcher,
  job creation (about 1,000 lines).
- **Not reviewed:** `control-api/app/main.py` (3,335 lines, including operator auth, approval and preflight
  gates), `frontend/index.html`, `operator_auth.py`, `positive_model.py`, `positive_validator.py`, CLI and
  Next-Gen parsers, most of the guided Browser Lab. Treat this review as covering roughly a quarter of the code.
- Findings marked **reproduced** were confirmed by running the repo code with small scripts; the rest come
  from reading.

## 3. Findings

Severity reflects impact on correct recommendations and on safety of the change path.

### High

| # | Finding | Where | Evidence |
|---|---|---|---|
| H1 | **Any `session*` cookie is detected as Drupal (0.93).** `name.startswith("sess")` matches `session`, `sessionid`, `sess_id`. Real Drupal cookies are `SESS`/`SSESS` plus a 32-char hash. | `technology_detection.py:172` | **Reproduced:** cookies `["session","sessionid"]` return `Drupal 0.93`. |
| H2 | **No confidence or corroboration gate before product rules are added.** Every detected technology in the alias map contributes all its tagged rules, whatever its score. `java` also pulls `struts` and `tomcat` rules. | `signature_workflow.py:144,183-188`; `signature_technology.py:16-31` | **Reproduced:** a Drupal signal at 0.30 selects both Drupal rules; a `JSESSIONID`-only Java signal selects the Struts rule. Combined with H1, an unrelated app with a `session` cookie gets Drupal rules. |
| H3 | **XML/SOAP and GraphQL are detected from body keywords.** `"soap" in body_lower` fires on a soap shop page or a CSS file; `"xml" in content_type` fires on `application/xhtml+xml` and SVG. This drives the XML protection intent (applicability 0.94) and the `has_api` fact. The roadmap flagged this on 2026-09-21 (line 718); it is still unguarded. | `technology_detection.py:243-246`; `generic_protection.py:42,64,97-99` | **Reproduced:** `text/css` with `.soap-dish{}` returns `XML or SOAP 0.78`; an HTML page saying "graphql" returns `GraphQL 0.86`. |
| H4 | **Inline `<script>` capture is dead code.** The `script` tag is consumed by an earlier branch, so the later `elif tag == "script" and not src` branch can never run. `inline_script_parts` is always empty, so "route discovered in inline JavaScript" never fires. | `discovery-worker/app/main.py:61` shadows `:93` | **Reproduced:** parsing `<script>router.navigate("/inline/route")</script>` leaves `inline_script_parts == []`. |

### Medium

| # | Finding | Where |
|---|---|---|
| M1 | ASP.NET Core cookies are never matched. The code intersects a set with the exact name `.aspnetcore`, but real names are `.AspNetCore.Session`, `.AspNetCore.Identity.Application` and so on. **Reproduced:** returns nothing. The pre-refactor code used a substring test. | `technology_detection.py:201` |
| M2 | Framework detection by substring of any asset URL, including images. `reaction.png` matches React; `triangular.min.js` matches Angular. **Reproduced.** The crawler passes every `<img>`, `<link>` and `<source>` URL as an asset. Same pattern for Vue, jQuery, Bootstrap. | `technology_detection.py:218-231`; `discovery-worker/app/main.py:61-64` |
| M3 | Weak single-signal fingerprints: `/administrator` alone gives Joomla 0.94; `Server: Apache-Coyote` (Tomcat) gives Apache HTTP Server 0.92; `invite` plus `import.meta` gives Vite. All **reproduced**. | `technology_detection.py:182,111-112,234` |
| M4 | Detector coverage is small compared with the catalog. About 30 fingerprints against a catalog with hundreds of products (the GUI ships about 80 vendor logos). Everything outside the 14-entry alias map is reachable only by manual product selection. | `signature_technology.py:16-31` |
| M5 | **Name allow-list permits CLI argument injection.** Object names may contain space, `#`, `@`, `=` and a leading `-`, and are interpolated unquoted: `import appfw signatures local:<file> <name> -autoEnableNewSignatures OFF`. A name such as `x -overwrite` passes validation and adds an option. Needs an authenticated operator, but it contradicts the documented "adapter never accepts arbitrary CLI text". | `netscaler-adapter/app/main.py:142-143,512,528,544-546`; `signature_workflow.py:16,341` |
| M6 | Adapter rollback can remove **any** user-defined signature object whose name fits the pattern, not just objects this tool created (the built-ins start with `*` and are protected). No ownership prefix or marker is checked at the adapter. | `netscaler-adapter/app/main.py:540-553` |
| M7 | **BLOCK export is unverified.** The exported XML sets `actions="block"` (lowercased action) with no `log`/`stats`. LOG was proven on the lab; BLOCK was never exported. If `block` alone drops logging, hit counters and violation logs go dark exactly when enforcement starts. Validate on the lab ADC before enabling BLOCK. | `netscaler-adapter/app/main.py:125-126` |
| M8 | Non-guided runtime inspection drives a real Chromium with no request routing. Page JavaScript can issue POST/PUT or third-party requests while rendering. The "render-and-inspect-only" and "passive" claims hold only for the guided lab, which has context-wide GET/HEAD routing. | `runtime-inspector/app/main.py:421-448` |
| M9 | Discovery accepts any `seed_url`, including hosts on the Compose network (`netscaler-adapter:8092`, `postgres`, `control-api`). The worker and the browser sit inside that network, so an operator can make them probe internal services. I saw no service-to-service authentication on the worker or adapter routes I read. | `control-api/app/main.py:1567-1590`; `discovery-worker/app/main.py:136-146` |
| M10 | Query values can reach stored evidence. Asset rows store `"source_page": url` unredacted while everything else goes through `redact_url`. This conflicts with the privacy contract. | `discovery-worker/app/main.py:701,708` |
| M11 | Positive-model draft from a scan has three modelling problems. (a) Concrete paths are stored, so `/product/1`, `/product/2` become separate endpoints. (b) Response header names are modelled as input "fields". (c) Form fields, POST endpoints and auth surfaces are ignored. | `positive_learning.py:233-277,156-159` |
| M12 | Analysis uses stale technology names. The detector emits `PHP`, `Java`, `ASP.NET`, but analysis looks for `php runtime`, `java runtime`, `asp.net runtime`, so the "stateful server runtime" architecture label only fires for Laravel. | `analysis-service/app/main.py:323` |
| M13 | The CSP draft can never include third-party origins. It derives external script/style origins from asset evidence, but discovery drops every off-host asset in `normalize_url`. An enforced draft would break CDN-backed sites. | `analysis-service/app/main.py:340-356`; `discovery-worker/app/main.py:149-155` |
| M14 | Page responses are not size-capped. Assets are limited to 2 MB (`fetch_asset`), but pages use `client.get()` and are read fully into memory. | `discovery-worker/app/main.py:672` |
| M15 | Tests do not protect these paths. `test_generic_signature_groups.py` holds 9 pytest-style functions that `unittest discover` (the README command) runs as **0 tests**; pytest is not a declared dependency. Services each define a package named `app`, so the whole suite cannot run in one process (9 import errors). No CI exists. None of H1-H4, M1-M3 has a test. | `tests/`; no `.github/` |

### Low

- `fingerprint()` has about 60 lines of unreachable legacy code after its `return` (`discovery-worker/app/main.py:349-408`).
- `classify_auth_surface` ignores its `markers` and `buttons` arguments, and tokens like "register" or "authentication" in a heading mark a page as an auth surface (`runtime-inspector/app/main.py:69-99`).
- Sensitive-name regexes disagree between modules: the inspector includes `username|email|otp`, `positive_learning.SECRET_NAME` does not (`:31` in each).
- The crawler follows every in-scope link, including `logout`, `delete`, `unsubscribe`-style GETs. No deny-list (`discovery-worker/app/main.py:684-689`).
- `in_scope` compares hostname only; another port on the same host is in scope (`:136-146`).
- A scan whose requests all failed still counts as "reachable" because `request_error` rows are evidence (`generic_signature_groups.py:99`).
- Per-job endpoints list all runs to find one (`discovery-worker/app/main.py:784,792,820,828`), and `/healthz` runs DDL every call (`:761`).
- Quadratic membership tests while building selections (`signature_workflow.py:187,194,236-240`); fine at 3,208 rules, wasteful as the catalog grows.
- Two parallel recommendation paths exist: the legacy `build_protection_plan` catalog keys and the newer intents (`analysis-service/app/main.py:167-298`).
- `cli_import_commands` ignores two of its arguments (`signature_workflow.py:337`).
- Temp file names collide when two object names normalise to the same string (`netscaler-adapter/app/main.py:137-139`).
- XML is parsed with stdlib `ElementTree` (no entity-expansion protection) for Citrix and admin-supplied files (`sync.py:147`, `rule_catalog.py:216`). Citrix files are signature-verified; admin files are not.
- Static parse keeps only 100 controls and 50 forms per page (`discovery-worker/app/main.py:731`).

### Positive observations

- Raw values and bodies are consistently excluded from evidence, and the positive-model contract rejects them.
- The adapter write routes I read use `fullmatch` for names and accept only numeric rule IDs for XML generation.
- Strict SSH host-key checking is implemented; only the Compose file turns it off.
- Catalog fingerprints and Citrix RSA verification run before a catalog is accepted.
- Technology-tag exclusion keeps unrelated product rules out of the generic path. H2 is the gap in the other direction.

## 4. Recommended fix order

1. **Detector correctness (H1, H3, M1-M3):** anchor the Drupal cookie to `^s?sess[0-9a-f]{32}$`; require a
   matching content type or document root for XML/SOAP; restrict asset matching to script/style URLs and
   path-segment patterns; fix the ASP.NET Core cookie test. Add a negative test for each.
2. **Selection gate (H2):** add a minimum score and a second independent signal family before product-tagged
   rules are auto-selected; show below-threshold technologies as "suggested, not selected". Narrow
   `java -> struts/tomcat` to evidence that names those products.
3. **Crawler (H4, M10, M14):** remove the shadowed branch, redact `source_page`, cap page size, add a
   destructive-path deny-list.
4. **Write path (M5-M7):** restrict object names to `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}$` or quote safely; require
   an ownership prefix on rollback; verify BLOCK XML on the lab and add `log,stats`.
5. **Tests (M15):** convert the pytest-style file, run each service's tests inside its own image in CI.
6. **Then build the missing field layer** (section 5).

## 5. Building the field and positive-model layer

What to add, in order:

1. **Form-aware parsing:** track the open `<form>` so each control carries `form_action`, `form_method`,
   `enctype`; capture `<input form=...>`, `<select>` option counts and `<label>` text.
2. **Field role classifier** (deterministic, with evidence): `search`, `username`, `password`, `email`,
   `phone`, `card`, `file`, `csrf-token`, `numeric-id`, `date`, `free-text`, `hidden`. Use `type`,
   `autocomplete`, `name`, `id`, label and `placeholder`. Return the role plus the signals that produced it.
3. **Endpoint model:** one endpoint per `(method, action path template)`, including POST form actions and
   observed XHR calls, with templated IDs and request-side fields only.
4. **Start URL selection:** entry points reachable without prior state, merged with `sitemap.xml`; keep deep
   URLs as "allowed after navigation".
5. **Compile to NetScaler checks** in LOG/learn mode: Start URL, Form Field Consistency, Field Formats, CSRF
   tagging, Cookie Consistency.

**Decision for you: the SQL injection test.** Two options:

- **Passive (recommended first):** flag which roles are injection-prone (search, free text, numeric IDs, login)
  from the classifier above. No payloads, keeps the roadmap's safety boundary, works on production.
- **Active, opt-in later:** NetScaler Console's own recommender simulates SQLi/XSS and advises against production
  use. If you want the same, make it an explicit per-job switch, restricted to allow-listed or ADC-owned lab
  hosts, with fixed canary probes, rate limits and code-enforced caps. It requires changing the roadmap's
  "no attack payloads" rule.

## 6. Test results on this machine

- 11 test files (58 tests) pass when run one file at a time with
  `python3 -m unittest discover -s tests -p "<file>"`.
- 7 files cannot import in this machine's bare Python (`pydantic` is not installed): `guided_correlation`,
  `nextgen_adapter`, `operator_auth`, `positive_learning`, `positive_model`, `positive_validator`,
  `signature_sync`. They need the service images or a virtualenv, so they were **not run**.
- `test_generic_signature_groups.py` runs 0 tests under `unittest` (section 3, M15).
- Running everything in one process fails with 9 import errors because of the shared `app` package name.
