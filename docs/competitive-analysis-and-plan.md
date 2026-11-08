# Competitive analysis and recommended plan

Prepared 2026-11-08 from `WAF_ANALYSIS_ROADMAP.md`, the `docs/` set, `docker-compose.yml`, a few targeted
code checks, and web research on competing products. This is a recommendation, not a commitment.
Evidence quality notes are in the last section; read them before quoting any competitor claim.

## 1. Bottom line

**What the project is:** a passive, evidence-driven way to decide *which* NetScaler AppFW signature rules
an application needs, and to walk those rules from LOG to BLOCK with approvals, preflight and rollback.

**Where it is strong:** exact rule-level selection with technology-aware exclusions, a verified hourly
Citrix catalog, GET-only discovery (safe on production), and a guarded export/bind/rollback path.
No competitor I found does rule-level, scan-driven selection *for NetScaler* with this safety model.

**Where it is exposed:** every serious competitor closes the loop *after* deployment. They watch what the
WAF does on real traffic, suggest scoped exceptions, and tell you when a rule is ready to block. This
project stops at "LOG-bound, here is a hit counter". NetScaler Console (ADM) already ships a scan-based
recommender and a learning engine, so the incumbent covers the same first step.

**Recommendation, in order:**

1. **Harden and stabilise first** (Phase 0). Write mode is on by default, SSH host-key checking is off in
   compose, there is no CI, and the roadmap itself flags unresolved detector false positives.
2. **Close the feedback loop** (Phase 1): ingest AppFW violations, cluster them against the scan's
   known-good route inventory, propose *scoped* exceptions, and score LOG-to-BLOCK readiness.
3. **Add security-check recommendations and compile the positive model** (Phase 2): this is feature parity
   with the incumbent's recommender and uses evidence you already collect.
4. Then continuous posture, signature-release deltas, and IaC export (Phases 3-4).

**Positioning to hold onto:** *safe, explainable, rule-level WAF onboarding and tuning for NetScaler.
Works before you have traffic, shows why each rule is selected, and proves readiness before BLOCK.*

## 2. Where the project is today

### Built (per roadmap, docs and code)

| Area | State |
|---|---|
| Discovery | Passive crawl, tech fingerprints, static JS endpoint candidates, Playwright runtime inspection |
| Analysis | Provider-neutral protection intents with applicability scores |
| Catalog | Hourly Citrix sync with SHA-1 and RSA verification; 3,208 rules at v183 |
| Selection | Exact rule IDs, tech-aware exclusion, group/subgroup/CVE trees, Regex Rulz |
| Change path | prepare, edit, approve, preflight, `ENABLE WRITE` export, LOG-only profile/policy/vServer bind, rollback |
| Operate | Protection status, hit counters, promote-to-BLOCK and exception *drafts* |
| Positive security | Versioned contract, dry-run validator, Browser Lab, candidate review, observe-only compile preview |
| Platform | TLS frontend, operator session + CSRF, 8 containers |

### Deliberately deferred (roadmap)

Positive-model enforcement, schema/allowlist, bot, rate-limit, and the "security-check workstream"
(start URL, cookie consistency, form-field consistency, field formats, CSRF, file upload, XML/JSON).

### Gaps I verified in the repo

- **No violation or log ingestion.** A search of `services/` finds no syslog/AppFlow/learning-data code.
  Hit data is per policy or profile name only (`cli_inventory.py:368-458`), not per rule.
- **Exceptions are manual.** `build_exception_selection` removes rule IDs the operator typed in
  (`protection_lifecycle.py`); nothing suggests which rules are noisy or where.
- **No CI.** There is no `.github/` directory. The roadmap notes `test_operator_auth` could not run locally
  because `httpx` was missing.
- **Write mode on, host keys off.** `docker-compose.yml` sets `NETSCALER_WRITE_ENABLED: "true"` for two
  services and `NETSCALER_SSH_STRICT_HOST_KEY: "false"`. The adapter already supports strict checking and a
  known-hosts file (`ssh_inventory.py:47-54`), so this is configuration, not missing code.
- **Detector false-positive risk remains plausible.** The roadmap (line 718) reports XML/SOAP promoted from
  CSS responses. `technology_detection.py:245` still triggers on `"soap" in body_lower` with no
  content-type guard. Confirm during the code review.
- **One-shot scans.** No scheduled re-scan, no diff between scans, no ADC drift check.
- **Roadmap doubles as a runbook.** 94 KB of dated checkpoints with lab IPs, Windows paths and recovery
  commands. Useful history, poor as a forward plan.

## 3. Competitive landscape

Confidence column: **H** = read the vendor's own docs, **M** = vendor material through search summaries,
**L** = third-party or marketing only.

| Competitor | Relevant capability | Takeaway for this project | Conf. |
|---|---|---|---|
| **NetScaler Console (ADM)** [WAF recommendation](https://docs.netscaler.com/en-us/netscaler-console-service/analytics/security/waf-recommendation), [WAF learning](https://docs.netscaler.com/en-us/netscaler-console-service/analytics/security/waf-learning) | Scan from a public domain and start URL with depth and optional login; active SQLi/XSS simulation (recommended outside production); recommends signatures by detected tech and security checks (Buffer Overflow, Field Formats, Credit Card, Cookie Consistency, HTML SQLi/XSS, Form Field Consistency, CSRF tagging); applies via StyleBooks; needs premium licence and an LB vServer. Separate learning engine produces relaxation rules for admin review. | Direct incumbent. Differentiate on rule-level precision, no attack simulation, LOG-first lifecycle and independence from ADM. Match its security-check coverage. | M |
| **F5 Advanced WAF** [Policy Builder suggestions](https://clouddocs.f5.com/bigip-next/20-0-1/waf_management/cm_awaf_how_to_learning_suggestion.html), [tuning guide](https://www.peakhour.io/blog/tag/waf-tuning/) | Transparent mode, then learning suggestions rated 1-5 (1 likely false positive, 5 likely attack); guidance to scope each exception to the URL, parameter or cookie. | The suggestion + rating + scoped-exception pattern is the reference workflow. | M |
| **Akamai App & API Protector** [Adaptive Security Engine](https://www.akamai.com/blog/security/the-adaptive-security-engine-a-quantum-leap-forward-for-application) | Continuous ML analysis yields per-policy tuning recommendations, one-click accept, also via API, CLI and Terraform; manual evaluation mode; "zero-touch" acceptance stated as a plan. | Recommendations should be automatable through APIs. Zero-touch acceptance is the wrong model for this tool. | M |
| **Cloudflare** [Application/Schema Profiles](https://developers.cloudflare.com/waf/detections/application-profiles/get-started/), [Attack Score](https://developers.cloudflare.com/waf/about/waf-attack-score/) | Learns per-operation schemas from traffic (1,000 qualifying 2xx requests for fields, 10,000 for boundaries, weekly relearn) or an uploaded OpenAPI file. Always-on validation only *annotates*; blocking needs a rule you write. Documented limits: no multipart, GraphQL or XML; no required-field enforcement. Closed beta for non-API-Security Enterprise. | Observe-first positive security with explicit scope limits is credible. Copy the limits and the "annotate, then enforce" separation. | H |
| **Cloudflare adaptive AI testing** [blog](https://blog.cloudflare.com/adaptive-ai-waf-testing/) | LLM proposes mutations of already-blocked exploits; code (not the model) enforces host allowlist, redirect disabling and attempt caps; 45 scenarios, 1,107 attempts; candidate rules checked for false-positive risk before deploy; models cannot deploy. | Model for an opt-in lab validation harness and for the guardrails any AI feature needs. | H |
| **AWS WAF** [Count-to-Block](https://repost.aws/knowledge-center/waf-managed-rules-count-to-block), [customising managed rules](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) | Count mode first; move one rule at a time to Block; exceptions through labels, scope-down statements or excluding request components. | Confirms the LOG-first lifecycle and the "one rule at a time, with rollback" promotion discipline. | M |
| **OWASP CRS / Coraza** [tuning docs](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), [netnea](https://www.netnea.com/cms/?p=951), [AutoEx](https://www.mdpi.com/2079-9292/15/9/1877/htm) | DetectionOnly, read audit log, write narrow exclusions; community scripts generate exclusions from alerts; AutoEx is a research framework for automatic exclusion generation. | Exclusion generation from alert logs is a known, tractable problem. No NetScaler equivalent surfaced. | M |
| **FortiWeb** [API protection docs](https://docs.fortinet.com/document/fortiweb/8.0.4/administration-guide/98060) | ML API discovery and schema protection; model trains after 100 samples per domain by default; continuous learning since 7.4; models are version-specific. | Learned models need a sample threshold, restricted paths and version awareness. | M |
| **Imperva** [Attack Analytics](https://www.imperva.com/blog/avoid-alert-fatigue-how-to-automatically-get-rid-of-waf-false-positive/) | Groups alerts into incidents and classifies likely false positives with a supervised model; API discovery inventory. | Cluster before judging single requests. | L |
| **open-appsec** [overview](https://www.openappsec.io/post/how-open-appsec-machine-learning-pre-emptively-block-attacks-watch-our-deep-dive-video) | Signature-less ML WAF, free community edition, runs on ingress/NGINX/Envoy. Vendor claims little tuning. | Not a NetScaler competitor, but it sets customer expectations for "no tuning". Do not chase it. | L |
| **Wallarm GoTestWAF** [overview](https://www.wallarm.com/gotestwaf/overview) | Open-source harness with attack and true-negative (false-positive) payload sets. | Template for post-deploy efficacy and false-positive tests. | M |
| **CVE-to-rule AI** [Miggo](https://www.miggo.io/post/from-cve-to-waf-rule-in-minutes-what-we-learned-building-an-ai-pipeline-that-ships), [Edgescan](https://www.edgescan.com/features/ai-powered-waf-rule-generation/) | LLM pipelines write vendor-native rules from CVEs; separate reviewer model; Edgescan keeps a human review gate. | Citrix already ships CVE signatures. The gap is *telling each app which new ones apply*. | L |

Also relevant: a [June 2026 paper](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=7398219) argues AI makes false-positive
suppression more accurate while cheapening novel payloads, so manual tuning stays necessary but insufficient.

### NetScaler-specific building blocks worth using

- API schema validation via imported specs, available on 14.1 build 21.57 and later
  ([docs](https://docs.citrix.com/en-us/citrix-adc/current-release/aaa-tm/waf-protection-endpoint-urls)).
  This is a plausible compile target for the positive model's REST/JSON part. Verify on the lab ADC.
- A WAF StyleBook exists, but it attaches an *existing* signature object and cannot create one
  ([docs](https://docs.netscaler.com/en-us/netscaler-application-delivery-management-software/current-release/stylebooks/how-to-use-default-stylebooks/web-application-stylebook.html)).
  Your SFTP-import path fills a real gap.
- A [Terraform provider](https://beta.pkg.go.dev/github.com/citrix/terraform-provider-citrixadc/citrixadc) exists
  with `citrixadc_appfwprofile` resources. I could not confirm a signature-object resource.
- Citrix publishes per-CVE WAF signature updates (for example the
  [React2Shell article](https://support.citrix.com/external/article/CTX695819/netscaler-waf-signature-against-react2sh.html)).

## 4. Gap analysis

| Capability | Market norm | This tool today | Verdict |
|---|---|---|---|
| Pre-traffic scan to rule recommendation | NetScaler Console (active SQLi/XSS) | Passive, exact rule IDs, tech-aware exclusion | **Strength** |
| Non-signature security-check recommendation | Console recommends 8+ checks | Deferred | **Gap, high** |
| Learning from real violations to suggest scoped exceptions | F5, Akamai, Console, FortiWeb, CRS tooling | None; manual rule-ID removal | **Gap, highest** |
| LOG-to-BLOCK readiness guidance | AWS, Cloudflare, F5 guidance | Manual promote draft, policy-level hit counts | **Gap, high** |
| Positive security from schema/traffic | Cloudflare, FortiWeb, Imperva | Contract, validator, observe-only candidate, no ADC compile | **Partial** |
| Continuous re-learn and drift | Cloudflare weekly, FortiWeb continuous, Akamai | One-shot scans, no drift check | **Gap, medium** |
| Post-deploy validation | GoTestWAF, Cloudflare adaptive testing | One benign request plus hit count | **Gap, medium** |
| Per-app CVE/signature-release relevance | Citrix signature notes only | Hourly sync, CVE tree, no per-app delta | **Opportunity, cheap** |
| IaC/automation export | Akamai Terraform/CLI/API, F5, StyleBooks | Imperative SSH/SFTP writes | **Gap, medium** |
| Roles, four-eyes, audit | Standard | Single operator credential | **Gap, medium** |
| Fleet coverage view | Console unified security dashboard | Per-job views | **Gap, cheap** |
| Bot, rate-limit, API protection | All | Deferred | **Defer** |
| ML anomaly or signature-less engine | open-appsec, FortiWeb, Cloudflare | None | **Do not build** |

## 5. Recommended plan

Sizes assume one engineer: **S** = days, **M** = one to two weeks, **L** = three or more weeks. These are
rough and should be re-estimated after the code review.

### Phase 0: Stabilise and de-risk (do before any new write feature)

| # | Item | Size |
|---|---|---|
| 0.1 | Split the roadmap into a forward `ROADMAP.md`, a `CHANGELOG.md`, and a `RUNBOOK.md` that holds lab IPs, paths and recovery steps | S |
| 0.2 | Safe defaults: `NETSCALER_WRITE_ENABLED` defaults to `false` via `.env`; enable `NETSCALER_SSH_STRICT_HOST_KEY` and a known-hosts file (code already supports it); move ADC host and user into `.env.example` | S |
| 0.3 | CI (GitHub Actions): build each service image and run the tests inside it, `docker compose config`, frontend JS syntax check | S-M |
| 0.4 | Detector regression fixtures: saved HTML/headers for Juice Shop, ESS and RTVSLO; fix the XML/SOAP content-type guard, WordPress vs TYPO3 corroboration and password-marker classification the roadmap flagged | M |
| 0.5 | Roles (viewer, analyst, approver, applier) and a different-user approval requirement for BLOCK; an audit record with operator identity on every ADC write | M |
| 0.6 | Scan authorisation guard: Browser Lab clicks and synthetic probes only on allow-listed hosts or hosts that correlate to a managed vServer. The roadmap shows probes run against third-party public sites | S-M |
| 0.7 | Least-privilege ADC accounts: read-only account for inventory; write account limited by command policy to the exact commands the adapter builds | S-M (needs ADC admin) |

**Exit:** CI green on every push; a fresh `docker compose up` cannot write to the ADC; detector fixtures pass.

### Phase 1: Close the feedback loop (the main differentiator)

| # | Item | Size |
|---|---|---|
| 1.0 | **Spike:** find the supported way to get per-rule AppFW violation events off the lab ADC (syslog target, log file over SFTP, AppFlow, or Console). Decide the ingestion path before building anything | S |
| 1.1 | Violation ingestion with redaction: store rule ID, check, method, path template, parameter *name*, count, time bucket and distinct-client count. Never values, consistent with the privacy contract | M |
| 1.2 | Explainable classifier: join violation clusters to the scan's known-good routes and fields; give each cluster an F5-style 1-5 rating with visible reasons (rules first, ML only if rules prove insufficient) | M |
| 1.3 | Scoped exception generator: propose the narrowest exception NetScaler supports (relaxation rule, policy-expression scope, per-rule action). **Verify which of these exist for signatures on 14.1 before designing** | M |
| 1.4 | Promotion readiness: minimum soak time and request volume, no unreviewed false-positive clusters, promote rule groups in stages (critical and CVE rules first), never the whole set at once | M |
| 1.5 | Post-change canary: replay the crawl's GET corpus through the ADC after bind or promotion and compare hit counts; recommend (never auto-apply) rollback on regression | S-M |

**Exit (lab):** Juice Shop in LOG with operator-generated test traffic produces clustered suggestions, an exception
draft, a staged promotion of a rule subset, and a tested rollback.

### Phase 2: Security-check recommendations and positive-model compile

Can start in parallel with Phase 1; it touches different services and needs no new data source.

| # | Item | Size |
|---|---|---|
| 2.1 | Security-check recommender in LOG/learn mode: Start URL, Content-Type, Form Field Consistency, Field Formats, Cookie Consistency, CSRF Form Tagging, Buffer Overflow, Credit Card, JSON SQL/XSS/command injection. Each with intent, evidence, false-positive risk and a "why" panel like the signature tree. Verify exact check names on the lab ADC | L |
| 2.2 | Compile the positive model to NetScaler: JSON/REST to an OpenAPI export and API Spec Import; HTML forms to field formats and consistency checks. Still observe/LOG only | L |
| 2.3 | More evidence sources: OpenAPI upload, HAR import (redacted), read-only NetScaler learning data. The contract already lists these as source kinds. Combine sources into confidence rather than counting samples | M |
| 2.4 | Lifecycle transitions with audit: `discovered > candidate > reviewed > staged > enforced > retired`; `enforced` requires Phase 1 soak evidence | M |

**Scope limit:** HTML forms and JSON only. Cloudflare also leaves out multipart, GraphQL and XML.

**Exit:** Juice Shop (REST/JSON) and one form-heavy app yield a security-check proposal and a compiled model that
import on the lab ADC in LOG mode with no regressions on the benign replay.

### Phase 3: Continuous posture and signature intelligence

| # | Item | Size |
|---|---|---|
| 3.1 | Scheduled re-scan and diff (routes, forms, tech, auth surfaces); "application changed" refreshes the proposal; stale-scan badges | M |
| 3.2 | **Signature-release delta per app:** when `signature-sync` moves from v183 to the next version, list new, removed and changed rules that apply to each scanned app's technologies and intents; propose a LOG addition | M |
| 3.3 | Coverage posture dashboard over all vServers: no AppFW, AppFW without policy, LOG, BLOCK; scan age; open suggestions | S-M |
| 3.4 | ADC drift detection against the last applied plan fingerprint (adopt or reconverge); propose cleanup of stale signature objects, since each export creates one object per host | M |
| 3.5 | Notifications (email, Slack, webhook) for new suggestions, drift and release deltas | S |

### Phase 4: Integrations and optional bets (decisions needed)

| # | Item | Size |
|---|---|---|
| 4.1 | Export a plan as Terraform, Ansible, NITRO JSON, CLI script or a Git pull request. Enables a **read-only deployment mode** that removes ADC credentials with write rights from the tool | M |
| 4.2 | NetScaler Console interop spike: read its learning relaxations and security insight, or export to a StyleBook. Worth it only if your users already own Console | S spike |
| 4.3 | Opt-in lab efficacy harness: GoTestWAF-style attack and false-positive corpora, later Cloudflare-style LLM mutation. **Requires changing the "no attack payloads" boundary**, so see decisions below | L |
| 4.4 | Advisory AI: explain recommendations, summarise violation clusters, draft custom-signature candidates with offline positive and negative tests. Separate reviewer, no values sent to external models, model never selects or applies rules | M |
| 4.5 | Second provider adapter (CRS/Coraza exclusions or a cloud WAF) | L, only if scope should broaden |

## 6. What not to build

- **An ML anomaly or signature-less engine.** open-appsec, FortiWeb and Cloudflare Attack Score need traffic at
  scale and years of tuning. Your edge is explainable rule selection.
- **Zero-touch acceptance or automatic BLOCK.** Akamai floats it for a managed edge. For an admin-run ADC the risk
  outweighs the convenience; keep human approval at every enforcement step.
- **Attack simulation in the production path.** NetScaler Console does this and advises against production use.
  Passive-only is your safety advantage.
- **AI choosing or applying rules.** Keep the existing rule: predefined catalog is authoritative, AI is advisory.
- **Bot, rate-limit and general API-security features** before the feedback loop exists. NetScaler has its own
  [bot detection](https://docs.netscaler.com/us/en/citrix-adc/current-release/bot-management/bot-detection.html);
  integrate later rather than rebuild.

## 7. Risks and decisions for you

**Decisions that change the plan**

1. **Safety boundary.** Allow an opt-in, lab-only validation mode that sends attack payloads (item 4.3)? Without
   it, post-deploy efficacy stays unproven and you rely on benign replay only.
2. **Primary user.** NetScaler admins *with* Console or *without*? With Console, interop (4.2) matters and you
   compete head-on; without, you are the only recommender they have.
3. **Write mode as product or lab feature.** Guarded write is powerful but makes the tool a high-value target.
   Export-first (4.1) with write as an optional module is the lower-risk shape.
4. **Provider scope.** Stay NetScaler-only, or keep "provider-neutral" as a real goal (4.5)?
5. **Deployment shape.** Single lab instance, or multi-team service? This decides how much RBAC and tenancy
   Phase 0.5 needs.

**Risks**

- Phase 1 depends on getting per-rule violation data from the ADC. Spike 1.0 comes first; if only counters are
  available, the feedback loop shrinks to promotion readiness without exception suggestions.
- Learned positive models are version-specific on some products (FortiWeb) and noisy when "successful" traffic
  includes scanners (Cloudflare warns of this). Keep models reviewable and stay in observe mode until soaked.
- Crawl-only evidence is single-session and low confidence. Multi-source evidence (2.3) is how it improves.
- `control-api/app/main.py` (3,335 lines) and `frontend/index.html` (2,075 lines) concentrate risk. Plan a split
  after the code review rather than before.

## 8. Evidence notes

- **NetScaler Console pages** were read through a summarising fetch tool; the verbatim page text was mostly
  navigation. Details such as "premium licence", "LB vServer only" and the security-check list are from that
  summary. One input description ("must be a valid IPv4 address" vs "public domain") was internally inconsistent.
  Re-read the live pages before relying on them in a customer conversation.
- **Cloudflare** details come from pages dated September-October 2026, read in full by a fetch agent.
- **Imperva, Akamai and Fortinet** coverage is thin: vendor blogs and search summaries, no independent test
  results. Treat their efficacy numbers as claims.
- **Several sources are third-party** (peakhour, securityscientist, openappsec blog, ogma). I used them for
  workflow patterns, not for facts about a vendor's product.
- **Not researched:** pricing, market share, WAAP products outside the list above, and NetScaler 15.x specifics.
- **Code checks** were targeted greps and short reads, not a code review. Items marked "confirm during the code
  review" are unverified beyond what is cited.
