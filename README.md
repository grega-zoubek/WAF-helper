# WAF Intelligence Platform

Initial microservice foundation for the NetScaler WAF intelligence platform.

## Services

- `frontend`: GUI shell on port 8180
- `control-api`: platform API and job coordinator on port 8110
- `discovery-worker`: isolated discovery job worker
- `netscaler-adapter`: bounded ADC integration service
- `signature-sync`: hourly, read-only Citrix signature-source synchronizer and indexer
- `postgres`: initial persistence layer

Application analysis uses passive, deterministic technology fingerprints. It keeps
application platforms separate from generic server/runtime and form signals, records
the evidence family and exposed version when available, and corroborates signals from
paths, headers, cookies, HTML metadata, document markers, and assets. The initial catalog
includes Microsoft Exchange OWA, WordPress, Drupal, Joomla, Magento, IIS, nginx, Apache,
PHP, Java, ASP.NET, Laravel, Angular, React, Next.js, Nuxt, jQuery, Bootstrap, and API
protocol markers.

Protection planning is provider-neutral. The analysis service derives generic protection
intents from observed application surfaces—baseline attack signatures, input/injection,
XSS, sessions/authentication, uploads, XML services, and optional runtime/product
enrichment. A provider adapter must resolve those intents against the installed NetScaler
catalog before selecting rule IDs. Predefined policy rules are authoritative; an optional
AI advisor may explain or rank evidence but cannot invent unavailable rules or apply ADC
changes. The default automation mode is proposal-only.

The current signature-only phase resolves five generic groups to exact untagged catalog
rules: HTTP protocol compliance, canonicalization/evasion, injection, XSS, and path/file
attacks. Product- and runtime-tagged rules remain controlled by the detected technology
selectors. File-upload rules require upload evidence; path-traversal rules do not. The
selection response reports group confidence, exact rule counts, match reasons, and a
`positive_model.enabled=false` marker. Positive security, allowlisting, schema,
behavioral, bot, and rate-limit controls are deliberately deferred.

Positive security phase 1 defines a versioned, value-minimizing application
model contract in `services/control-api/app/positive_model.py`, with privacy
and lifecycle rules in `docs/positive-security-model-contract.md`. This is a
schema foundation only; it does not collect or enforce positive policies. The
existing Playwright runtime inspector remains headless and read-only; guided
browser interaction and policy compilation are future phases.

Each generic group is also returned as a closed-by-default selection tree. The tree is
grouped into catalog-derived subgroups (for example SQL/command/LDAP/NoSQL injection,
path traversal/file upload, XSS catalog categories, and protocol/evasion families) and
contains individual rule checkboxes. The GUI sends the resulting exact `selected_rule_ids`
to both recommendation and prepare endpoints; deselected rules remain visible as
unchecked candidates and are not exported.

Within `WEB-MISC`, subgrouping prefers a catalog product-index match and otherwise
extracts a software name from the rule description. Cisco ISE, Infoblox NETMRI, and
Ivanti products therefore appear as software groups. Rules without a reliable software
name are grouped by protection family, such as traversal, sensitive-file disclosure,
command execution, availability, authentication, or reconnaissance, rather than under
a single undifferentiated `WEB-MISC` bucket.

Rules containing CVE references are additionally cross-listed under a `CVE references`
tree. CVE entries reuse the original rule IDs and selection state; deselecting a rule in
the CVE tree removes it from every other group as well. CVE cross-listing does not create
duplicate export rules.

The `signature-sync` service checks Citrix's published `SignaturesMapping.xml`
hourly, defaults to the ADC 14.1 build 0 entry, verifies the published SHA-1,
downloads a changed signature XML atomically, and builds a normalized upstream
index. Its data is kept under the ignored `signature-cache/upstream/` directory;
it does not overwrite the reviewed `catalogs/netscaler_rule_catalog.json` or
apply anything to the ADC. The Citrix RSA public key is provisioned separately
as `signature-cache/citrix_public.pem`; the service verifies the published
`.digest` signature over the XML using that key. The source URL, target
release/build, interval, and data directory are configurable with `SIGNATURE_*`
environment variables. The internal service exposes `/healthz`, `/status`, and
a manual `POST /run` for operations and testing.

The first release is read-only and preview-oriented. NetScaler topology discovery
uses the supplied NetScaler Next-Gen API contract (`/mgmt/api/nextgen/v1`) with
cookie-based login. The supplied contract does not expose AppFW profiles or
signature catalogs, so those resources remain explicitly unavailable and the
adapter never falls back to an older API. WAF changes are not applied automatically.

Technology profiles also expose `signature_technology_context` from the reviewed
normalized signature index. It correlates already-detected web-application and
server/runtime technologies with matching NetScaler signature tags, categories,
rule counts, and example IDs. This is catalog applicability context only; a WAF
signature category cannot independently confirm that a target runs that technology.

## Deployment

1. Create `secrets/netscaler_password` with the ADC password and restrict it to
   the deployment account.
2. Set `WAF_DB_PASSWORD` in an untracked deployment `.env` file. Do not commit
   that file to Git.
3. Run `docker compose up -d --build`.
4. Open `http://192.168.11.90:8180` for the GUI.
5. Check `http://192.168.11.90:8110/healthz` for the API.

Technology detector tests can be run locally with the bundled Python runtime:

```powershell
python -m unittest discover -s tests -p "test_technology_detection.py" -v
```

Port 8110 was selected after confirming that the existing services use 8000,
8080, and 6274. Recheck before deployment if another service is added.
