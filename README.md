# WAF Intelligence Platform

Initial microservice foundation for the NetScaler WAF intelligence platform.

## Services

- `frontend`: GUI shell on port 8180
- `control-api`: platform API and job coordinator on port 8110
- `discovery-worker`: isolated discovery job worker
- `netscaler-adapter`: bounded ADC integration service
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

The first release is read-only and preview-oriented. It does not expose arbitrary
CLI or NITRO operations and does not apply WAF changes automatically.

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
