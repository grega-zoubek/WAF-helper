# NetScaler Next-Gen integration

## Contract used

- Source: `C:\Users\G.Zoubek\Downloads\Nextgen-API-Spec.yaml`
- OpenAPI: `3.0.3`
- Contract version: `0.1.10`
- SHA-256 at implementation time: `88006C4D59EB0C0E4344458CAA5CEB130EEFF41AF325087221536260319FDD8F`
- Server template: `http://{adc-mgmt-ip}/mgmt/api/nextgen/v1`
- Runtime default: HTTPS, because the lab management endpoint is TLS-enabled; override with `NETSCALER_NEXTGEN_SCHEME` or `NETSCALER_NEXTGEN_BASE_URL`.
- Authentication: `POST /login` with `{ "login": { "username", "password", "timeout" } }`; subsequent requests use the returned `sessionid` cookie.

## Implemented read paths

The adapter uses the contract's application model:

- `GET /applications`
- `GET /applications/{application-name}/frontends`
- `GET /applications/{application-name}/backends`
- `GET /applications/{application-name}/routes`
- `GET /applications/{application-name}/health`
- `GET /applications/{application-name}/statistics`

The existing adapter topology routes are compatibility views over the Next-Gen
application response. They are not calls to a legacy management API.

## Explicitly unavailable in this OAS

The supplied contract does not define AppFW profiles, AppFW policies, signature
catalogs, classic CS policies, service groups, or HA-node inventory. The adapter
returns a structured `unsupported-by-oas` result for those read paths and HTTP
501 for the old AppFW write routes. This is intentional fail-closed behavior.

The administrator-mounted rule catalog remains a separate read-only input for
proposal generation; it is not fetched from the ADC by this contract.

## Live verification result

On 2026-09-20, a read-only login attempt from the deployment host to
`https://192.168.11.101/mgmt/api/nextgen/v1/login` returned HTTP 403 from Apache.
The response body was not retained. Until the Next-Gen API is enabled/exposed or
the access policy is corrected, application discovery is blocked and no change
operation is permitted.

## Resume after connectivity loss or reboot

1. Read `WAF_ANALYSIS_ROADMAP.md` and this file.
2. Check the OAS SHA-256; do not silently replace the contract.
3. Verify SSH to `grega@192.168.11.90` using the WAF scanner key.
4. Run `docker compose ps` in `/home/grega/waf-intelligence-repo`.
5. Query `/healthz` and `/api/adc/target` on port 8110/8180.
6. Verify `https://192.168.11.101/mgmt/api/nextgen/v1/login` returns an API response rather than the current Apache 403.
7. Re-run only the read-only application discovery; do not enable writes or create duplicate jobs.
