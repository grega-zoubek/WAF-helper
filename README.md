# WAF Intelligence Platform

Initial microservice foundation for the NetScaler WAF intelligence platform.

## Services

- `frontend`: GUI shell on port 8180
- `control-api`: platform API and job coordinator on port 8110
- `discovery-worker`: isolated discovery job worker
- `netscaler-adapter`: bounded ADC integration service
- `postgres`: initial persistence layer

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

Port 8110 was selected after confirming that the existing services use 8000,
8080, and 6274. Recheck before deployment if another service is added.
