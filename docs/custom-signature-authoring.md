# Custom signature authoring

The control API now supports proposal-only authoring of local NetScaler Web App Firewall rules:

```text
POST /api/custom-signatures/drafts
GET  /api/custom-signatures/drafts?job_id=<discovery-job-id>
GET  /api/custom-signatures/drafts/<draft-id>
```

The request must reference a completed discovery job and include an operator-supplied pattern plus at least one positive and one negative offline test case. The discovery profile is captured as applicability context; technology markers, routes, and fields are never converted into an attack pattern automatically.

New rules are forced to `enabled=false` and `actions=["LOG"]`. Local rule IDs are allocated in NetScaler's documented `1000000-1999999` range. The result contains the validated rule specification, detection context, a stable draft fingerprint, and an import-command template.

Native XML is intentionally not generated yet. Before enabling native export or an ADC write adapter, provide an appliance-exported user-defined signature template and validate the exact XML schema and pattern encoding on the lab ADC. Until then, `write_enabled=false`, `proposal_only=true`, and `changes_applied=false` remain mandatory.

Recovery after connectivity loss or reboot: verify the server checkout revision, query `http://192.168.11.90:8110/healthz`, confirm `waf-intelligence-control-api-1` and Postgres are healthy, and retrieve the draft by its ID. Do not resend an ADC import or enable writes as a recovery action.
