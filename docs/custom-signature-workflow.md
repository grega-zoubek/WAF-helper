# Detection-driven custom signature workflow

The workflow is intentionally split into verified stages:

1. `signature-sync` checks Citrix's signed mapping every hour and stores the verified latest normalized catalog at `signature-cache/upstream/index/latest.json`.
2. A completed discovery job is evaluated against that latest catalog. Generic protection intents and technology tags produce exact rule IDs; the catalog fingerprint and integrity metadata are retained with the proposal.
3. `POST /api/custom-signature-sets/prepare` creates a draft. The default object name includes the discovered hostname, for example `waf-www-ess-gov-si-bdac3c4c`, and the administrator can change it.
4. `PATCH /api/custom-signature-sets/{id}` lets the administrator edit the exact rule IDs and choose one action for enabled rules: `LOG` or `BLOCK`.
5. `POST /api/custom-signature-sets/{id}/approve` requires `APPROVE CUSTOM SIGNATURE SET` and the exact plan fingerprint.
6. `POST /api/custom-signature-sets/{id}/preflight` rechecks the latest catalog fingerprint, rule IDs, object-name collision, and action mode.
7. After the write flag is deliberately enabled, `POST /api/custom-signature-sets/{id}/export` requires `ENABLE WRITE` and generates a native XML subset containing only the approved rule IDs. The adapter uploads that file temporarily over the allow-listed SSH/SFTP path, imports it with the ADC-supported `local:<filename>` command, saves the configuration, and removes the temporary file.
8. The rollback endpoint removes only the exported object after confirming it is not referenced by the current AppFW profile or policy inventory.

The current adapter does not accept arbitrary CLI text. It constructs the import command from a validated object name and a generated temporary filename; the XML is built only from validated numeric rule IDs and the selected action. All new rules start enabled with the selected `LOG` or `BLOCK` action because they are imported as reviewed exact IDs. Temporary files are removed after the CLI transaction.

Recovery after connectivity loss or reboot: verify the local/server revision, confirm `signature-sync`, `control-api`, `discovery-worker`, `netscaler-adapter`, and Postgres are healthy, query `/healthz`, inspect the signature-sync state and proposal by ID, and rerun preflight before any export. Do not bypass the catalog fingerprint, approval, preflight, or exact `ENABLE WRITE` guard.
