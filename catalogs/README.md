# Optional provider rule catalogs

Place an administrator-approved, read-only NetScaler rule-level export here as
`netscaler_rule_catalog.json` or XML. The adapter reads normalized rule metadata
only and never retains the raw file in API responses or the database.

Do not commit vendor exports, credentials, session data, or proprietary raw
signature files to Git. The directory is mounted read-only into the adapter.

## Local export and indexing workflow

1. Export the NetScaler signature objects from the Web App Firewall GUI into a
   local directory such as `signature-cache/raw/`.
2. Run:

   ```text
   python tools/index_netscaler_signatures.py signature-cache/raw/default_signatures.xml signature-cache/raw/xpath_injection_patterns.xml
   ```

3. Review the printed catalog and rule counts. The generated
   `catalogs/netscaler_rule_catalog.json` contains normalized metadata only:
   rule IDs, categories, versions, enabled state, actions, descriptions,
   references, match types, locations, and derived attack classes. It does not
   retain pattern payloads and is intentionally ignored by Git.

The generated index can be copied to the server checkout's `catalogs/`
directory and mounted read-only into the adapter. The adapter then exposes the
rule count and fingerprint through `/api/adc/signatures/rules` for exact,
fail-closed applicability matching.
