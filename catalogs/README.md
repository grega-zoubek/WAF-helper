# Optional provider rule catalogs

Place an administrator-approved, read-only NetScaler rule-level export here as
`netscaler_rule_catalog.json` or XML. The adapter reads normalized rule metadata
only and never retains the raw file in API responses or the database.

Do not commit vendor exports, credentials, session data, or proprietary raw
signature files to Git. The directory is mounted read-only into the adapter.
