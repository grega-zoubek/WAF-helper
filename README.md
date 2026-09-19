# WAF Intelligence Scanner

Read-only foundation for an application-specific NetScaler WAF security posture assessment.

The first milestone follows the supplied WAF Scanner plan:

- ingest authoritative CycloneDX SBOM evidence;
- normalize application components;
- evaluate simple version applicability;
- correlate applicable CVEs with NetScaler signature intelligence;
- compare required rules with the observed ADC signature state; and
- emit deterministic, evidence-backed recommendations in monitor mode.

The package deliberately has no arbitrary CLI or NITRO execution path. NetScaler access is
represented by a typed read-only adapter boundary so the existing NetScaler MCP remains the
authoritative ADC control plane.

## Run a sample assessment

```powershell
python -m app.cli examples/assessment.json
```

The input is JSON and contains an application, components, CVEs, signature mappings, and the
observed signature state returned by the ADC adapter. The output is a JSON assessment.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

This is the read-only Phase 1 foundation. Topology resolution, traffic/API evidence, NVD/KEV
ingestion, persistence, and approved change planning are subsequent milestones.

## Use the existing MCP server

The only supported integration is the existing NetScaler MCP service at
`http://192.168.11.90:8000/mcp`, which keeps NetScaler credentials inside the MCP host and
translates approved plain-English automation intent into supported Next-Gen API operations. The
scanner verifies that the MCP-reported appliance is NetScaler 14.1 before it proceeds:

```powershell
python -m app.mcp_discover
```

The legacy direct-NITRO adapter in `app/netscaler/nitro.py` is not part of the normal scanner path.
