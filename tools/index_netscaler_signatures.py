"""Build a local, normalized index from exported NetScaler signature XML files.

Raw exports stay local and are never written to the generated index. The index
contains metadata needed for fast applicability matching, not signature pattern
payloads. It is intentionally ignored by Git and can be copied to the adapter's
read-only catalog mount.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "netscaler-adapter"))

from app.rule_catalog import load_rule_catalog  # noqa: E402


def build_index(inputs: list[Path]) -> dict[str, object]:
    rules: list[dict[str, object]] = []
    catalogs: list[dict[str, object]] = []
    seen: set[str] = set()
    for source in inputs:
        loaded = load_rule_catalog(str(source))
        source_rules = loaded.get("rules", []) if isinstance(loaded, dict) else []
        for rule in source_rules:
            if not isinstance(rule, dict):
                continue
            rule_id = str(rule.get("rule_id") or "").strip()
            if not rule_id or rule_id in seen:
                continue
            item = dict(rule)
            item["source_catalog"] = source.name
            rules.append(item)
            seen.add(rule_id)
        catalogs.append({
            "file": source.name,
            "size_bytes": source.stat().st_size if source.is_file() else 0,
            "status": loaded.get("status"),
            "rule_count": loaded.get("rule_count", 0),
            "catalog_fingerprint": loaded.get("catalog_fingerprint"),
        })
    return {
        "schema_version": "1.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_payload_retained": False,
        "catalogs": catalogs,
        "rule_count": len(rules),
        "rules": rules,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Exported NetScaler signature XML/JSON files")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "catalogs" / "netscaler_rule_catalog.json")
    args = parser.parse_args()

    missing = [str(path) for path in args.inputs if not path.is_file()]
    if missing:
        parser.error("input file(s) missing: " + ", ".join(missing))
    index = build_index(args.inputs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "catalog_count": len(index["catalogs"]),
        "rule_count": index["rule_count"],
        "categories": sorted({str(rule.get("category")) for rule in index["rules"] if rule.get("category")}),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
