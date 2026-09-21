"""Correlate detected technologies with normalized WAF signature metadata."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


DEFAULT_INDEX_FILE = "/run/signature-index/WAF_Default.json"

# These aliases map the scanner's canonical technology keys to tags derived from
# the normalized NetScaler signature catalog. A catalog match is contextual
# support only; it is never treated as independent HTTP detection evidence.
TECHNOLOGY_TAG_ALIASES: dict[str, set[str]] = {
    "microsoft-exchange-owa": {"exchange", "owa"},
    "microsoft-iis": {"iis", "asp", "asp.net"},
    "apache-http-server": {"apache"},
    "asp-net": {"asp", "asp.net"},
    "asp-net-core": {"asp", "asp.net"},
    "express-node-js": {"node", "express"},
    "wordpress": {"wordpress"},
    "drupal": {"drupal"},
    "joomla": {"joomla"},
    "magento": {"magento"},
    "php": {"php"},
    "java": {"java", "tomcat", "struts"},
    "laravel": {"laravel"},
    "nginx": {"nginx"},
}


def _index_path(path_value: str | None = None) -> Path:
    return Path(path_value or os.getenv("SIGNATURE_TECHNOLOGY_INDEX_FILE", DEFAULT_INDEX_FILE))


def _load_index(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "configured-file-missing"
    except (OSError, json.JSONDecodeError):
        return None, "invalid-index"
    if not isinstance(value, dict) or not isinstance(value.get("rules"), list):
        return None, "invalid-index"
    return value, None


def build_signature_technology_context(
    technologies: list[dict[str, Any]],
    *,
    index_path: str | None = None,
) -> dict[str, Any]:
    """Return signature-backed context for technologies already detected.

    The returned matches describe which normalized signature rules are relevant
    to an observed technology. They are deliberately marked as contextual and
    are not added to the detector's evidence or confidence score.
    """

    path = _index_path(index_path)
    catalog, error = _load_index(path)
    if error:
        return {
            "status": error,
            "source": "netscaler-signature-index",
            "index_file": str(path),
            "technology_matches": [],
            "is_detection_evidence": False,
        }

    assert catalog is not None
    tag_stats: dict[str, dict[str, Any]] = {}
    for rule in catalog.get("rules", []):
        if not isinstance(rule, dict):
            continue
        category = str(rule.get("category") or "").strip().casefold()
        rule_id = str(rule.get("rule_id") or "").strip()
        for tag_value in rule.get("technology_tags", []):
            tag = str(tag_value).strip().casefold()
            if not tag:
                continue
            stats = tag_stats.setdefault(tag, {"rule_count": 0, "categories": set(), "example_rule_ids": []})
            stats["rule_count"] += 1
            if category:
                stats["categories"].add(category)
            if rule_id and len(stats["example_rule_ids"]) < 10:
                stats["example_rule_ids"].append(rule_id)

    matches: list[dict[str, Any]] = []
    for item in technologies:
        key = str(item.get("technology_key") or "").strip().casefold()
        aliases = TECHNOLOGY_TAG_ALIASES.get(key, set())
        if not aliases:
            continue
        matched_tags = sorted(tag for tag in aliases if tag in tag_stats)
        if not matched_tags:
            continue
        categories = sorted({category for tag in matched_tags for category in tag_stats[tag]["categories"]})
        rule_count = sum(tag_stats[tag]["rule_count"] for tag in matched_tags)
        example_rule_ids: list[str] = []
        for tag in matched_tags:
            for rule_id in tag_stats[tag]["example_rule_ids"]:
                if rule_id not in example_rule_ids and len(example_rule_ids) < 10:
                    example_rule_ids.append(rule_id)
        surface = "server" if item.get("category") in {"web-server", "server-runtime"} else "web-application"
        matches.append({
            "technology": item.get("technology"),
            "technology_key": key,
            "surface": surface,
            "matched_signature_tags": matched_tags,
            "signature_rule_count": rule_count,
            "signature_categories": categories,
            "example_rule_ids": example_rule_ids,
            "source": "netscaler-signature-index",
            "is_detection_evidence": False,
            "interpretation": "Catalog applicability context only; passive HTTP evidence remains authoritative for technology detection.",
        })

    return {
        "status": "matched" if matches else "no-technology-tag-match",
        "source": "netscaler-signature-index",
        "index_file": str(path),
        "catalog_fingerprint": catalog.get("catalogs", [{}])[0].get("catalog_fingerprint") if catalog.get("catalogs") else None,
        "catalog_rule_count": catalog.get("rule_count", 0),
        "technology_matches": matches,
        "is_detection_evidence": False,
    }
