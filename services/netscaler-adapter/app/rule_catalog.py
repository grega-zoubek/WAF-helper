from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


# Explicit product phrases keep generic attack words out of the searchable
# taxonomy while covering vendor/product names found in NetScaler log strings.
VENDOR_PRODUCT_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("VMware", "vCenter", r"\bvcenter(?:\s+server)?\b"),
    ("VMware", "ESX / ESXi", r"\besx(?:i)?\b"),
    ("VMware", "vSphere", r"\bvsphere\b"),
    ("VMware", "Aria Operations for Networks", r"\bvmware\s+aria\s+operations\s+for\s+networks\b"),
    ("VMware", "Aria Operations for Logs", r"\bvmware\s+aria\s+operations\s+for\s+logs\b"),
    ("VMware", "Workspace ONE Access", r"\bworkspace\s+one\s+access\b"),
    ("VMware", "Carbon Black", r"\bcarbon\s+black\b"),
    ("VMware", "vRealize Operations Manager", r"\bvrealize\s+operations\s+manager\b"),
    ("VMware", "Cloud Foundation", r"\bcloud\s+foundation\b"),
    ("VMware", "SD-WAN Orchestrator", r"\bsd[- ]wan\s+orchestrator\b"),
    ("IBM", "Lotus Domino", r"\b(?:ibm\s+)?lotus\s+domino\b|\bdomino\b"),
    ("IBM", "Lotus Notes", r"\b(?:ibm\s+)?lotus\s+notes?\b|\blotusnotes?\b"),
    ("IBM", "WebSphere", r"\b(?:ibm\s+)?websphere\b"),
    ("IBM", "Net.Commerce", r"\b(?:ibm\s+)?net[.]commerce\b"),
    ("IBM", "QRadar", r"\b(?:ibm\s+)?qradar\b"),
    ("IBM", "BigFix", r"\b(?:ibm\s+)?bigfix\b"),
    ("IBM", "DataPower", r"\b(?:ibm\s+)?datapower\b"),
    ("Microsoft", "Exchange / OWA", r"\b(?:microsoft\s+)?exchange\b|\bowa\b"),
    ("Microsoft", "IIS", r"\biis\b|\bwebdav\b"),
    ("Microsoft", "SharePoint", r"\bsharepoint\b"),
    ("Microsoft", "ASP.NET", r"\basp[.]net\b"),
    ("Microsoft", "Outlook", r"\boutlook\b"),
    ("Microsoft", "Windows", r"\bmicrosoft\s+windows\b|\bwindows\s+server\b"),
    ("Apache", "HTTP Server", r"\bapache\s+(?:httpd|http\s+server)\b"),
    ("Apache", "Tomcat", r"\b(?:apache\s+)?tomcat\b"),
    ("Apache", "Struts", r"\b(?:apache\s+)?struts\b"),
    ("Apache", "Solr", r"\bapache\s+solr\b|\bsolr\b"),
    ("Apache", "OFBiz", r"\bapache\s+ofbiz\b|\bofbiz\b"),
    ("Oracle", "WebLogic", r"\b(?:oracle\s+)?weblogic\b"),
    ("Oracle", "MySQL", r"\bmysql\b"),
    ("Oracle", "Database", r"\boracle\s+(?:database|db)\b"),
    ("Oracle", "PeopleSoft", r"\bpeoplesoft\b"),
    ("Citrix", "NetScaler / ADC", r"\b(?:citrix\s+)?(?:netscaler|adc)\b"),
    ("Citrix", "XenApp / XenDesktop", r"\b(?:xenapp|xendesktop)\b"),
    ("Citrix", "ShareFile", r"\bsharefile\b"),
    ("SAP", "NetWeaver", r"\bnetweaver\b"),
    ("SAP", "HANA", r"\bsap\s+hana\b|\bhana\b"),
    ("SAP", "BusinessObjects", r"\bbusinessobjects\b"),
    ("Adobe", "ColdFusion", r"\bcoldfusion\b"),
    ("Adobe", "Experience Manager", r"\b(?:adobe\s+)?experience\s+manager\b|\baem\b"),
    ("Red Hat", "JBoss / WildFly", r"\b(?:jboss|wildfly)\b"),
    ("Red Hat", "OpenShift", r"\bopenshift\b"),
    ("Atlassian", "Jira", r"\bjira\b"),
    ("Atlassian", "Confluence", r"\bconfluence\b"),
    ("Atlassian", "Bitbucket", r"\bbitbucket\b"),
    ("WordPress", "WordPress", r"\bwordpress\b"),
    ("Drupal", "Drupal", r"\bdrupal\b"),
    ("Joomla", "Joomla", r"\bjoomla\b"),
    ("Magento", "Magento", r"\bmagento\b"),
    ("Nginx", "Nginx", r"\bnginx\b"),
    ("Node.js", "Express", r"\bexpress(?:[.]js)?\b"),
    ("PHP", "PHP", r"\bphp(?:[- ]?nuke)?\b"),
)


def extract_vendor_products(text: str) -> list[dict[str, Any]]:
    haystack = " ".join(str(text or "").split())
    entities: list[dict[str, Any]] = []
    seen: set[str] = set()
    for vendor, product, pattern in VENDOR_PRODUCT_PATTERNS:
        matches = list(re.finditer(pattern, haystack, flags=re.IGNORECASE))
        if not matches:
            continue
        key = f"{_slug(vendor)}/{_slug(product)}"
        if key in seen:
            continue
        seen.add(key)
        entities.append({
            "vendor": vendor,
            "product": product,
            "key": key,
            "label": f"{vendor} / {product}",
            "source_terms": sorted({match.group(0).strip() for match in matches}, key=str.casefold)[:10],
        })
    return entities


def build_product_index(rules: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for rule in rules:
        for entity in rule.get("vendor_products", []):
            key = str(entity.get("key") or "")
            vendor = str(entity.get("vendor") or "").strip()
            product = str(entity.get("product") or "").strip()
            if not key or not vendor or not product:
                continue
            entry = grouped.setdefault(key, {"key": key, "vendor": vendor, "product": product, "rule_count": 0, "rule_ids": [], "example_rule_ids": [], "source_terms": set()})
            entry["rule_count"] += 1
            rule_id = str(rule.get("rule_id") or "")
            if rule_id and rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(rule_id)
            if rule_id and len(entry["example_rule_ids"]) < 25 and rule_id not in entry["example_rule_ids"]:
                entry["example_rule_ids"].append(rule_id)
            entry["source_terms"].update(str(term) for term in entity.get("source_terms", []) if term)
    vendors: dict[str, dict[str, Any]] = {}
    for entry in grouped.values():
        vendor = entry["vendor"]
        vendor_entry = vendors.setdefault(vendor, {"vendor": vendor, "key": _slug(vendor), "rule_count": 0, "product_count": 0, "products": []})
        vendor_entry["rule_count"] += entry["rule_count"]
        vendor_entry["product_count"] += 1
        vendor_entry["products"].append({**entry, "source_terms": sorted(entry["source_terms"], key=str.casefold)})
    vendor_list = sorted(vendors.values(), key=lambda item: str(item["vendor"]).casefold())
    for vendor in vendor_list:
        vendor["products"].sort(key=lambda item: str(item["product"]).casefold())
    flat_products = [product for vendor in vendor_list for product in vendor["products"]]
    return {"schema_version": "1.0.0", "vendor_count": len(vendor_list), "product_count": len(flat_products), "rule_count": len({rule_id for product in flat_products for rule_id in product["rule_ids"]}), "vendors": vendor_list, "products": flat_products}


def _normalize_rules(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("rules", value.get("entries", []))
    if not isinstance(value, list):
        return []
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id", item.get("ruleid", item.get("id")))
        if rule_id is None:
            continue
        key = str(rule_id).strip()
        if not key or key in seen:
            continue
        attack_classes = item.get("attack_classes", item.get("attack_class", []))
        technology_tags = item.get("technology_tags", item.get("technologies", []))
        if isinstance(attack_classes, str):
            attack_classes = [attack_classes]
        if isinstance(technology_tags, str):
            technology_tags = [technology_tags]
        description = str(item.get("description") or item.get("name") or item.get("logstring") or "")[:500]
        released_year = item.get("released_year", item.get("year"))
        vendor_products = item.get("vendor_products")
        if not isinstance(vendor_products, list):
            vendor_products = extract_vendor_products(description)
        rules.append({
            "rule_id": key,
            "category": str(item.get("category") or "").strip().casefold() or None,
            "attack_classes": sorted({str(v).strip().casefold() for v in attack_classes if v}),
            "technology_tags": sorted({str(v).strip().casefold() for v in technology_tags if v}),
            "description": description,
            "vendor_products": [entity for entity in vendor_products if isinstance(entity, dict)],
            "action": str(item.get("action") or "LOG").upper(),
            "enabled": bool(item.get("enabled", True)),
            "version": str(item.get("version") or "").strip() or None,
            "released_year": str(released_year).strip() if released_year is not None and str(released_year).strip() else None,
            "severity": str(item.get("severity") or "").strip().casefold() or None,
            "source": str(item.get("source") or "").strip() or None,
            "source_catalog": str(item.get("source_catalog") or "").strip() or None,
            "reference_count": int(item.get("reference_count") or 0),
            "pattern_count": int(item.get("pattern_count") or 0),
            "match_types": sorted({str(v).strip().casefold() for v in (item.get("match_types") or []) if v}),
            "locations": sorted({str(v).strip().casefold() for v in (item.get("locations") or []) if v}),
        })
        seen.add(key)
    return rules


def _split_tokens(value: str) -> list[str]:
    return [token.strip().casefold() for token in re.split(r"[,;|\s]+", value or "") if token.strip()]


def _infer_attack_classes(category: str, description: str, match_types: list[str], locations: list[str]) -> list[str]:
    haystack = " ".join([category, description, " ".join(match_types), " ".join(locations)]).casefold()
    result = set(_split_tokens(category))
    mappings = {
        "sql-injection": ("sql", "sql injection"),
        "cross-site-scripting": ("xss", "cross-site scripting", "crosssitescripting"),
        "xpath-injection": ("xpath",),
        "ldap-injection": ("ldap",),
        "nosql-injection": ("nosql", "mongo", "mongodb"),
        "command-injection": ("command injection", "command-injection", "os command", "os-command"),
        "buffer-overflow": ("buffer overflow", "buffer-overflow"),
        "file-upload": ("file upload", "file-upload", "unrestricted upload"),
        "path-traversal": ("path traversal", "directory traversal", "path-traversal"),
        "xml": ("xml", "soap"),
    }
    for attack_class, needles in mappings.items():
        if any(needle in haystack for needle in needles):
            result.add(attack_class)
    return sorted(result)


def _infer_technology_tags(category: str, description: str) -> list[str]:
    haystack = f"{category} {description}".casefold()
    technologies = (
        "apache", "asp", "asp.net", "coldfusion", "drupal", "exchange", "express", "iis",
        "java", "joomla", "laravel", "microsoft", "nginx", "node", "php", "postgres",
        "tomcat", "wordpress", "owa", "mysql", "oracle", "mongodb", "struts",
        "perl", "jet", "vba", "visual basic", "lotus", "domino", "websphere",
        "vcenter", "esx", "esxi", "vmware", "sharepoint", "sap", "ibm", "citrix",
        "python", "ruby", "rails", "graphql", "soap", "xml",
    )
    return [technology for technology in technologies if technology in haystack]


def _xml_rules(text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rules: list[dict[str, Any]] = []
    for element in root.iter():
        attrs = {str(k).casefold().split("}")[-1]: str(v) for k, v in element.attrib.items()}
        rule_id = attrs.get("ruleid") or attrs.get("rule_id") or attrs.get("id")
        tag = str(element.tag).casefold().split("}")[-1]
        if not rule_id or ("rule" not in tag and "signature" not in tag):
            continue
        def child_text(name: str) -> str:
            for child in element.iter():
                child_tag = str(child.tag).casefold().split("}")[-1]
                if child_tag == name.casefold() and child.text:
                    return " ".join(child.text.split())
            return ""

        description = attrs.get("logstring") or attrs.get("description") or attrs.get("name") or child_text("logstring")
        category = attrs.get("category") or attrs.get("sigcategory") or ""
        matches: list[str] = []
        locations: list[str] = []
        for child in element.iter():
            child_tag = str(child.tag).casefold().split("}")[-1]
            child_attrs = {str(k).casefold().split("}")[-1]: str(v) for k, v in child.attrib.items()}
            if child_tag == "match" and child_attrs.get("type"):
                matches.append(child_attrs["type"])
            if child_tag == "location" and child_attrs.get("area"):
                locations.append(child_attrs["area"])
        references = [
            " ".join(child.text.split())
            for child in element.iter()
            if str(child.tag).casefold().split("}")[-1] == "reference" and child.text and child.text.strip()
        ]
        actions = attrs.get("actions") or attrs.get("action") or "LOG"
        enabled_value = attrs.get("enabled", "true").casefold()
        enabled = enabled_value not in {"false", "off", "0"}
        attack_classes = _infer_attack_classes(category, description, matches, locations)
        technology_tags = _infer_technology_tags(category, description)
        rules.append({
            "rule_id": rule_id,
            "category": category,
            "attack_classes": attack_classes,
            "technology_tags": technology_tags,
            "description": description,
            "action": actions.split(",")[0].strip() or "LOG",
            "enabled": enabled,
            "version": attrs.get("version"),
            "released_year": attrs.get("year"),
            "severity": attrs.get("severity"),
            "source": attrs.get("source") or attrs.get("vendor"),
            "reference_count": len(references),
            "pattern_count": len(matches) + len(locations),
            "match_types": matches,
            "locations": locations,
            "vendor_products": extract_vendor_products(description),
        })
    return _normalize_rules(rules)


def load_rule_catalog(path_value: str) -> dict[str, Any]:
    path_value = path_value.strip()
    if not path_value:
        return {"status": "not-configured", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    path = Path(path_value)
    if not path.is_file():
        return {"status": "configured-file-missing", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    if path.stat().st_size > 64 * 1024 * 1024:
        return {"status": "file-too-large", "provider": "netscaler", "rules": [], "rule_count": 0, "catalog_fingerprint": None}
    text = path.read_text(encoding="utf-8")
    source_payload: dict[str, Any] = {}
    try:
        source_payload = json.loads(text)
        rules = _normalize_rules(source_payload)
    except json.JSONDecodeError:
        rules = _xml_rules(text)
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), default=str).encode()
    category_counts: dict[str, int] = {}
    attack_class_counts: dict[str, int] = {}
    source_catalog_counts: dict[str, int] = {}
    for rule in rules:
        category = rule.get("category")
        if category:
            category_counts[str(category)] = category_counts.get(str(category), 0) + 1
        for attack_class in rule.get("attack_classes", []):
            attack_class_counts[str(attack_class)] = attack_class_counts.get(str(attack_class), 0) + 1
        source_catalog = rule.get("source_catalog")
        if source_catalog:
            source_catalog_counts[str(source_catalog)] = source_catalog_counts.get(str(source_catalog), 0) + 1
    return {
        "status": "enumerated" if rules else "no-rule-metadata",
        "provider": "netscaler",
        "schema_version": str(source_payload.get("schema_version") or "1.1.0") if isinstance(source_payload, dict) else "1.1.0",
        "catalogs": source_payload.get("catalogs", []) if isinstance(source_payload, dict) else [],
        "rules": rules,
        "product_index": build_product_index(rules),
        "rule_count": len(rules),
        "category_counts": dict(sorted(category_counts.items())),
        "attack_class_counts": dict(sorted(attack_class_counts.items())),
        "source_catalog_counts": dict(sorted(source_catalog_counts.items())),
        "catalog_fingerprint": hashlib.sha256(canonical).hexdigest() if rules else None,
        "raw_payload_retained": False,
    }
