from pathlib import Path
import json
import sys


CONTROL_API = Path(__file__).resolve().parents[1] / "services" / "control-api"
sys.path.insert(0, str(CONTROL_API))

from app.generic_signature_groups import GROUP_IDS, match_rule_to_group, select_generic_signature_groups  # noqa: E402


def rule(rule_id: str, *, classes=None, description="", tags=None):
    return {
        "rule_id": rule_id,
        "attack_classes": classes or [],
        "description": description,
        "technology_tags": tags or [],
        "category": "web-misc",
    }


def test_first_five_are_stable_and_signature_only():
    assert GROUP_IDS == (
        "http-protocol-compliance",
        "canonicalization-evasion",
        "injection",
        "xss",
        "path-file",
    )
    result = select_generic_signature_groups(
        [
            rule("1", description="Chunked-Encoding transfer attempt"),
            rule("2", description="double URL encoding attempt"),
            rule("3", classes=["sql-injection"]),
            rule("4", classes=["cross-site-scripting"]),
            rule("5", classes=["path-traversal"]),
            rule("6", classes=["file-upload"]),
            rule("7", classes=["sql-injection"], tags=["wordpress"]),
        ],
        {"route_inventory": [{"path": "/"}], "evidence": []},
    )
    counts = {item["group_id"]: item["selected_rule_count"] for item in result["groups"]}
    assert counts == {
        "http-protocol-compliance": 1,
        "canonicalization-evasion": 1,
        "injection": 1,
        "xss": 1,
        "path-file": 1,
    }
    assert "7" not in result["selected_rule_ids"]
    assert result["signature_only"] is True
    assert result["positive_model"]["enabled"] is False


def test_file_upload_rules_require_upload_evidence_but_traversal_does_not():
    rules = [
        rule("10", classes=["path-traversal"]),
        rule("11", classes=["file-upload"]),
    ]
    no_upload = select_generic_signature_groups(rules, {"route_inventory": [{"path": "/"}], "evidence": []})
    path_group = next(item for item in no_upload["groups"] if item["group_id"] == "path-file")
    assert path_group["rule_ids"] == ["10"]

    with_upload = select_generic_signature_groups(
        rules,
        {
            "route_inventory": [{"path": "/"}],
            "evidence": [{"technology": "File upload surface"}],
        },
    )
    path_group = next(item for item in with_upload["groups"] if item["group_id"] == "path-file")
    assert path_group["rule_ids"] == ["10", "11"]


def test_group_matcher_does_not_select_tagged_product_rules():
    matched, reasons = match_rule_to_group(
        "injection",
        rule("20", classes=["sql-injection"], tags=["mysql"]),
        {"route_inventory": [{"path": "/"}], "evidence": []},
    )
    assert matched is False
    assert reasons == []
