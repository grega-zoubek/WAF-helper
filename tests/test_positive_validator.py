import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

CONTROL_API = Path(__file__).resolve().parents[1] / "services" / "control-api"
sys.path.insert(0, str(CONTROL_API))

from app.positive_model import PositiveModelDocument
from app.positive_validator import TransactionDescriptor, validate_transaction


def model_document():
    return PositiveModelDocument.model_validate({
        "model_id": "model-test",
        "application_id": "app-test",
        "hostname": "example.test",
        "environment": "test",
        "endpoints": [{
            "path_template": "/items/{item_id:int}",
            "method": "GET",
            "request_content_types": [],
            "fields": [{
                "name": "page",
                "location": "query",
                "proposed_constraints": {"requiredness": "required", "value_type": "integer", "min_length": 1, "max_length": 3},
            }],
        }],
    })


class PositiveValidatorTests(unittest.TestCase):
    def test_route_parameter_and_matching_metadata_pass(self):
        result = validate_transaction(model_document(), TransactionDescriptor.model_validate({
            "method": "GET", "path": "/items/42", "fields": [
                {"name": "page", "location": "query", "value_type": "integer", "length": 2},
            ],
        }))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["matched_endpoint"]["path_template"], "/items/{item_id:int}")
        self.assertFalse(result["raw_values_received"])

    def test_missing_required_and_unexpected_fields_are_reported(self):
        result = validate_transaction(model_document(), TransactionDescriptor.model_validate({
            "method": "GET", "path": "/items/42", "fields": [
                {"name": "debug", "location": "query", "value_type": "boolean"},
            ],
        }))
        codes = {item["code"] for item in result["findings"]}
        self.assertEqual(result["status"], "findings")
        self.assertIn("required_field_missing", codes)
        self.assertIn("unexpected_field", codes)

    def test_type_length_and_content_type_mismatch(self):
        document = model_document()
        document.endpoints[0].request_content_types = ["application/json"]
        result = validate_transaction(document, TransactionDescriptor.model_validate({
            "method": "GET", "path": "/items/42", "content_type": "text/plain",
            "fields": [{"name": "page", "location": "query", "value_type": "string", "length": 9}],
        }))
        codes = {item["code"] for item in result["findings"]}
        self.assertTrue({"content_type_mismatch", "field_type_mismatch", "field_above_max_length"}.issubset(codes))

    def test_unmodeled_method_and_route_fail_closed(self):
        method = validate_transaction(model_document(), TransactionDescriptor(method="POST", path="/items/42"))
        route = validate_transaction(model_document(), TransactionDescriptor(method="GET", path="/admin"))
        self.assertEqual(method["findings"][0]["code"], "method_not_modeled")
        self.assertEqual(route["findings"][0]["code"], "route_not_modeled")

    def test_format_content_rules_are_reported_not_guessed(self):
        document = model_document()
        document.endpoints[0].fields[0].proposed_constraints.format_hint = "email"
        result = validate_transaction(document, TransactionDescriptor.model_validate({
            "method": "GET", "path": "/items/42", "fields": [
                {"name": "page", "location": "query", "value_type": "integer", "length": 2},
            ],
        }))
        self.assertIn("content_constraint_not_evaluated", {item["code"] for item in result["findings"]})

    def test_raw_values_and_unknown_fields_are_rejected(self):
        with self.assertRaises(ValidationError):
            TransactionDescriptor.model_validate({"method": "GET", "path": "/items", "raw_value": "secret"})
        with self.assertRaises(ValueError):
            transaction = TransactionDescriptor(method="GET", path="/items?token=secret")
            validate_transaction(model_document(), transaction)


if __name__ == "__main__":
    unittest.main()
