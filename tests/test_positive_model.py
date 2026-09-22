import sys
import unittest
from pathlib import Path

from pydantic import ValidationError


sys.path.insert(0, str(Path(__file__).parents[1] / "services" / "control-api"))

from app.positive_model import (  # noqa: E402
    DecisionMode,
    EndpointModel,
    FieldLocation,
    FieldModel,
    FieldShape,
    Lifecycle,
    PositiveModelDocument,
    positive_model_json_schema,
)


class PositiveModelContractTests(unittest.TestCase):
    def valid_document(self):
        return {
            "model_id": "model-app-staging-1",
            "application_id": "app-1",
            "hostname": "shop.example.test",
            "environment": "staging",
            "evidence": [{
                "evidence_id": "ev-opaque-001",
                "source": "guided_browser",
                "observed_at": "2026-09-22T10:00:00Z",
                "sample_count": 12,
                "confidence": 0.92,
            }],
            "endpoints": [{
                "path_template": "/api/search",
                "method": "POST",
                "request_content_types": ["application/json"],
                "authentication": "public",
                "fields": [{
                    "name": "$.query",
                    "location": "json",
                    "sensitivity": "public",
                    "shape": {
                        "sample_count": 12,
                        "present_count": 12,
                        "distinct_value_count": 8,
                        "observed_types": ["string"],
                        "character_classes": ["letter", "whitespace"],
                        "min_length": 2,
                        "max_length": 42,
                    },
                    "proposed_constraints": {
                        "requiredness": "required",
                        "value_type": "string",
                        "max_length": 128,
                    },
                    "confidence": {
                        "score": 0.92,
                        "sample_count": 12,
                        "independent_session_count": 4,
                        "source_count": 2,
                    },
                }],
                "confidence": {
                    "score": 0.9,
                    "sample_count": 12,
                    "independent_session_count": 4,
                    "source_count": 2,
                },
            }],
        }

    def test_accepts_value_minimized_model_and_defaults_to_observe(self):
        document = PositiveModelDocument.model_validate(self.valid_document())
        endpoint = document.endpoints[0]
        self.assertEqual(document.schema_version, "1.0.0")
        self.assertEqual(endpoint.decision_mode, DecisionMode.OBSERVE)
        self.assertEqual(endpoint.lifecycle, Lifecycle.DISCOVERED)
        self.assertFalse(document.privacy.raw_observed_values_retained)

    def test_rejects_unmodeled_raw_values_and_body_fields(self):
        bad = self.valid_document()
        bad["endpoints"][0]["fields"][0]["shape"]["observed_values"] = ["secret sample"]
        with self.assertRaises(ValidationError):
            PositiveModelDocument.model_validate(bad)

        bad = self.valid_document()
        bad["evidence"][0]["evidence_id"] = "Authorization: Bearer secret"
        with self.assertRaises(ValidationError):
            PositiveModelDocument.model_validate(bad)

        bad = self.valid_document()
        bad.setdefault("privacy", {})["raw_observed_values_retained"] = True
        with self.assertRaises(ValidationError):
            PositiveModelDocument.model_validate(bad)

        bad = self.valid_document()
        bad["evidence"][0]["observed_at"] = "2026-09-22T10:00:00"
        with self.assertRaises(ValidationError):
            PositiveModelDocument.model_validate(bad)

        bad = self.valid_document()
        bad["request_body"] = {"password": "do-not-store"}
        with self.assertRaises(ValidationError):
            PositiveModelDocument.model_validate(bad)

    def test_rejects_block_before_staging(self):
        endpoint = {
            "path_template": "/login",
            "method": "POST",
            "decision_mode": "block",
            "lifecycle": "candidate",
        }
        with self.assertRaises(ValidationError):
            EndpointModel.model_validate(endpoint)

    def test_rejects_query_or_fragment_in_route_template(self):
        with self.assertRaises(ValidationError):
            EndpointModel.model_validate({"path_template": "/search?term=private", "method": "GET"})

    def test_rejects_inconsistent_aggregate_statistics(self):
        with self.assertRaises(ValidationError):
            FieldShape(sample_count=3, present_count=4)
        with self.assertRaises(ValidationError):
            FieldModel.model_validate({
                "name": "email",
                "location": FieldLocation.FORM,
                "proposed_constraints": {"min_length": 20, "max_length": 4},
            })

    def test_schema_is_versioned_and_does_not_define_raw_sample_properties(self):
        schema = positive_model_json_schema()
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0.0")
        def property_names(value):
            names = []
            if isinstance(value, dict):
                names.extend(value.get("properties", {}).keys())
                for child in value.values():
                    names.extend(property_names(child))
            elif isinstance(value, list):
                for child in value:
                    names.extend(property_names(child))
            return names

        names = property_names(schema)
        self.assertNotIn("observed_values", names)
        self.assertNotIn("raw_request_body", names)


if __name__ == "__main__":
    unittest.main()
