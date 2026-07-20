from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
OPENAPI = ROOT / "openapi"


class SchemaTests(unittest.TestCase):
    def test_all_json_schema_files_parse(self) -> None:
        for path in sorted(SCHEMAS.glob("*.schema.json")):
            with self.subTest(path=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertTrue(schema["$id"].startswith("https://delegent.example/schemas/"))
                self.assertIn("title", schema)

    def test_openapi_fragment_parses(self) -> None:
        fragment = json.loads(
            (OPENAPI / "delegent-validation.openapi.json").read_text(encoding="utf-8")
        )

        self.assertEqual(fragment["openapi"], "3.1.0")
        self.assertIn("/delegent/validate", fragment["paths"])

    def test_reason_codes_match_contract_constants(self) -> None:
        from delegent import ReasonCode

        schema = json.loads(
            (SCHEMAS / "reason-code.schema.json").read_text(encoding="utf-8")
        )
        contract_codes = {
            value
            for name, value in vars(ReasonCode).items()
            if name.isupper() and isinstance(value, str)
        }

        self.assertEqual(set(schema["enum"]), contract_codes)

    def test_validation_request_names_core_required_fields(self) -> None:
        schema = json.loads(
            (SCHEMAS / "validation-request.schema.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            set(schema["required"]),
            {
                "method",
                "url",
                "audience",
                "project_id",
                "session_id",
                "requested_action",
                "purpose",
                "grant",
                "sender_proof",
            },
        )


if __name__ == "__main__":
    unittest.main()
