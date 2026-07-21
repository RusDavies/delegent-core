from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ExampleTests(unittest.TestCase):
    def test_examples_validate_without_commercial_service(self) -> None:
        examples = [
            "examples/document_review_gate.py",
            "examples/maintenance_window_gate.py",
        ]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        for example in examples:
            with self.subTest(example=example):
                completed = subprocess.run(
                    [sys.executable, example],
                    cwd=ROOT,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                result = json.loads(completed.stdout)
                self.assertEqual(result["decision"], "allow")
                self.assertEqual(result["reason_code"], "allowed")
                self.assertEqual(
                    result["audit_event_type"], "authority_grant_validated"
                )
