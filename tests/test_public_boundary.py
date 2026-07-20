from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_public_boundary.py"

spec = importlib.util.spec_from_file_location("check_public_boundary", SCRIPT)
assert spec and spec.loader
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


class PublicBoundaryCheckerTests(unittest.TestCase):
    def test_clean_file_has_no_failures(self) -> None:
        path = ROOT / "tests" / "fixtures" / "public-safe-example.txt"

        self.assertEqual(boundary.check_path(path), [])

    def test_private_markers_are_detected(self) -> None:
        path = ROOT / "tests" / "fixtures" / "private-marker-example.txt"

        failures = boundary.check_path(path)

        self.assertGreaterEqual(len(failures), 2)
        self.assertTrue(any("legacy project name" in item for item in failures))
        self.assertTrue(any("discord channel id" in item for item in failures))
