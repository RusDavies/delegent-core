#!/usr/bin/env python3
"""Fail if public-intended Delegent Core files contain private coupling."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
}
SKIP_FILES = {
    Path("scripts/check_public_boundary.py"),
    Path("tests/test_public_boundary.py"),
    Path("tests/fixtures/private-marker-example.txt"),
}
BINARY_SUFFIXES = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip"}

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("legacy project name", re.compile(r"\brsk-ai-auth\b", re.IGNORECASE)),
    ("downstream relying product", re.compile(r"\brsk-works\b", re.IGNORECASE)),
    ("downstream relying product", re.compile(r"\bredshieldworks\b", re.IGNORECASE)),
    ("downstream governance product", re.compile(r"\bknightwarden\b", re.IGNORECASE)),
    ("downstream runtime product", re.compile(r"\bknightarmor\b", re.IGNORECASE)),
    ("private management repo", re.compile(r"\bdelegent-mgnt\b", re.IGNORECASE)),
    ("private commercial repo", re.compile(r"\bdelegent-commercial\b", re.IGNORECASE)),
    ("workspace-local path", re.compile(r"(^|[^A-Za-z0-9_])projects/[A-Za-z0-9_.-]+")),
    ("discord channel", re.compile(r"#[A-Za-z0-9_-]+")),
    ("discord channel id", re.compile(r"\b\d{17,20}\b")),
    ("personal email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("private org marker", re.compile(r"\bblakemere\b", re.IGNORECASE)),
    ("private GitHub owner", re.compile(r"\brusdavies\b", re.IGNORECASE)),
)


def iter_text_files(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if rel in SKIP_FILES:
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        paths.append(path)
    return paths


def check_path(path: Path) -> list[str]:
    rel = path.relative_to(ROOT)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{rel}: cannot decode as UTF-8"]

    failures: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for label, pattern in FORBIDDEN_PATTERNS:
            if pattern.search(line):
                failures.append(f"{rel}:{line_number}: {label}")
    return failures


def main() -> int:
    failures: list[str] = []
    for path in iter_text_files(ROOT):
        failures.extend(check_path(path))

    if failures:
        print("Delegent Core public-boundary check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Delegent Core public-boundary check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
