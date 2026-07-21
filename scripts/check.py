#!/usr/bin/env python3
"""Run the Delegent Core local verification gate."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    commands = [
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        [sys.executable, "scripts/check_public_boundary.py"],
    ]
    for command in commands:
        run(command)
    print("Delegent Core verification gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
