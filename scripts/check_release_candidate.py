#!/usr/bin/env python3
"""Build and verify a local Delegent Core release candidate."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=cwd, env=env, check=True)


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def clean_build_outputs() -> None:
    for path in (DIST, ROOT / "build", ROOT / "src/delegent.egg-info"):
        if path.exists():
            shutil.rmtree(path)


def built_wheel() -> Path:
    wheels = sorted(DIST.glob("delegent-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one built wheel, found {len(wheels)}")
    return wheels[0]


def main() -> int:
    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)

    clean_build_outputs()
    run([sys.executable, "-m", "build"])
    wheel = built_wheel()

    with tempfile.TemporaryDirectory(prefix="delegent-rc-") as tmp:
        venv_dir = Path(tmp) / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_python(venv_dir)
        run([str(python), "-m", "pip", "install", str(wheel)])
        run([str(python), "-m", "pip", "install", "pytest"])
        run([str(python), "-m", "pytest", "tests"])
        run([str(python), "examples/document_review_gate.py"], env=clean_env)
        run([str(python), "examples/maintenance_window_gate.py"], env=clean_env)

    run([sys.executable, "scripts/check_public_boundary.py"])
    print(f"Delegent Core release candidate verified: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
