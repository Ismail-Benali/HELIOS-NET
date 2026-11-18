"""Installs a built wheel in a throwaway environment and proves the cores load.

A wheel can contain every native file and still be broken: a wrong platform tag,
a library that cannot resolve its dependencies, or package data left out of the
archive. This installs the artifact the way a user would, runs the backend probe
outside the checkout (so the checkout cannot shadow the wheel), and fails if a
required backend is not available.

    python tools/bundle_cores.py
    python -m pip wheel . --no-deps -w dist
    python tools/verify_wheel.py --wheel dist/*.whl --require c rust go
"""

from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PROBE = """
import json
from core.accel import backend_infos
print(json.dumps({item.name: item.available for item in backend_infos()}))
"""


def _python(environment: Path) -> Path:
    if sys.platform == "win32":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _resolve_wheel(pattern: str) -> Path:
    matches = sorted(glob.glob(pattern))
    if not matches:
        raise SystemExit(f"no wheel matches {pattern!r}; build one first")
    if len(matches) > 1:
        matches.sort(key=lambda item: Path(item).stat().st_mtime)
    return Path(matches[-1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", default=str(ROOT / "dist" / "*.whl"))
    parser.add_argument(
        "--require", nargs="+", default=["c", "rust", "go"], choices=["c", "rust", "go"]
    )
    args = parser.parse_args(argv)

    wheel = _resolve_wheel(args.wheel)
    workdir = Path(tempfile.mkdtemp(prefix="helios-wheel-check-"))
    environment = workdir / "venv"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = _python(environment)

    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if install.returncode != 0:
        print(install.stdout)
        print(install.stderr, file=sys.stderr)
        raise SystemExit(f"cannot install {wheel.name}")

    probe = subprocess.run(
        [str(python), "-c", PROBE],
        cwd=workdir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if probe.returncode != 0:
        print(probe.stdout)
        print(probe.stderr, file=sys.stderr)
        raise SystemExit("the installed package cannot be imported")

    available = json.loads(probe.stdout.strip().splitlines()[-1])
    print(f"wheel    : {wheel.name}")
    print(f"backends : {available}")
    missing = [name for name in args.require if not available.get(name, False)]
    if missing:
        raise SystemExit("unavailable backend(s): " + ", ".join(missing))
    print("all required native backends are available from the installed wheel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
