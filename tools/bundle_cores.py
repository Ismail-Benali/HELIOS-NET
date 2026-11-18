"""Copies locally built native cores into the package a wheel ships.

A checkout resolves its cores from ``transport/`` and ``rust-core/``; a wheel
has neither tree. Building a wheel therefore means: build the cores for the
wheel's platform, bundle them, then package.

    python build.py
    python tools/bundle_cores.py --require c rust go
    python -m pip wheel . --no-deps -w dist

Only the artifacts of the current platform are copied, into
``core/native/``, which ``core/native/__init__.py`` turns into a package so
setuptools can carry the files as package data. Anything left over from an
earlier platform is removed first: a Windows wheel that also carried a Linux
``.so`` would be misleading.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_EXE = ".exe" if os.name == "nt" else ""
NATIVE_SUFFIXES = {".exe", ".dll", ".so", ".dylib"}

_C_LIB_NAMES = (
    "helios_core.dll",
    "libhelios_core.so",
    "libhelios_core.dylib",
)
_RUST_NAMES = (
    "helios_rust_core.dll",
    "libhelios_rust_core.so",
    "libhelios_rust_core.dylib",
)


@dataclass(frozen=True)
class BuiltCores:
    c: tuple[Path, ...]
    rust: tuple[Path, ...]
    go: tuple[Path, ...]

    def as_dict(self) -> dict[str, tuple[Path, ...]]:
        return {"c": self.c, "rust": self.rust, "go": self.go}


def candidate_artifacts(root: Path = ROOT) -> BuiltCores:
    """The built artifacts for this platform, whether or not they exist."""
    c_core = root / "transport" / "c_core"
    c_paths = [
        c_core / "build" / f"helios_core{_EXE}",
        c_core / f"helios_core{_EXE}",
    ]
    c_paths.extend(c_core / "build" / name for name in _C_LIB_NAMES)
    c_paths.extend(c_core / name for name in _C_LIB_NAMES)
    rust_paths = [
        root / "rust-core" / "target" / "release" / name for name in _RUST_NAMES
    ]
    go_paths = [root / "transport" / "goscan" / f"goscan{_EXE}"]
    return BuiltCores(
        c=tuple(dict.fromkeys(path for path in c_paths if path.exists())),
        rust=tuple(path for path in rust_paths if path.exists()),
        go=tuple(path for path in go_paths if path.exists()),
    )


def bundle(root: Path = ROOT, destination: Path | None = None) -> list[Path]:
    """Copies the built artifacts into `destination`, replacing older files."""
    target = destination or root / "core" / "native"
    target.mkdir(parents=True, exist_ok=True)
    for stale in target.iterdir():
        if stale.is_file() and stale.suffix.lower() in NATIVE_SUFFIXES:
            stale.unlink()
    copied: list[Path] = []
    for paths in candidate_artifacts(root).as_dict().values():
        for artifact in paths:
            destination_path = target / artifact.name
            shutil.copy2(artifact, destination_path)
            copied.append(destination_path)
    return copied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--dest", default=None)
    parser.add_argument(
        "--require",
        nargs="+",
        default=["c", "rust", "go"],
        choices=["c", "rust", "go"],
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    found = candidate_artifacts(root)
    missing = [name for name in args.require if not found.as_dict()[name]]
    if missing:
        print(
            "missing built artifacts for: "
            + ", ".join(missing)
            + "; run `python build.py` first",
            file=sys.stderr,
        )
        return 1

    if args.dest is None:
        copied = bundle(root)
    else:
        copied = bundle(root, Path(args.dest))
    for path in copied:
        print(
            f"[HELIOS] bundled {path.relative_to(root) if path.is_relative_to(root) else path}"
        )
    print(f"[HELIOS] {len(copied)} artifact(s) bundled for this platform")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
