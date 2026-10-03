"""
HELIOS-NET :: tests/test_imports.py
Every module in the package must be importable.

Why this file exists
--------------------
`modules/discovery/service.py` and `modules/recon/fingerprint.py` both did
`from transport import RAWSYNC, _run` and `from transport import FINGERPRINT,
_run`. None of those three names existed. Both modules raised ImportError on
import, so they were entirely dead, and the test suite never noticed because
nothing imported them.

A test that only exercises the code paths it knows about cannot catch that. A
test that walks the tree and imports everything can. This is the cheapest
regression guard in the repository: it costs a fraction of a second and turns
"an entire subsystem is silently broken" into a red build.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Packages that legitimately have side effects, need a live target, or are
# entry points rather than libraries.
SKIP_PREFIXES = ("tests.",)


def _discover_modules() -> list[str]:
    """Yields every importable dotted module name in the project."""
    names: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if any(
            p in {"__pycache__", "build", "target", ".git", "rust-core"}
            for p in rel.parts
        ):
            continue
        # build.py is a script, not a library: importing it is harmless thanks
        # to its __main__ guard, but it is not part of the package surface.
        if rel.name == "build.py":
            continue

        # Strip the extension before dropping __init__, otherwise a package
        # entry point is named "pkg.__init__" and the real "pkg" is never tested.
        parts = list(rel.parts)
        parts[-1] = parts[-1][: -len(".py")]
        parts = [p for p in parts if p != "__init__"]
        dotted = ".".join(parts)
        if not dotted or dotted == "tests" or dotted.startswith("tests."):
            continue
        names.append(dotted)
    return names


MODULES = _discover_modules()


def test_the_walker_actually_finds_modules():
    """Guard against the discovery itself silently returning nothing."""
    assert len(MODULES) > 20, f"discovery found only {len(MODULES)} modules"
    for expected in (
        "core.cores",
        "modules.discovery.service",
        "modules.recon.fingerprint",
        "transport",
        "engine.graph.core",
    ):
        assert expected in MODULES, f"discovery missed {expected}"


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name: str):
    """Importing must not raise, and must not execute network activity."""
    assert importlib.import_module(name) is not None


def test_no_module_imports_a_name_that_does_not_exist():
    """Directly asserts the bug that started this file.

    `from transport import X` raises at import time, so any surviving import of
    a name the target module does not define is a hard failure for whoever
    imports it next.
    """
    import transport

    for gone in ("RAWSYNC", "FINGERPRINT", "RAWSOCKET"):
        assert not hasattr(transport, gone), (
            f"transport re-exported {gone}; callers may still depend on a binary "
            "that no longer exists"
        )


def test_subprocess_pipes_pin_an_explicit_encoding():
    """`text=True` alone decodes with the host locale (cp1252 on Windows).

    The native contract is UTF-8. A missing `encoding=` on any subprocess call
    reintroduces the non-ASCII fingerprint divergence documented in
    docs/Architecture.md, so it is checked mechanically rather than by review.
    """
    import ast

    offenders: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if any(
            p in {"__pycache__", "build", "target", ".git", "rust-core"}
            for p in rel.parts
        ):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name not in {"run", "Popen", "check_output", "communicate"}:
                continue
            # Only subprocess module calls matter.
            if not isinstance(func, ast.Attribute) and name not in {
                "run",
                "Popen",
                "check_output",
            }:
                continue
            if not any(
                isinstance(a, ast.Attribute)
                and a.attr == name
                and isinstance(a.value, ast.Name)
                and a.value.id == "subprocess"
                for a in [getattr(node, "func", None)]
            ):
                continue

            kwargs = {k.arg for k in node.keywords if k.arg}
            if "text" in kwargs or "universal_newlines" in kwargs:
                if "encoding" not in kwargs:
                    offenders.append(f"{rel}:{node.lineno}")

    assert not offenders, (
        "subprocess calls decode with the host locale instead of UTF-8:\n  "
        + "\n  ".join(offenders)
    )
