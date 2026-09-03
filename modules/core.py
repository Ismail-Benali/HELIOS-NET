"""HELIOS-NET :: modules/core.py
Module spawner system — extending modules without touching the core.

Philosophy:
  Instead of a fixed manual registration list, each standalone module registers
  itself via the `@module()` decorator and declares its name, kind, and runner.
  Any new folder is then auto-discovered and loaded. The system stays growable
  without a rebuild.

Contract:
  - A module: an object holding name, kind, runner, and a link to its task core.
  - The registry is global: the engine or orchestrator can query it anytime.
"""

from __future__ import annotations

import importlib
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

Runner = Callable[..., dict]


@dataclass
class ModuleSpec:
    """A registered module spec."""
    name: str
    kind: str
    runner: Runner
    params: dict = field(default_factory=dict)


# The global registry — unique per process.
_MODULES: dict[str, ModuleSpec] = {}


def module(name: str, kind: str = "generic", **params):
    """Decorator for a module: registers it in the registry on import.

    Example:
        @module("dns_enum", kind="discovery", timeout=3)
        def dns_runner(step, ctx): ...
    """
    def deco(fn: Runner) -> Runner:
        _MODULES[name] = ModuleSpec(name=name, kind=kind, runner=fn, params=params)
        return fn
    return deco


def get_module(name: str) -> ModuleSpec | None:
    return _MODULES.get(name)


def list_modules(kind: str | None = None) -> list[ModuleSpec]:
    if kind is None:
        return list(_MODULES.values())
    return [m for m in _MODULES.values() if m.kind == kind]


def load_package(module_path: str) -> int:
    """Imports a package/folder, causing all its decorated modules to register.

    Returns:
      The number of newly registered modules after import.
    """
    before = set(_MODULES)
    importlib.import_module(module_path)
    return len(set(_MODULES) - before)


def discover(scan_dir: Path) -> int:
    """Discovers and imports every new .py file in a folder, registering its modules.

    Skips files that already registered themselves (no double registration).

    Returns:
      The number of new modules.
    """
    before = set(_MODULES)
    sys.path.insert(0, str(scan_dir))
    for py in sorted(scan_dir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        try:
            importlib.import_module(py.stem)
        except Exception:
            continue  # a broken module is skipped — it does not drop discovery.
    return len(set(_MODULES) - before)
