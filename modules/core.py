"""HELIOS-NET :: modules/core.py
نظام توصيل الوحدات (Module Spawner) — توسّع الوحدات بلا لمس النواة.

الفلسفة:
  بدل سجل إعداد يدوي ثابت، كل وحدة مستقلة تُسجَّل نفسها عبر زخرفة
  `@module()` وتعلن: اسمها، فئتها، و«منفّذها» (runner). ثم يُكشف أي
  مجلد جديد تلقائيًا ويُحمَّل. النظام يبقى قابلاً للنمو دون إعادة بناء.

العقد:
  - الوحدة: كائن يحمل name, kind, runner, ورابط إلى جوهرة مهمتها.
  - السجل عام: يمكن للمحرك أو المنسّق الاستعلام عنه بأي وقت.
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
    """مواصفة وحدة مسجَّلة."""
    name: str
    kind: str
    runner: Runner
    params: dict = field(default_factory=dict)


# السجل العام — وحيد لكل عملية.
_MODULES: dict[str, ModuleSpec] = {}


def module(name: str, kind: str = "generic", **params):
    """زخرفة لوحدة: تُسجّل في السجل بمجرد استيراده.

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
    """يستورد حزمة/مجلدًا، فيتسبّب في تسجيل كل وحداته المزيّنة.

    Returns:
      عدد الوحدات الجديدة المسجّلة بعد الاستيراد.
    """
    before = set(_MODULES)
    importlib.import_module(module_path)
    return len(set(_MODULES) - before)


def discover(scan_dir: Path) -> int:
    """يكشف ويستورد كل ملفات .py جديدة في مجلد، مسجّلًا وحداتها.

    تخطّى الملفات التي نشرت نفسها سابقًا (لا إعادة تسجيل مزدوجة).

    Returns:
      عدد الوحدات الجديدة.
    """
    before = set(_MODULES)
    sys.path.insert(0, str(scan_dir))
    for py in sorted(scan_dir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        try:
            importlib.import_module(py.stem)
        except Exception:
            continue  # وحدة تالفة تتخطّى — لا تُسقط الاكتشاف.
    return len(set(_MODULES) - before)
