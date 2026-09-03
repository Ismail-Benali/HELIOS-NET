"""HELIOS-NET :: engine/algorithms — نظام الخوارزميات القابلة للتبديل.

أدراج الفئات الفرعية (balancing, fingerprint, ...) تلقائيًا كي يُملأ
السجل المركزي بمجرد استيراد الحزمة.

الفلسفة:
  كل خوارزمية مسجَّلة في سجل مركزي موحّد، تحمل اسماً وواجهة ثابتة.
  تبديل الخوارزمية (توزيع، بصمة، ...) يتم بالاسم دون لمس النواة.
"""

from __future__ import annotations

import importlib

from typing import Callable, TypeVar

T = TypeVar("T")


class AlgorithmError(Exception):
    """خطأ تنفيذ خوارزمية — يُعزل كي لا يُسقط الحملة."""


# سجل مركزي: فئة الخوارزمية -> {اسم الخوارزمية -> مُنشئ/دالة}. نموذج عام.
ALGO_REGISTRY: dict[str, dict[str, Callable[..., T]]] = {}
DEFAULT_FALLBACK = "__default__"


def register_algo(kind: str, name: str, factory: Callable[..., T], default: bool = False) -> None:
    """يسجّل خوارزمية في الفئة المعنية، مع اختيار الاحتياطية الافتراضية."""
    bucket = ALGO_REGISTRY.setdefault(kind, {})
    bucket[name] = factory
    if default:
        bucket[DEFAULT_FALLBACK] = factory


def get_algo(kind: str, name: str | None = None):
    """يستخرج خوارزمية، مع سقوط أمن إلى الاحتياطية عند الغياب."""
    bucket = ALGO_REGISTRY.get(kind)
    if not bucket:
        raise AlgorithmError(f"no algorithm class {kind!r}")
    if name and name in bucket:
        return bucket[name]
    if DEFAULT_FALLBACK in bucket:
        return bucket[DEFAULT_FALLBACK]
    return next(iter(bucket.values()))


def list_algos(kind: str | None = None) -> dict:
    if kind is not None:
        return {kind: sorted(ALGO_REGISTRY.get(kind, {}).keys())}
    return {k: sorted(v.keys()) for k, v in ALGO_REGISTRY.items()}


# تحميل فئات الخوارزميات الفرعية المسجَّلة تلقائيًا.
for _m in ("balancing", "fingerprint"):
    try:
        importlib.import_module(f".{_m}", __name__)
    except Exception:
        pass
