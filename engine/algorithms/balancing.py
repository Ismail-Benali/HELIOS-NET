"""HELIOS-NET :: engine/algorithms/balancing.py
فئة خوارزميات الموازنة — أمثلة حيّة لكيف يعمل نظام التوسّع.

تعرض فئتين مقابلتين لنفس الواجهة:
  - lpt:      التوزيع الجشع الحالي (Longest Processing Time).
  - brute:    توزيع مثالي عبر بحث عمق-أول مع تقليم (أدق، أغلى).

كلتاهما تحلّ المسألة نفسها: توزيع وظائف بأوزان على عدد عمال بحيث
يُصغَّر أطول عُمّد (makespan) — وهما نقطة دليل على قابلية التوسّع.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import register_algo


@dataclass
class LoadResult:
    """نتيجة توزيع: دلاء مؤشرات (indices) إلى القائمة الأصلية + makespan."""
    buckets: list[list[int]]
    makespan: float

    def index_buckets(self) -> list[list[int]]:
        return self.buckets


def _lpt(weights: list[float], workers: int) -> LoadResult:
    """جشع LPT: يرتّب الأثقل أولًا ويضعه على أصغر محمّل حاليًا.

    يعمل على (مؤشر، ثقل) فيُحفظ الربط بالمصدر الأصلي.
    """
    indexed = sorted(enumerate(weights), key=lambda x: x[1], reverse=True)
    buckets: list[list[int]] = [[] for _ in range(workers)]
    loads = [0.0] * workers
    for idx, w in indexed:
        i = min(range(workers), key=lambda k: loads[k])
        buckets[i].append(idx)
        loads[i] += w
    return LoadResult(buckets=[b for b in buckets if b], makespan=max(loads) if loads else 0.0)


def _brute(weights: list[float], workers: int) -> LoadResult:
    """بحث عمق-أول للتوازن الأمثل (+ تقليم + كسر تناظر العمال).

    يبني دلاء مؤشرات، فيبقى الربط بالمصدر محفوظًا. أغلى من LPT —
    مثال حيّ على أن تبديل الخوارزمية مؤثر لا تجميلي.
    """
    best = (None, float("inf"))
    buckets: list[list[int]] = [[] for _ in range(workers)]

    def dfs(i: int, loads: list[float]) -> None:
        nonlocal best
        if i == len(weights):
            mk = max(loads) if loads else 0.0
            if mk < best[1]:
                best = ([list(b) for b in buckets], mk)
            return
        if max(loads) >= best[1]:
            return  # تقليم: لا يمكن تحسين حل يتجاوز الأفضل.
        seen: set[float] = set()
        for w in range(workers):
            if loads[w] in seen:
                continue
            seen.add(loads[w])
            buckets[w].append(i)
            loads[w] += weights[i]
            dfs(i + 1, loads)
            loads[w] -= weights[i]
            buckets[w].pop()

    dfs(0, [0.0] * workers)
    if best[0] is None:
        return _lpt(weights, workers)  # سقوط أمان.
    return LoadResult(buckets=best[0], makespan=best[1])


# -- التسجيل في السجل المركزي -------------------------------------------
register_algo("balancing", "lpt", _lpt, default=True)
register_algo("balancing", "brute", _brute)


def solve(kind: str = "lpt", weights: list[float] | None = None,
          workers: int = 3) -> LoadResult:
    """البوابة العامّة — يستدعيها المحرّك عند تغيير الخوارزمية."""
    from . import get_algo
    if not weights:
        return LoadResult(buckets=[[] for _ in range(workers)], makespan=0.0)
    try:
        algo = get_algo("balancing", kind)
    except Exception:
        algo = _lpt
    return algo(weights, workers)
