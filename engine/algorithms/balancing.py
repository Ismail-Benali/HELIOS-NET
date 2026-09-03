"""HELIOS-NET :: engine/algorithms/balancing.py
Balancing algorithm family — live examples of how the extensibility works.

Exposes two contrasting classes behind the same interface:
  - lpt:      the current greedy distribution (Longest Processing Time).
  - brute:    optimal distribution via pruned depth-first search (slower, costlier).

Both solve the same problem: distributing weighted jobs over a number of
workers so the longest column (makespan) is minimized — a demonstration of
extensibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import register_algo


@dataclass
class LoadResult:
    """Load distribution result: index buckets into the original list + makespan."""
    buckets: list[list[int]]
    makespan: float

    def index_buckets(self) -> list[list[int]]:
        return self.buckets


def _lpt(weights: list[float], workers: int) -> LoadResult:
    """Greedy LPT: orders the heaviest first and places it on the least loaded.

    Works on (index, weight) pairs so the link to the original source is kept.
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
    """Depth-first search for optimal balancing (+ pruning + worker symmetry tiebreak).

    Builds index buckets, keeping the link to the source intact. Costlier than LPT —
    a live example that switching algorithms is functional, not cosmetic.
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
            return  # prune: cannot improve on a solution that already beats the best.
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
        return _lpt(weights, workers)  # safety fallback.
    return LoadResult(buckets=best[0], makespan=best[1])


# -- registration in the central registry ----------------------------------
register_algo("balancing", "lpt", _lpt, default=True)
register_algo("balancing", "brute", _brute)


def solve(kind: str = "lpt", weights: list[float] | None = None,
          workers: int = 3) -> LoadResult:
    """The public gateway — invoked by the engine when switching algorithms."""
    from . import get_algo
    if not weights:
        return LoadResult(buckets=[[] for _ in range(workers)], makespan=0.0)
    try:
        algo = get_algo("balancing", kind)
    except Exception:
        algo = _lpt
    return algo(weights, workers)
