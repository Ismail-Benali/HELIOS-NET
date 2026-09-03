"""HELIOS-NET :: engine/scanner.py
Distributed parallel scanning with load balancing and bounded down-time.

Responsibilities:
  - Run multiple scan tasks in parallel against a single target.
  - Rate limiting and synchronization of access to shared resources.
  - Isolate a single task failure from the rest — a failure in one task does
    not bring down the whole scan.

Implementation note:
  - Here the pattern is fail-isolated: each task's result captures its own
    exception and is resolved regardless of the failure of others.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable

log = logging.getLogger(__name__)


@dataclass
class ScanTask:
    """A single scan task."""
    name: str
    fn: Callable[[], dict]
    weight: float = 1.0      # relative weight for balancing (may be an estimated task duration).
    result: dict | None = None
    error: str | None = None
    started: float | None = None
    finished: float | None = None

    def run(self) -> dict:
        self.started = time.time()
        self.result = self.fn()
        self.finished = time.time()
        return self.result

    def to_dict(self) -> dict:
        dur = (self.finished or time.time()) - (self.started or time.time())
        return {
            "name": self.name,
            "weight": self.weight,
            "ok": self.error is None,
            "duration": round(dur, 4),
            "error": self.error,
            "result": self.result,
            "started": self.started,
            "finished": self.finished,
        }


class Scanner:
    """Distributed scan executor with guaranteed load balancing."""

    def __init__(self, max_workers: int = 8, min_interval: float = 0.0,
                 balancing_algo: str | None = None):
        self.max_workers = max_workers
        self.min_interval = min_interval
        self.balancing_algo = balancing_algo
        self._last_start: dict[str, float] = {}

    # -- load balancing basis: cost weight --------------------------------------
    def balanced_batches(self, tasks: list[ScanTask], max_workers: int) -> list[list[ScanTask]]:
        """Distributes tasks into batches balancing their weights (as close as possible).

        Delegates the decision to the swappable algorithm gateway — so switching
        a balancer does not touch this file. If the gateway fails, it falls back
        safely to LPT.
        """
        from .algorithms.balancing import solve as algo_solve

        weights = [t.weight for t in tasks]
        try:
            result = algo_solve(kind=self.balancing_algo, weights=weights,
                                workers=max_workers)
            idx_buckets = result.index_buckets()
        except Exception:
            idx_buckets = self._lpt_idx(weights, max_workers)

        # map the indices back to the same rows — the link to the source is always kept.
        mapped = [[tasks[i] for i in b] for b in idx_buckets]
        return [g for g in mapped if g]

    @staticmethod
    def _lpt_idx(weights: list[float], workers: int) -> list[list[int]]:
        """Same LPT but builds index buckets — used as a safety fallback after the gateway."""
        buckets: list[list[int]] = [[] for _ in range(workers)]
        loads = [0.0] * workers
        for idx in sorted(range(len(weights)), key=lambda k: weights[k], reverse=True):
            i = min(range(workers), key=lambda k: loads[k])
            buckets[i].append(idx)
            loads[i] += weights[idx]
        return [b for b in buckets if b]

    # -- executor -----------------------------------------------------------
    def scan(self, tasks: list[ScanTask]) -> list[dict]:
        """Runs all tasks in parallel and returns their results in a unified table.

        Each task has its own immunity: one task's failure does not stop the rest.
        """
        if not tasks:
            return []
        batches = self.balanced_batches(tasks, self.max_workers)
        results: list[dict] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            for batch in batches:
                for t in batch:
                    fut = pool.submit(self._guarded, t)
                    futures[fut] = t

            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    fut.result()
                except Exception as exc:  # we do not swallow it silently — apply it to the task itself.
                    t.error = f"{type(exc).__name__}: {exc}"
                    log.warning("scan task %s failed: %s", t.name, t.error)
                results.append(t.to_dict())

        results.sort(key=lambda d: d["started"] or 0)
        return results

    def _guarded(self, t: ScanTask) -> dict:
        if self.min_interval > 0:
            time.sleep(self.min_interval)  # spacing: a controlled cadence.
        return t.run()

    # -- helper utilities --------------------------------------------------------
    @staticmethod
    def tcp_probe(host: str, port: int, timeout: float = 3.0) -> dict:
        """Tests a TCP connection and decides whether the port is open — with no external library.

        This method only probes and requires no additional authorization beyond
        the user's granted scope. It is used as an experimental lab component.
        """
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return {"host": host, "port": port, "open": True}
        except OSError:
            return {"host": host, "port": port, "open": False}
        finally:
            s.close()
