"""HELIOS-NET :: engine/scanner.py
مسح موزّع متوازٍ مع موازنة حمل وحد  down-time.

المسؤولية:
  - تشغيل مهام مسح متعددة بالتوازي على هدف واحد.
  - الحد من التركيز (rate-limit) ومزامنة وصول الموارد المشتركة.
  - عزل فشل مهمة واحدة عن البقية — لا ينهار المسح بأكمله بخطأ مهامٍ واحدة.

ملاحظة تطبيقية:
  - هنا النمط (قاتل الخطأ): نتائج كل مهمة يُلتقط لها استثناءها الخاص،
    وتُعرب (تُنجَز) بصرف النظر عن فشل الآخرين.
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
    """مهمة مسح واحدة."""
    name: str
    fn: Callable[[], dict]
    weight: float = 1.0      # ثقل نسبي للموازنة (قد يكون مدة تقديرية للمهمة).
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
    """منفّذ مسح موزّع بموازنة حمل مضمونة."""

    def __init__(self, max_workers: int = 8, min_interval: float = 0.0,
                 balancing_algo: str | None = None):
        self.max_workers = max_workers
        self.min_interval = min_interval
        self.balancing_algo = balancing_algo
        self._last_start: dict[str, float] = {}

    # -- أساس موازنة الحمل: ثقل الكلفة --------------------------------------
    def balanced_batches(self, tasks: list[ScanTask], max_workers: int) -> list[list[ScanTask]]:
        """يوزّع المهام على دفعات فتتوازن أوزانها (أقرب ما أمكن).

        يفوض القرار إلى بوابة الخوارزميات القابلة للتبديل — فتبديل موزّن
        لا يلمس هذا الملف. إن تعثّرت بوابة الخوارزميات، يسقط أمنًا إلى LPT.
        """
        from .algorithms.balancing import solve as algo_solve

        weights = [t.weight for t in tasks]
        try:
            result = algo_solve(kind=self.balancing_algo, weights=weights,
                                workers=max_workers)
            idx_buckets = result.index_buckets()
        except Exception:
            idx_buckets = self._lpt_idx(weights, max_workers)

        # ردّ المؤشرات إلى الأسطر ذاتها — الربط بالمصدر محفوظ دائمًا.
        mapped = [[tasks[i] for i in b] for b in idx_buckets]
        return [g for g in mapped if g]

    @staticmethod
    def _lpt_idx(weights: list[float], workers: int) -> list[list[int]]:
        """نفس LPT لكن يبني دلاء مؤشرات — يستخدم كاحتياط أمني بعد البوابة."""
        buckets: list[list[int]] = [[] for _ in range(workers)]
        loads = [0.0] * workers
        for idx in sorted(range(len(weights)), key=lambda k: weights[k], reverse=True):
            i = min(range(workers), key=lambda k: loads[k])
            buckets[i].append(idx)
            loads[i] += weights[idx]
        return [b for b in buckets if b]

    # -- المنفّذ -----------------------------------------------------------
    def scan(self, tasks: list[ScanTask]) -> list[dict]:
        """ينفّذ كل المهام موازيًا ويعيد نتائجها بجدول موحّد.

        كل مهمة تملك حصانتها: خطأ مهمة واحدة لا يوقف البقية.
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
                except Exception as exc:  # لا نسكت — نُطبق على المهمة ذاتها.
                    t.error = f"{type(exc).__name__}: {exc}"
                    log.warning("scan task %s failed: %s", t.name, t.error)
                results.append(t.to_dict())

        results.sort(key=lambda d: d["started"] or 0)
        return results

    def _guarded(self, t: ScanTask) -> dict:
        if self.min_interval > 0:
            time.sleep(self.min_interval)  # تباعد: إيقاع مضبوط.
        return t.run()

    # -- أدوات مساعدة --------------------------------------------------------
    @staticmethod
    def tcp_probe(host: str, port: int, timeout: float = 3.0) -> dict:
        """يلمس اتصال TCP ويقرر هل المنفذ مفتوح — بلا مكتبة خارجية.

        هذه الطريقة تلمس فقط، ولا تحتاج تفويضًا إضافيًا خارج نطاق المستخدم.
        تُستخدم كمكوّن تجريبي في المختبر.
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
