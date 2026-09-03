"""HELIOS-NET :: modules/stealth/pacer.py
التخفي: إيقاع احتمالي متقدّم (توزيع أسي/بواسون).

يحاكي ضوضاء الشبكة الطبيعية وتفاوت الحركة البشرية، مما يُعجز
أنظمة كشف التسلل (IDS/IPS) عن رصد النمط التكراري للمسح.
"""

from __future__ import annotations

import math
import random


class Pacer:
    """مسيّر إيقاع احتمالي متقدّم."""

    def __init__(self, mean_dwell: float = 0.3, jitter: float = 0.15, rng=None):
        self.mean_dwell = max(0.01, mean_dwell)
        self.jitter = max(0.0, jitter)
        self._rng = rng or random.Random()

    def dwell(self, mode: str = "exponential") -> float:
        """يحسب الفجوة الزمنية التالية بتوزيع احتمالي واقعي.

        Args:
          mode: 'exponential' (توزيع أسي يحاكي طوابير الانتظار) أو 'uniform' (ثابت+مشوش).
        """
        if mode == "exponential":
            # التوزيع الأسي: -mean * ln(1 - U)
            u = max(1e-6, self._rng.random())
            val = -self.mean_dwell * math.log(u)
            return max(0.01, val + self._rng.uniform(-self.jitter, self.jitter))
        else:
            return max(0.0, self.mean_dwell + self._rng.uniform(-self.jitter, self.jitter))

    def wait(self, mode: str = "exponential") -> float:
        import time
        d = self.dwell(mode)
        time.sleep(d)
        return d

    def schedule(self, steps: int, mode: str = "exponential") -> list[float]:
        return [self.dwell(mode) for _ in range(steps)]


def strip_artifacts(text: str, artifacts: list[str] | None = None) -> str:
    artifacts = artifacts or ["helios", "helios-net", "H3l!0s"]
    lines = []
    for line in (text or "").splitlines():
        if any(a.lower() in line.lower() for a in artifacts):
            continue
        lines.append(line)
    return "\n".join(lines)
