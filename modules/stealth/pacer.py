"""HELIOS-NET :: modules/stealth/pacer.py
Stealth: advanced probabilistic pacing (exponential/Poisson distribution).

Simulates natural network noise and human-like movement variance, making it
hard for intrusion detection systems (IDS/IPS) to spot the repetitive scanning
pattern.
"""

from __future__ import annotations

import math
import random


class Pacer:
    """An advanced probabilistic pacing runner."""

    def __init__(self, mean_dwell: float = 0.3, jitter: float = 0.15, rng=None):
        self.mean_dwell = max(0.01, mean_dwell)
        self.jitter = max(0.0, jitter)
        self._rng = rng or random.Random()

    def dwell(self, mode: str = "exponential") -> float:
        """Computes the next time gap with a realistic probabilistic distribution.

        Args:
          mode: 'exponential' (an exponential distribution simulating queue
                wait-times) or 'uniform' (constant + jitter).
        """
        if mode == "exponential":
            # exponential distribution: -mean * ln(1 - U)
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
