"""HELIOS-NET :: engine/ai/adaptive_learner.py
Adaptive Reinforcement Learning Engine (Pure Math Multi-Armed Bandit).

Dynamically adjusts scanning speed and evasion strategies in real-time
based on WAF/IDS feedback and target response latencies, using pure Python.
"""

from __future__ import annotations

import random
from typing import List


class EpsilonGreedyBandit:
    """Multi-Armed Bandit for dynamic scan speed optimization."""

    def __init__(self, arms: List[float], epsilon: float = 0.1):
        # arms represent different scan rates (requests per second)
        self.arms = arms
        self.epsilon = epsilon
        self.counts = [0] * len(arms)
        self.values = [0.0] * len(arms)

    def select_arm(self) -> int:
        """Selects optimal scan rate using Epsilon-Greedy strategy."""
        if random.random() < self.epsilon:
            return random.randint(0, len(self.arms) - 1)
        return self.values.index(max(self.values))

    def update(self, arm_index: int, reward: float) -> None:
        """Updates reward estimation for the selected scan rate."""
        self.counts[arm_index] += 1
        n = self.counts[arm_index]
        value = self.values[arm_index]
        # Incremental average update
        self.values[arm_index] = value + (reward - value) / n

    def get_optimal_rate(self) -> float:
        """Returns the currently learned optimal scan rate."""
        best_idx = self.values.index(max(self.values))
        return self.arms[best_idx]
