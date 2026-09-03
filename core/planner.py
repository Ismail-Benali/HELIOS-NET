"""HELIOS-NET :: core/planner.py
Operation planning and converting intelligence discoveries into execution steps.

Responsibilities:
  - Takes raw intelligence from modules and structures it into a priority plan.
  - Enforces scheduling: dependencies, concurrency, and max task limits.
  - Pure planning intelligence; does not execute actions directly.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlanStep:
    """A single step within a campaign plan."""
    step_id: int
    module: str
    action: str
    target: str
    priority: int = 100          # Lower = higher priority
    depends_on: list[int] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"      # pending | ready | running | done | failed

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "module": self.module,
            "action": self.action,
            "target": self.target,
            "priority": self.priority,
            "depends_on": list(self.depends_on),
            "params": self.params,
            "status": self.status,
        }


class Planner:
    """Transforms raw intelligence into executable step plans."""

    MODULE_PRIORITY = {
        "discovery": 10,
        "recon": 20,
        "stealth": 30,
        "exfil": 40,
    }

    def __init__(self, max_concurrency: int = 8):
        self.max_concurrency = max_concurrency
        self._step_counter = 0

    def _next_id(self) -> int:
        self._step_counter += 1
        return self._step_counter

    def plan(self, intelligence: list[dict], target: str) -> list[PlanStep]:
        steps: list[PlanStep] = []

        discovery_items = [i for i in intelligence if i.get("module") == "discovery"]
        recon_items = [i for i in intelligence if i.get("module") == "recon"]
        extra_items = [i for i in intelligence if i.get("module") not in ("discovery", "recon", "stealth", "exfil")]

        # 1) Discovery is always guaranteed on the target
        if not discovery_items:
            steps.append(self._mk("discovery", "scan", target, self.MODULE_PRIORITY["discovery"]))
        for it in discovery_items:
            steps.append(self._mk(it.get("module", "discovery"), it.get("action", "scan"), target,
                                 it.get("priority", self.MODULE_PRIORITY["discovery"])))

        # 2) Deep recon depends on discovery results
        for it in recon_items:
            dep_ids = [s.step_id for s in steps]
            steps.append(self._mk(it.get("module", "recon"), it.get("action", "fingerprint"), target,
                                  it.get("priority", self.MODULE_PRIORITY["recon"]), depends_on=dep_ids))

        # 2b) Extended/plugin modules executed after discovery
        for it in extra_items:
            dep_ids = [s.step_id for s in steps]
            steps.append(self._mk(it["module"], it.get("action", "run"), target,
                                  it.get("priority", 25), depends_on=dep_ids))

        # 3) Stealth pacing
        for it in [i for i in intelligence if i.get("module") == "stealth"]:
            steps.append(self._mk("stealth", it.get("action", "pace"), target,
                                  self.MODULE_PRIORITY["stealth"], depends_on=[s.step_id for s in steps]))

        # 4) Data collection / reporting
        if steps:
            steps.append(self._mk("exfil", "collect", target,
                                  self.MODULE_PRIORITY["exfil"], depends_on=[s.step_id for s in steps]))

        steps.sort(key=lambda s: (s.priority, s.step_id))
        return steps

    def _mk(self, module: str, action: str, target: str, priority: int, depends_on: list[int] | None = None) -> PlanStep:
        return PlanStep(step_id=self._next_id(), module=module, action=action, target=target,
                        priority=priority, depends_on=list(depends_on or []))

    def schedule(self, steps: list[PlanStep]) -> list[list[PlanStep]]:
        """Distributes steps into parallel waves of execution."""
        done: set[int] = set()
        waves: list[list[PlanStep]] = []
        remaining = {s.step_id: s for s in steps}

        while remaining:
            wave = [s for s in remaining.values()
                    if all(d in done for d in s.depends_on)]
            if not wave:
                deadlock = min(remaining.values(), key=lambda s: s.step_id)
                wave = [deadlock]
            wave.sort(key=lambda s: s.priority)
            waves.append(wave[:self.max_concurrency])
            for s in wave[:self.max_concurrency]:
                done.add(s.step_id)
                del remaining[s.step_id]
        return waves

    def to_json(self, steps: list[PlanStep]) -> str:
        return json.dumps([s.to_dict() for s in steps], ensure_ascii=False, indent=2)

    def from_json(self, text: str) -> list[PlanStep]:
        steps = []
        for d in json.loads(text):
            steps.append(PlanStep(step_id=d["step_id"], module=d["module"], action=d["action"],
                                  target=d["target"], priority=d.get("priority", 100),
                                  params=d.get("params", {}), status=d.get("status", "pending")))
            steps[-1].depends_on = list(d.get("depends_on", []))
        return steps
