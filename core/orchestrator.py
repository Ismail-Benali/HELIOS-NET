"""HELIOS-NET :: core/orchestrator.py
Central Master Mind — Orchestrates campaign lifecycle from planning to reporting.

Responsibilities:
  - Drives the closed-loop intelligence cycle: recon -> planning -> execution -> feedback.
  - Manages campaign state via StateStore and logs audit events.
  - Executes plans in parallel bounded waves.
  - Fault tolerant: module failures are isolated and logged without crashing the system.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from .planner import PlanStep, Planner
from .state import CampaignState, StateStore

ModuleRunner = Callable[[PlanStep, dict], dict]


class Orchestrator:
    """Central orchestrator for HELIOS-NET campaigns."""

    def __init__(self, store: StateStore, reg: dict[str, ModuleRunner] | None = None,
                 max_workers: int = 8):
        self.store = store
        self.planner = Planner(max_concurrency=max_workers)
        self.max_workers = max_workers
        self._registry: dict[str, ModuleRunner] = dict(reg or {})
        self._context: dict = {"timestamps": {}, "findings": [], "reports": [], "meta": {}}

    def register(self, name: str, runner: ModuleRunner) -> None:
        if not callable(runner):
            raise TypeError(f"runner for {name!r} must be callable")
        self._registry[name] = runner

    def run_campaign(self, target: str, intelligence: list[dict] | None = None) -> CampaignState:
        """Executes a full campaign against the specified target."""
        state = CampaignState(target=target)
        state.transition("planning")
        self.store.save(state)
        self.store.log_event(state, "campaign_start", target=target)

        steps = self.planner.plan(list(intelligence or []), target)
        waves = self.planner.schedule(steps)

        state.transition("scanning")
        self.store.save(state)

        plan_hash = self.planner.to_json(steps)
        self._context["plan"] = steps
        self.store.log_event(state, "plan_built", steps=plan_hash)

        try:
            self._execute_waves(state, waves)
        except Exception as exc:
            state.transition("failed")
            self.store.save(state)
            self.store.log_event(state, "campaign_failed", error=str(exc), ts=time.time())
            raise

        state.transition("done")
        state.meta["findings_count"] = len(self._context.get("findings", []))
        state.meta["report_count"] = len(self._context.get("reports", []))
        state.meta["plan"] = plan_hash
        self._finalize_graph(state)
        self.store.save(state)
        self.store.log_event(state, "campaign_done", findings=state.meta["findings_count"])
        return state

    def _finalize_graph(self, state: CampaignState) -> None:
        """Builds asset graph from findings and records high-centrality targets."""
        try:
            from engine.graph.core import AssetGraph
            g = AssetGraph()
            g.ingest(state.meta.get("findings", []) or self._context.get("findings", []))
            state.meta["graph_nodes"] = len(g.nodes)
            state.meta["graph_edges"] = len(g.adj)
            state.meta["top_targets"] = g.top_targets(limit=8)
        except Exception as exc:
            state.meta["graph_error"] = str(exc)

    def _execute_waves(self, state: CampaignState, waves: list[list[PlanStep]]) -> None:
        for wave in waves:
            if state.status == "aborted":
                break
            self._run_wave(state, wave)

    def _run_wave(self, state: CampaignState, wave: list[PlanStep]) -> None:
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._safe_run, state, step): step for step in wave}
            for fut in as_completed(futures):
                step = futures[fut]
                try:
                    result = fut.result()
                    if result:
                        self._context.setdefault("reports", []).append(result)
                except Exception as exc:
                    step.status = "failed"
                    self.store.log_event(state, "step_failed",
                                         module=step.module, action=step.action, error=str(exc))

    def _safe_run(self, state: CampaignState, step: PlanStep) -> dict | None:
        """Safely executes a module step, isolating failures."""
        runner = self._registry.get(step.module)
        if runner is None:
            self.store.log_event(state, "module_missing", module=step.module)
            return None
        step.status = "running"
        self.store.log_event(state, "step_start", module=step.module, action=step.action, step_id=step.step_id)
        try:
            result = runner(step, self._context)
            step.status = "done"
            self.store.log_event(state, "step_done", module=step.module, action=step.action, step_id=step.step_id)
            return result
        except Exception as exc:
            step.status = "failed"
            self.store.log_event(state, "step_failed",
                                 module=step.module, action=step.action, error=str(exc))
            return None

    def recover(self, campaign_id: str) -> CampaignState:
        """Recovers campaign state from disk storage."""
        state = self.store.load(campaign_id)
        self.store.log_event(state, "campaign_recovered")
        return state

    def report(self, state: CampaignState) -> dict:
        """Generates a structured audit report from campaign state and logs."""
        events = self.store.read_log(state.campaign_id)
        return {
            "campaign_id": state.campaign_id,
            "target": state.target,
            "status": state.status,
            "summary": state.meta,
            "timeline": events,
        }
