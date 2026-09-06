"""HELIOS-NET :: core/daemon.py
Continuous Autonomous Mission Daemon.

Operates as a silent background agent executing the full Helios loop:
Recon -> Pathfinding -> Mutation/Self-Healing -> Executive Briefing.
Zero human intervention required.
"""

from __future__ import annotations

__all__ = ["AutonomousDaemon"]

import asyncio
import logging
import time
from pathlib import Path

from core.async_engine import enterprise_adaptive_recon
from core.mutation_engine import MutationEngine
from core.wal import TransactionalWAL
from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine
from modules.stealth.pacer import Pacer

log = logging.getLogger(__name__)


class AutonomousDaemon:
    """Autonomous background security intelligence daemon."""

    def __init__(self, target: str, state_dir: str | Path, interval_seconds: float = 30.0):
        self.target = target
        self.state_dir = Path(state_dir)
        self.interval = interval_seconds
        self.wal = TransactionalWAL(self.state_dir / "daemon_missions.wal")
        self.mutator = MutationEngine(self.state_dir)
        self.pacer = Pacer(mean_dwell=self.interval, jitter=self.interval * 0.35)
        self._running = False

    async def run_mission_cycle(self) -> None:
        """Executes a single autonomous mission cycle."""
        log.info(f"[DAEMON] Initiating autonomous mission cycle against target: {self.target}")
        
        # 1. Transactional WAL logging start
        self.wal.begin()
        self.wal.append("MISSION_START", {"target": self.target, "timestamp": time.time()})
        
        try:
            # 2. Async recon probe
            ports = [80, 443, 22, 3306]
            active_services = await enterprise_adaptive_recon(self.target, ports)
            
            # 3. Graph & Kill-Chain analysis
            g = AssetGraph()
            host_node = f"host:{self.target}"
            g.add_node(host_node, "host", ip=self.target)
            
            for svc in active_services:
                p = svc["port"]
                svc_node = f"svc:{self.target}:{p}/tcp"
                g.add_node(svc_node, "service", port=p)
                g.add_edge(host_node, svc_node, "runs")
                
            engine = KillChainEngine(g)
            top_targets = g.top_targets(limit=3)
            
            # 4. Check for anomalies / trap triggers
            if not active_services:
                # Trigger self-healing mutation if target appears walled or honeyed
                mutation_event = self.mutator.trigger_self_destruct_and_mutate()
                self.wal.append("MUTATION_TRIGGERED", mutation_event)
            else:
                self.wal.append("MISSION_SUCCESS", {"active_services": len(active_services), "top_targets": top_targets})

            self.wal.commit()
            log.info(f"[DAEMON] Mission cycle completed successfully. Top targets: {top_targets}")

        except Exception as exc:
            self.wal.rollback()
            log.error(f"[DAEMON] Mission cycle failed: {exc}")

    async def start(self) -> None:
        """Starts the infinite autonomous daemon loop with probabilistic behavioral jitter."""
        self._running = True
        log.info("[DAEMON] Autonomous Helios Daemon activated in background with stealth jitter.")
        while self._running:
            await self.run_mission_cycle()
            dwell_time = self.pacer.dwell("exponential")
            await asyncio.sleep(dwell_time)

    def stop(self) -> None:
        self._running = False
        log.info("[DAEMON] Autonomous Helios Daemon deactivated.")
