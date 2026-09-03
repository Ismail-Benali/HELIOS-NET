"""HELIOS-NET :: run_simulation.py
End-to-End Cinematic Live Simulation Script.

Executes a full operational combat simulation connecting:
  1. Encrypted Transactional WAL (Secure Logging)
  2. Industrial Async Recon Engine & Go/C Bridge
  3. Asset Graph & Dijkstra Kill-Chain Pathfinding
  4. Autonomous Mutation Engine & Self-Healing
  5. Executive Briefing Report Generation
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from core.async_engine import enterprise_adaptive_recon
from core.mutation_engine import MutationEngine
from core.reporter import generate_executive_briefing
from core.state import CampaignState
from core.wal import TransactionalWAL
from engine.c_matcher_bridge import run_c_matcher
from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine


async def simulate_combat_mission():
    print("=" * 60)
    print("[HELIOS-NET] INITIATING END-TO-END COMBAT SIMULATION...")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        state_dir = Path(tmp)

        # 1. Initialize Secure Encrypted WAL
        wal_path = state_dir / "combat_mission.wal"
        wal = TransactionalWAL(wal_path)
        wal.begin()
        wal.append("MISSION_INIT", {"operator": "Demiurg", "target": "127.0.0.1"})
        wal.commit()
        print("[+] [Step 1] Secure Encrypted WAL initialized and transaction committed.")

        # 2. Execute Async Recon on Local Target (127.0.0.1)
        target = "127.0.0.1"
        print(f"[+] [Step 2] Executing asynchronous recon probe against {target}...")
        active_services = await enterprise_adaptive_recon(target, [80, 443, 3306, 5432])
        print(f"    -> Discovered active services: {active_services}")

        # 3. Native C-powered Banner/Signature Matcher Test
        print("[+] [Step 3] Running native C memory banner analysis...")
        sample_banner = "Server: nginx/1.18.0 and OpenSSH_8.2p1 running securely"
        c_matches = run_c_matcher(sample_banner)
        print(f"    -> C Native Matcher detected signatures: {c_matches}")

        # 4. Build Asset Graph & Compute Kill-Chain Pathfinding
        print("[+] [Step 4] Constructing Asset Graph & calculating Dijkstra Kill-Chain path...")
        g = AssetGraph()
        host_node = f"host:{target}"
        g.add_node(host_node, "host", ip=target)

        for svc in active_services:
            p = svc["port"]
            svc_node = f"svc:{target}:{p}/tcp"
            g.add_node(svc_node, "service", port=p, name="web-service" if p in [80, 443] else "database")
            g.add_edge(host_node, svc_node, "runs")

        engine = KillChainEngine(g)
        top_targets = g.top_targets(limit=5)
        print(f"    -> Centrality Ranked Top Targets: {top_targets}")

        path, cost = [], 0.0
        if active_services:
            target_svc = f"svc:{target}:{active_services[0]['port']}/tcp"
            path, cost = engine.find_attack_path(host_node, target_svc)
            print(f"    -> Calculated Attack Path: {path} (Resistance Cost: {cost})")

        # 5. Simulate Trap Detection & Autonomous Mutation (Self-Healing)
        print("[+] [Step 5] Simulating WAF/Honeypot trap detection & self-healing mutation...")
        mutator = MutationEngine(state_dir)
        trap_detected = mutator.detect_trap(response_latency=6.5, http_status=200)
        print(f"    -> Anomaly/Trap Triggered: {trap_detected}")
        
        mutation_result = mutator.trigger_self_destruct_and_mutate()
        print(f"    -> Mutation Executed: Generation {mutation_result['generation']} (Traces shredded: {mutation_result['traces_shredded']})")

        # 6. Generate Executive Briefing Report
        print("[+] [Step 6] Compiling Executive Briefing Report...")
        state = CampaignState(target=target)
        state.status = "done"
        state.meta["findings_count"] = len(active_services)
        state.meta["graph_nodes"] = len(g.nodes)
        state.meta["graph_edges"] = len(g.adj)
        state.meta["top_targets"] = top_targets

        report_data = {
            "timeline": [
                {"ts": 1788403200.0, "event": "mission_start", "module": "core"},
                {"ts": 1788403201.5, "event": "async_recon_complete", "module": "async_engine"},
                {"ts": 1788403202.0, "event": "killchain_computed", "module": "pathfinder"},
                {"ts": 1788403203.1, "event": "mutation_triggered", "module": "mutation_engine"}
            ]
        }

        briefing = generate_executive_briefing(state, report_data)
        print("\n" + "=" * 60)
        print(briefing)
        print("=" * 60)
        print("[HELIOS-NET] COMBAT SIMULATION COMPLETED WITH ABSOLUTE SUPREMACY.")


if __name__ == "__main__":
    asyncio.run(simulate_combat_mission())
