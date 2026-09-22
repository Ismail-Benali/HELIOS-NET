"""HELIOS-NET :: run_simulation.py
Unified Autonomous Attack Surface Management & High-Performance Scanning Demonstration.

Executes a cohesive end-to-end ASM pipeline connecting:
  1. Encrypted Transactional WAL (Secure Audit Logging)
  2. High-Performance Async Recon & AIMD Concurrency Control
  3. Asset Graph & Dijkstra Attack Surface Path/Risk Ranking
  4. Verdict Engine & Rule Evaluation
  5. Executive HTML Briefing Report Generation
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from core.async_engine import enterprise_adaptive_recon
from core.reporter_html import generate_html_report
from core.state import CampaignState
from core.wal import TransactionalWAL
from engine.c_matcher_bridge import run_c_matcher
from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine
from engine.verdict import VerdictEngine, default_rules


async def simulate_engagement():
    print("=" * 65)
    print("[HELIOS-NET] INITIATING UNIFIED ASM & SCANNING PIPELINE DEMONSTRATION...")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmp:
        state_dir = Path(tmp)

        # 1. Initialize Secure Encrypted WAL
        wal_path = state_dir / "engagement.wal"
        wal = TransactionalWAL(wal_path)
        wal.begin()
        wal.append("ASM_ENGAGEMENT_INIT", {"operator": "HELIOS-ENGINE", "target": "127.0.0.1"})
        wal.commit()
        print("[+] [Step 1] Secure Encrypted WAL initialized and transaction committed.")

        # 2. Execute Async Recon & AIMD Flow Control
        target = "127.0.0.1"
        ports = [80, 443, 3306, 5432, 22, 445]
        print(f"[+] [Step 2] Executing asynchronous AIMD-paced recon against {target}...")
        active_services = await enterprise_adaptive_recon(target, ports)
        print(f"    -> Discovered active services: {active_services}")

        # 3. Verdict & Rule Evaluation
        print("[+] [Step 3] Evaluating findings through Verdict Engine rules...")
        ve = VerdictEngine(rules=default_rules())
        findings_for_verdict = [{"module": "discovery", "host": target, "port": s["port"], "service": "tcp-service", "open": True} for s in active_services]
        verdicts = ve.judge_all(findings_for_verdict)
        for v in verdicts:
            print(f"    -> Port {v.finding.get('port')} | Severity: {v.to_dict()['severity']} | Rules Hit: {v.rules_hit}")

        # 4. Construct Asset Graph & Dijkstra Risk Ranking
        print("[+] [Step 4] Constructing Asset Graph & calculating Dijkstra risk path...")
        g = AssetGraph()
        host_node = f"host:{target}"
        g.add_node(host_node, "host", ip=target)

        for svc in active_services:
            p = svc["port"]
            svc_node = f"svc:{target}:{p}/tcp"
            g.add_node(svc_node, "service", port=p, name="web-service" if p in [80, 443] else "infrastructure")
            g.add_edge(host_node, svc_node, "runs")

        engine = KillChainEngine(g)
        top_targets = g.top_targets(limit=5)
        print(f"    -> Centrality Ranked Top Targets: {top_targets}")

        path, cost = [], 0.0
        if active_services:
            target_svc = f"svc:{target}:{active_services[0]['port']}/tcp"
            path, cost = engine.find_attack_path(host_node, target_svc)
            print(f"    -> Calculated Engagement Route: {path} (Resistance Cost: {cost})")

        # 5. Generate Self-Contained Executive HTML Briefing Report
        print("[+] [Step 5] Compiling Executive Briefing Report...")
        out_file = state_dir / "executive_report.html"
        state = CampaignState(target=target)
        state.status = "done"
        state.meta["findings_count"] = len(active_services)
        state.meta["graph_nodes"] = len(g.nodes)
        state.meta["graph_edges"] = len(g.adj)
        state.meta["top_targets"] = top_targets

        briefing = {
            "campaign_id": state.campaign_id,
            "target": target,
            "status": "done",
            "findings_count": len(active_services),
            "top_targets": top_targets,
            "events": [
                {"ts": 1788403200.0, "event": "engagement_start", "module": "core"},
                {"ts": 1788403201.5, "event": "aimd_recon_complete", "module": "async_engine"},
                {"ts": 1788403202.0, "event": "verdict_evaluated", "module": "verdict"},
                {"ts": 1788403202.5, "event": "path_computed", "module": "pathfinder"}
            ]
        }
        report_path = generate_html_report(briefing, out_file)
        print(f"    -> Executive HTML Report successfully generated at: {report_path}")

    print("=" * 65)
    print("[HELIOS-NET] UNIFIED ASM & SCANNING DEMONSTRATION COMPLETED.")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(simulate_engagement())
