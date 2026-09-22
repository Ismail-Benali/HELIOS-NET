"""
HELIOS-NET :: Authorized Engagement Runner (strike.py)
Executes authorized attack surface management and route planning against user-specified targets
integrated with the central Orchestrator, StateStore, and HTML Reporting engine.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import Orchestrator
from core.state import StateStore
from core.reporter_html import generate_html_report
from modules.registry import default_registry


def main() -> int:
    parser = argparse.ArgumentParser(description="HELIOS-NET Authorized Engagement Orchestrator")
    parser.add_argument("--target", default="127.0.0.1", help="Target domain or IP (default: 127.0.0.1)")
    parser.add_argument("--data", default=str(ROOT / "data"), help="Campaign data directory")
    args = parser.parse_args()

    print(f"[HELIOS-NET] Initializing authorized campaign engagement against target: {args.target}")
    
    store = StateStore(args.data)
    orch = Orchestrator(store=store, reg=default_registry())
    
    state = orch.run_campaign(args.target)
    rep = orch.report(state)
    
    print(f"[HELIOS] Campaign {state.campaign_id} completed with status: {state.status}")
    print(f"[HELIOS] Findings collected: {state.meta.get('findings_count', 0)}")
    print(f"[HELIOS] Asset graph nodes: {state.meta.get('graph_nodes', 0)}, edges: {state.meta.get('graph_edges', 0)}")
    
    if state.meta.get("top_targets"):
        print(f"[HELIOS] Top high-centrality targets: {state.meta['top_targets']}")

    # Generate Executive HTML Report
    html_out = Path(args.data) / f"campaign_{state.campaign_id}_report.html"
    briefing = {
        "campaign_id": state.campaign_id,
        "target": state.target,
        "status": state.status,
        "findings_count": state.meta.get("findings_count", 0),
        "top_targets": state.meta.get("top_targets", []),
        "events": rep.get("timeline", [])
    }
    report_path = generate_html_report(briefing, html_out)
    print(f"[HELIOS] Executive HTML report generated at: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
