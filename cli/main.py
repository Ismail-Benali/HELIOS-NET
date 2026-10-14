"""HELIOS-NET :: cli/main.py
Professional CLI Interface - Campaign execution from the terminal.

Usage:
    python run.py recon --target example.test
    python run.py judge --target example.test
    python run.py recover <campaign_id>
    python run.py info
    python run.py status
    python run.py daemon --target example.test
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import Orchestrator  # noqa: E402
from core.state import StateStore  # noqa: E402
from engine.plugins import plugin_registry  # noqa: E402
from engine.verdict import VerdictEngine, default_rules  # noqa: E402
from modules.registry import default_registry  # noqa: E402

DEFAULT_DATA = ROOT / "data"


def _build_orchestrator(data_dir: str) -> Orchestrator:
    store = StateStore(data_dir)
    orch = Orchestrator(store=store, reg=default_registry())
    return orch


def cmd_recon(args: Any) -> int:
    orch = _build_orchestrator(args.data)
    state = orch.run_campaign(args.target)
    rep = orch.report(state)
    print(f"[HELIOS] campaign {state.campaign_id} -> {state.status}")
    print(
        orch.planner.to_json(orch._context["plan"])
        if orch._context.get("plan")
        else "(no plan)"
    )
    summary = state.meta.get("findings_count", 0)
    print(f"[HELIOS] findings collected: {summary}")
    return 0


def cmd_judge(args: Any) -> int:
    from modules.discovery.service import discover_ports

    findings = discover_ports(args.target, ports=[22, 80, 443, 3306, 3389])
    ve = VerdictEngine(rules=default_rules())
    ve.load_plugins(plugin_registry())
    for v in ve.judge_all(findings):
        print(
            f"  {v.finding.get('host')}:{v.finding.get('port')} <- {v.finding.get('service')}"
        )
        print(f"    severity={v.to_dict()['severity']} rules={v.rules_hit}")
    return 0


def cmd_recover(args: Any) -> int:
    orch = _build_orchestrator(args.data)
    try:
        state = orch.recover(args.campaign_id)
    except FileNotFoundError as exc:
        print(f"[HELIOS] {exc}")
        return 1
    rep = orch.report(state)
    print(f"[HELIOS] recovered {state.campaign_id}: {state.status}")
    print(f"  target={state.target} findings={state.meta.get('findings_count', 0)}")
    return 0


def cmd_info(args: Any) -> int:
    """Displays extensible system components: algorithms, modules, rules."""
    import json

    from engine.algorithms import list_algos
    from modules.core import discover, list_modules

    try:
        discover(ROOT / "modules" / "plugins")
    except Exception as exc:
        # Silently listing fewer modules than exist is the one failure mode a
        # user cannot notice, so the inventory says so instead.
        print(
            f"[HELIOS] warning: plugin discovery failed ({exc}); "
            "the module list below is incomplete."
        )

    payload = {
        "algorithms": list_algos(),
        "modules": [{"name": m.name, "kind": m.kind} for m in list_modules()],
        "rule_plugins": sorted(plugin_registry().keys()),
        "core_rules": sorted(r.name for r in default_rules()),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_status(args: Any) -> int:
    orch = _build_orchestrator(args.data)
    states = orch.store.load_all()
    if not states:
        print("[HELIOS] no campaigns recorded.")
        return 0
    for s in sorted(states, key=lambda x: x.created_at, reverse=True):
        print(
            f"  {s.campaign_id} {s.status:9s} target={s.target} findings={s.meta.get('findings_count', 0)}"
        )
    return 0


def cmd_dashboard(args: Any) -> int:
    """Displays a gorgeous ASCII executive summary dashboard of system and campaigns."""
    orch = _build_orchestrator(args.data)
    states = orch.store.load_all()

    print("=" * 64)
    print("           HELIOS-NET :: EXECUTIVE SECURITY DASHBOARD           ")
    print("=" * 64)
    print(f" Data Directory : {args.data}")
    print(f" Total Campaigns: {len(states)}")
    print("-" * 64)
    if not states:
        print(
            " (No campaigns recorded yet. Run `python run.py recon --target <ip>` first)"
        )
    else:
        for s in sorted(states, key=lambda x: x.created_at, reverse=True):
            print(f" [ID]     {s.campaign_id}")
            print(f" Target   : {s.target}")
            print(f" Status   : {s.status.upper()}")
            print(f" Findings : {s.meta.get('findings_count', 0)}")
            print("-" * 64)
    print("=" * 64)
    return 0


def cmd_export(args: Any) -> int:
    """Exports campaign findings and metadata to JSON, CSV, or SARIF."""
    import csv
    import json
    import sys

    orch = _build_orchestrator(args.data)
    try:
        state = orch.store.load(args.campaign_id)
    except FileNotFoundError:
        print(f"[HELIOS] campaign {args.campaign_id} not found.")
        return 1

    format_type = args.format.lower()
    findings = state.meta.get("findings", [])

    if format_type == "json":
        print(json.dumps(state.to_dict(), indent=2, ensure_ascii=False))
    elif format_type == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["host", "port", "service", "open", "banner", "latency_ms"])
        for f in findings:
            writer.writerow(
                [
                    f.get("host"),
                    f.get("port"),
                    f.get("service"),
                    f.get("open"),
                    f.get("banner"),
                    f.get("latency_ms"),
                ]
            )
    elif format_type == "sarif":
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "HELIOS-NET", "version": "3.0.0"}},
                    "results": [
                        {
                            "ruleId": f.get("service", "open_port"),
                            "message": {
                                "text": f"Open port {f.get('port')} running {f.get('service')}"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(f.get("host"))}
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        print(json.dumps(sarif, indent=2, ensure_ascii=False))
    else:
        print(
            f"[HELIOS] unknown export format: {format_type}. Use json, csv, or sarif."
        )
        return 1
    return 0


def cmd_daemon(args: Any) -> int:
    """Activates the Continuous Autonomous Mission Daemon."""
    import asyncio

    from core.daemon import AutonomousDaemon

    print(f"[DEMIURG-DAEMON] Activating autonomous agent for target: {args.target}")
    print("[DEMIURG-DAEMON] Press Ctrl+C to terminate the living daemon loop.")

    daemon = AutonomousDaemon(
        target=args.target, state_dir=Path(args.data), interval_seconds=args.interval
    )
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        print("\n[DEMIURG-DAEMON] Daemon deactivated by master command.")
    return 0


def cmd_sim(args: Any) -> int:
    """Executes the full end-to-end framework simulation."""
    import asyncio

    import run_simulation

    asyncio.run(run_simulation.simulate_engagement())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="helios",
        description="HELIOS-NET - Autonomous Red Teaming & Attack Surface Management Orchestrator",
    )
    p.add_argument("--data", default=str(DEFAULT_DATA), help="Campaign data directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recon", help="Run full recon campaign")
    r.add_argument("--target", required=True, help="Target (authorized/owned)")
    r.set_defaults(fn=cmd_recon)

    j = sub.add_parser("judge", help="Classify open ports via verdict engine")
    j.add_argument("--target", required=True, help="Target host (authorized/owned)")
    j.set_defaults(fn=cmd_judge)

    rc = sub.add_parser("recover", help="Recover campaign state from disk")
    rc.add_argument("campaign_id")
    rc.set_defaults(fn=cmd_recover)

    info = sub.add_parser("info", help="Display extensible system components")
    info.set_defaults(fn=cmd_info)

    st = sub.add_parser("status", help="List registered campaigns")
    st.set_defaults(fn=cmd_status)

    dm = sub.add_parser("daemon", help="Run continuous autonomous mission daemon")
    dm.add_argument("--target", required=True, help="Target host")
    dm.add_argument(
        "--interval", type=float, default=15.0, help="Loop interval in seconds"
    )
    dm.set_defaults(fn=cmd_daemon)

    sim = sub.add_parser("sim", help="Run end-to-end simulation demonstration")
    sim.set_defaults(fn=cmd_sim)

    dash = sub.add_parser(
        "dashboard", help="Display professional ASCII executive dashboard"
    )
    dash.set_defaults(fn=cmd_dashboard)

    exp = sub.add_parser(
        "export", help="Export campaign results to JSON, CSV, or SARIF"
    )
    exp.add_argument("campaign_id", help="Campaign ID to export")
    exp.add_argument(
        "--format",
        default="json",
        choices=["json", "csv", "sarif"],
        help="Export format",
    )
    exp.set_defaults(fn=cmd_export)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))
