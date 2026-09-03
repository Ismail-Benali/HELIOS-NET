"""HELIOS-NET :: cli/main.py
Professional CLI Interface — Campaign execution from the terminal.

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

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import Orchestrator  # noqa: E402
from core.state import StateStore                   # noqa: E402
from engine.verdict import VerdictEngine, default_rules  # noqa: E402
from engine.plugins import plugin_registry          # noqa: E402
from modules.registry import default_registry       # noqa: E402


DEFAULT_DATA = ROOT / "data"


def _build_orchestrator(data_dir: str) -> Orchestrator:
    store = StateStore(data_dir)
    orch = Orchestrator(store=store, reg=default_registry())
    return orch


def cmd_recon(args) -> int:
    orch = _build_orchestrator(args.data)
    state = orch.run_campaign(args.target)
    rep = orch.report(state)
    print(f"[HELIOS] campaign {state.campaign_id} -> {state.status}")
    print(orch.planner.to_json(orch._context["plan"]) if orch._context.get("plan") else "(no plan)")
    summary = state.meta.get("findings_count", 0)
    print(f"[HELIOS] findings collected: {summary}")
    return 0


def cmd_judge(args) -> int:
    from modules.discovery.service import discover_ports

    findings = discover_ports(args.target, ports=[22, 80, 443, 3306, 3389])
    ve = VerdictEngine(rules=default_rules())
    ve.load_plugins(plugin_registry())
    for v in ve.judge_all(findings):
        print(f"  {v.finding.get('host')}:{v.finding.get('port')} <- {v.finding.get('service')}")
        print(f"    severity={v.to_dict()['severity']} rules={v.rules_hit}")
    return 0


def cmd_recover(args) -> int:
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


def cmd_info(args) -> int:
    """Displays extensible system components: algorithms, modules, rules."""
    import json
    from engine.algorithms import list_algos
    from modules.core import discover, list_modules

    try:
        discover(ROOT / "modules" / "plugins")
    except Exception:
        pass

    payload = {
        "algorithms": list_algos(),
        "modules": [{"name": m.name, "kind": m.kind} for m in list_modules()],
        "rule_plugins": sorted(plugin_registry().keys()),
        "core_rules": sorted(r.name for r in default_rules()),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_status(args) -> int:
    orch = _build_orchestrator(args.data)
    states = orch.store.load_all()
    if not states:
        print("[HELIOS] no campaigns recorded.")
        return 0
    for s in sorted(states, key=lambda x: x.created_at, reverse=True):
        print(f"  {s.campaign_id} {s.status:9s} target={s.target} findings={s.meta.get('findings_count', 0)}")
    return 0


def cmd_daemon(args) -> int:
    """Activates the Continuous Autonomous Mission Daemon."""
    import asyncio
    from core.daemon import AutonomousDaemon

    print(f"[DEMIURG-DAEMON] Activating autonomous agent for target: {args.target}")
    print("[DEMIURG-DAEMON] Press Ctrl+C to terminate the living daemon loop.")
    
    daemon = AutonomousDaemon(target=args.target, state_dir=Path(args.data), interval_seconds=args.interval)
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        print("\n[DEMIURG-DAEMON] Daemon deactivated by master command.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="helios", description="HELIOS-NET — Autonomous Cyber Warfare Orchestrator")
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
    dm.add_argument("--interval", type=float, default=15.0, help="Loop interval in seconds")
    dm.set_defaults(fn=cmd_daemon)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)
