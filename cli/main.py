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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.orchestrator import Orchestrator  # noqa: E402
from core.planner import PlanStep  # noqa: E402
from core.scope import ScopeEnforcer, ScopeError  # noqa: E402
from core.state import StateStore  # noqa: E402
from engine.plugins import plugin_registry  # noqa: E402
from engine.verdict import VerdictEngine, default_rules  # noqa: E402
from modules.registry import default_registry, discovery_runner  # noqa: E402

DEFAULT_DATA = ROOT / "data"


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    """Allow shared path options both before and after a command."""
    parser.add_argument("--data", default=argparse.SUPPRESS, help="Campaign data directory")
    parser.add_argument("--scope", default=argparse.SUPPRESS, help="Authorized scope file")


_SCOPE_TEMPLATE = '''# HELIOS-NET :: authorized scope
# Replace these examples with assets you own or are explicitly authorized to test.
# Keep the allowlist narrow. HELIOS-NET refuses targets outside this file.
scope:
  domains:
    - "example.test"
    - "lab.test"
  cidrs:
    - "127.0.0.0/24"
  ports:
    - 21
    - 22
    - 80
    - 443
    - 3306
    - 5432
  rate_limit:
    initial_concurrency: 20
    max_concurrency: 100
    timeout_seconds: 2.0
'''


def cmd_version(args: Any) -> int:
    """Show the checked-out revision and Python runtime."""
    revision = "unknown (Git metadata unavailable)"
    try:
        result = subprocess.run(["git", "describe", "--tags", "--always"], cwd=ROOT, capture_output=True, text=True, timeout=2, check=False)
        if result.returncode == 0 and result.stdout.strip():
            revision = result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    print(f"HELIOS-NET revision: {revision}")
    print(f"Python runtime: {sys.version.split()[0]}")
    return 0


def cmd_doctor(args: Any) -> int:
    """Read-only environment and configuration diagnostics; never probes targets."""
    python_ok = sys.version_info >= (3, 12)
    print(f"[{'OK' if python_ok else 'FAIL'}] Python {sys.version.split()[0]} (3.12 or newer required)")
    scope_path = Path(args.scope) if getattr(args, "scope", None) else ROOT / "config" / "scope.yaml"
    try:
        _load_scope(str(scope_path))
    except (ScopeError, OSError, ValueError) as exc:
        print(f"[FAIL] Scope configuration: {scope_path} ({exc})")
        scope_ok = False
    else:
        print(f"[OK] Scope configuration: {scope_path}")
        scope_ok = True
    data_path = Path(args.data)
    if data_path.is_dir():
        print(f"[OK] Data directory exists: {data_path}")
    elif data_path.exists():
        print(f"[FAIL] Data path is not a directory: {data_path}")
    else:
        print(f"[INFO] Data directory not initialized: {data_path} (run helios init)")
    for tool in ("go", "rustc", "cargo", "gcc", "clang"):
        location = shutil.which(tool)
        print(f"[{'OK' if location else 'OPTIONAL'}] {tool}: {location or 'not found'}")
    return 0 if python_ok and scope_ok and (not data_path.exists() or data_path.is_dir()) else 1


def cmd_init(args: Any) -> int:
    """Create local data and a conservative scope template without overwriting."""
    data_path = Path(args.data)
    scope_path = Path(args.scope) if getattr(args, "scope", None) else ROOT / "config" / "scope.yaml"
    try:
        data_path.mkdir(parents=True, exist_ok=True)
        print(f"[OK] Data directory: {data_path}")
        if scope_path.exists():
            print(f"[KEEP] Scope file already exists; left unchanged: {scope_path}")
        else:
            scope_path.parent.mkdir(parents=True, exist_ok=True)
            scope_path.write_text(_SCOPE_TEMPLATE, encoding="utf-8")
            print(f"[CREATED] Conservative scope template: {scope_path}")
    except OSError as exc:
        print(f"[HELIOS] initialization failed: {exc}")
        return 1
    print("[HELIOS] Initialization complete. Review the scope allowlist before any network command.")
    return 0

def _load_scope(scope_path: str | None) -> ScopeEnforcer:
    """Loads the authorized scope, refusing to run when it cannot be trusted."""
    return ScopeEnforcer.from_config(scope_path)


def _build_orchestrator(
    data_dir: str, scope: ScopeEnforcer | None = None
) -> Orchestrator:
    store = StateStore(data_dir)
    orch = Orchestrator(store=store, reg=default_registry(), scope=scope)
    return orch


def cmd_recon(args: Any) -> int:
    try:
        scope = _load_scope(getattr(args, "scope", None))
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2
    orch = _build_orchestrator(args.data, scope=scope)
    intelligence = (
        [{"module": "asset", "params": {"ct": True}}]
        if getattr(args, "ct", False)
        else None
    )
    try:
        state = orch.run_campaign(args.target, intelligence)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2
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
    try:
        scope = _load_scope(getattr(args, "scope", None))
        scope.check(args.target)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2

    step = PlanStep(step_id=1, module="discovery", action="scan", target=args.target)
    ctx: dict[str, Any] = {
        "scope_ports": list(scope.ports) or [22, 80, 443, 3306, 3389]
    }
    outcome = discovery_runner(step, ctx)
    findings = [f for f in ctx.get("findings", []) if f.get("open")]

    ve = VerdictEngine(rules=default_rules())
    ve.load_plugins(plugin_registry())
    for v in ve.judge_all(findings):
        print(
            f"  {v.finding.get('host')}:{v.finding.get('port')} <- {v.finding.get('service')}"
        )
        print(f"    severity={v.to_dict()['severity']} rules={v.rules_hit}")
    print(f"[HELIOS] engine={outcome['engine']} open={outcome['count']}")
    return 0


def cmd_probe(args: Any) -> int:
    """Grabs banners asynchronously through the adaptive engine."""
    import asyncio

    from core.async_engine import enterprise_adaptive_recon

    try:
        scope = _load_scope(getattr(args, "scope", None))
        scope.check(args.target)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2

    raw_ports: str | None = getattr(args, "ports", None)
    try:
        ports = _parse_port_list(raw_ports) if raw_ports else None
    except ValueError as exc:
        print(f"[HELIOS] invalid ports: {exc}")
        return 2
    if ports is None:
        ports = list(scope.ports) or [22, 80, 443]
    try:
        scope.check_ports(ports)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2

    results = asyncio.run(enterprise_adaptive_recon(args.target, ports))
    for result in results:
        if not result.get("open"):
            continue
        banner = result.get("banner", "")
        print(f"  {result['host']}:{result['port']}  {banner[:120]!r}")
    print(f"[HELIOS] probed {len(results)} port(s) via adaptive engine")
    return 0


def _parse_port_list(raw: str | None) -> list[int] | None:
    if raw is None:
        return None
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    if not parts:
        raise ValueError("provide at least one port")
    try:
        ports = [int(part) for part in parts]
    except ValueError as exc:
        raise ValueError("ports must be comma-separated integers") from exc
    invalid = [port for port in ports if not 1 <= port <= 65535]
    if invalid:
        raise ValueError(f"port numbers must be between 1 and 65535: {invalid}")
    return list(dict.fromkeys(ports))


def cmd_assets(args: Any) -> int:
    """Discovers scoped assets from names, CT entries, and HTTP metadata."""
    from modules.registry import asset_runner

    try:
        scope = _load_scope(getattr(args, "scope", None))
        scope.check(args.target)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2

    try:
        web_ports = _parse_port_list(getattr(args, "web_ports", None))
    except ValueError as exc:
        print(f"[HELIOS] invalid web ports: {exc}")
        return 2
    if web_ports:
        try:
            scope.check_ports(web_ports)
        except ScopeError as exc:
            print(f"[HELIOS] refused: {exc}")
            return 2

    params: dict[str, Any] = {
        "ct": bool(getattr(args, "ct", False)),
        "depth": getattr(args, "depth", 1),
        "max_hosts": getattr(args, "max_hosts", 50),
        "max_requests": getattr(args, "max_requests", 200),
        "deep": bool(getattr(args, "deep", False)),
    }
    if web_ports:
        params["web_ports"] = web_ports
    raw_seeds = getattr(args, "seeds", None)
    if raw_seeds:
        params["seeds"] = [
            seed.strip() for seed in raw_seeds.split(",") if seed.strip()
        ]

    step = PlanStep(
        step_id=1, module="asset", action="discover", target=args.target, params=params
    )
    ctx: dict[str, Any] = {"scope": scope, "scope_ports": list(scope.ports)}
    summary = asset_runner(step, ctx)

    for finding in ctx.get("findings", []):
        title = finding.get("title", "")
        vhost = " vhost" if finding.get("vhost") else ""
        print(
            f"  {finding['host']} -> {finding['ip']}:{finding['port']} "
            f"[{finding.get('status', '?')}] {title}{vhost}".rstrip()
        )
    for entry in summary.get("blocked", []):
        print(f"  blocked {entry['host']}: {entry['reason']}")
    graph_output = getattr(args, "graph_output", None)
    if graph_output:
        import json

        graph_payload = summary.get("graph")
        if not isinstance(graph_payload, dict):
            print(
                "[HELIOS] graph export unavailable: discovery did not return a typed graph."
            )
            return 2
        output_path = Path(graph_output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(graph_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"[HELIOS] graph export failed: {exc}")
            return 1
        print(f"[HELIOS] typed graph exported: {output_path}")

    graph = summary.get("graph", {})
    graph_assets = len(graph.get("assets", [])) if isinstance(graph, dict) else 0
    graph_relationships = (
        len(graph.get("relationships", [])) if isinstance(graph, dict) else 0
    )
    print(
        f"[HELIOS] hosts={len(summary.get('hosts', []))} "
        f"assets={summary.get('assets', 0)} requests={summary.get('requests', 0)} "
        f"graph_assets={graph_assets} graph_relationships={graph_relationships} "
        f"ct={params['ct']}"
    )
    return 2 if summary.get("error") else 0


def cmd_graph(args: Any) -> int:
    """Analyze a previously exported typed graph without performing network I/O."""
    import json

    from engine.graph.native import analyze_typed_graph, load_typed_graph

    input_path = Path(args.input)
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        graph = load_typed_graph(payload)
        result = analyze_typed_graph(
            graph,
            source_asset=getattr(args, "source_asset", None),
            target_asset=getattr(args, "target_asset", None),
            backend=None if args.backend == "auto" else args.backend,
        )
    except (
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        KeyError,
        RuntimeError,
    ) as exc:
        print(f"[HELIOS] graph analysis failed: {exc}")
        return 2

    summary = result["summary"]
    print("HELIOS-NET :: TYPED ASSET GRAPH")
    print(
        f"assets={summary['assets']} relationships={summary['typed_relationships']} "
        f"topology_edges={summary['topology_edges']} components={summary['components']}"
    )
    print("\nDegree centrality (highest first):")
    for row in result["degree_centrality"][: args.limit]:
        print(f"  {row['score']:>7.4f}  {row['type']:<12} {row['value']} [{row['id']}]")
    print("\nConnected components:")
    for index, component in enumerate(result["connected_components"], start=1):
        values = ", ".join(f"{item['type']}:{item['value']}" for item in component)
        print(f"  {index}. {values}")
    print("\nNative engine selection:")
    for operation, details in result["engines"].items():
        note = f" ({details['reason']})" if details.get("reason") else ""
        print(f"  {operation}: {details['engine']}{note}")

    if "shortest_path" in result:
        path = result["shortest_path"]
        print("\nShortest topology path:")
        if path["path"] is None:
            print("  no connected path")
        else:
            print(f"  hops={path['hops']}")
            for item in path["path"]:
                print(f"  -> {item['type']}:{item['value']} [{item['id']}]")

    output_path = getattr(args, "json_output", None)
    if output_path:
        destination = Path(output_path)
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"[HELIOS] result export failed: {exc}")
            return 1
        print(f"\n[HELIOS] analysis exported: {destination}")
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

    try:
        scope = _load_scope(getattr(args, "scope", None))
        scope.check(args.target)
    except ScopeError as exc:
        print(f"[HELIOS] refused: {exc}")
        return 2

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
    p.add_argument(
        "--scope",
        default=None,
        help="Scope file (JSON or supported YAML subset); defaults to config/scope.yaml",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("recon", help="Run full recon campaign")
    r.add_argument("--target", required=True, help="Target (authorized/owned)")
    r.add_argument(
        "--ct",
        action="store_true",
        help="Expand discovered names through Certificate Transparency",
    )
    _add_runtime_options(r)
    r.set_defaults(fn=cmd_recon)

    j = sub.add_parser("judge", help="Classify open ports via verdict engine")
    j.add_argument("--target", required=True, help="Target host (authorized/owned)")
    _add_runtime_options(j)
    j.set_defaults(fn=cmd_judge)

    pr = sub.add_parser("probe", help="Grab banners through the adaptive engine")
    pr.add_argument("--target", required=True, help="Target host (authorized/owned)")
    pr.add_argument(
        "--ports", default=None, help="Comma-separated ports; defaults to the scope"
    )
    _add_runtime_options(pr)
    pr.set_defaults(fn=cmd_probe)

    a = sub.add_parser(
        "assets", help="Discover scoped assets from names, CT and HTTP metadata"
    )
    a.add_argument("--target", required=True, help="Seed host (authorized/owned)")
    a.add_argument(
        "--ct",
        action="store_true",
        help="Expand names through Certificate Transparency",
    )
    a.add_argument("--depth", type=int, default=1, help="CT expansion hops")
    a.add_argument("--max-hosts", type=int, default=50, dest="max_hosts")
    a.add_argument("--max-requests", type=int, default=200, dest="max_requests")
    a.add_argument(
        "--deep",
        action="store_true",
        help="Also fetch security.txt and robots.txt for ownership signals",
    )
    a.add_argument(
        "--seeds",
        default=None,
        help="Comma-separated additional seed names (still scope-checked)",
    )
    a.add_argument(
        "--web-ports",
        default=None,
        dest="web_ports",
        help="Comma-separated web ports to probe; defaults to the scope",
    )
    a.add_argument(
        "--graph-output",
        default=None,
        help="Write the versioned typed asset graph JSON to this path",
    )
    _add_runtime_options(a)
    a.set_defaults(fn=cmd_assets)

    g = sub.add_parser("graph", help="Analyze an exported typed asset graph locally")
    g.add_argument("action", choices=["analyze"], help="Graph operation")
    g.add_argument("--input", required=True, help="Typed graph JSON exported by assets")
    g.add_argument(
        "--source-asset", default=None, help="Source typed asset ID for a shortest path"
    )
    g.add_argument(
        "--target-asset", default=None, help="Target typed asset ID for a shortest path"
    )
    g.add_argument("--backend", choices=["auto", "rust", "python"], default="auto")
    g.add_argument(
        "--limit", type=int, default=20, help="Maximum centrality rows to print"
    )
    g.add_argument(
        "--json-output", default=None, help="Write the full analysis result as JSON"
    )
    _add_runtime_options(g)
    g.set_defaults(fn=cmd_graph)

    rc = sub.add_parser("recover", help="Recover campaign state from disk")
    rc.add_argument("campaign_id")
    _add_runtime_options(rc)
    rc.set_defaults(fn=cmd_recover)

    info = sub.add_parser("info", help="Display extensible system components")
    _add_runtime_options(info)
    info.set_defaults(fn=cmd_info)

    st = sub.add_parser("status", help="List registered campaigns")
    _add_runtime_options(st)
    st.set_defaults(fn=cmd_status)

    dm = sub.add_parser("daemon", help="Run continuous autonomous mission daemon")
    dm.add_argument("--target", required=True, help="Target host")
    dm.add_argument(
        "--interval", type=float, default=15.0, help="Loop interval in seconds"
    )
    _add_runtime_options(dm)
    dm.set_defaults(fn=cmd_daemon)

    sim = sub.add_parser("sim", help="Run end-to-end simulation demonstration")
    _add_runtime_options(sim)
    sim.set_defaults(fn=cmd_sim)

    dash = sub.add_parser(
        "dashboard", help="Display professional ASCII executive dashboard"
    )
    _add_runtime_options(dash)
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
    _add_runtime_options(exp)
    _add_runtime_options(exp)
    exp.set_defaults(fn=cmd_export)


    version = sub.add_parser("version", help="Show HELIOS-NET revision and runtime")
    _add_runtime_options(version)
    version.set_defaults(fn=cmd_version)


    doctor = sub.add_parser("doctor", help="Run read-only environment diagnostics")
    _add_runtime_options(doctor)
    doctor.set_defaults(fn=cmd_doctor)


    init = sub.add_parser("init", help="Initialize data directory and scope template")
    _add_runtime_options(init)
    init.set_defaults(fn=cmd_init)


    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))
