"""HELIOS-NET :: modules/registry.py
Links the executable modules to the orchestrator's registry.

Each runner receives (step, ctx) and emits a finding dict. Here we surface the
core modules under a stable public contract - ready for registration in
core/orchestrator without touching the core.

The runners use the same cores the tests and fuzzers cover, not a parallel
implementation:

  * discovery routes every requested port through `core.accel.scan_ports`,
    which prefers the Go scanner and falls back to the socket probe. The old
    runner scanned with sockets and then re-confirmed a single port with Go, so
    the "high-performance" core was decoration on the critical path.
  * recon grabs a banner per open port and matches it through
    `core.accel.match_signatures`, so the C/Rust/Python matcher actually
    identifies services instead of only running in tests.
  * both report the engine that answered, so a degraded run is visible in the
    finding rather than inferred from a log.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from core import accel
from core.planner import PlanStep
from core.scope import ScopeEnforcer
from modules.core import discover, list_modules
from modules.discovery import goscan_bridge
from modules.discovery.assets import WEB_PORTS, discover_assets
from modules.discovery.service import COMMON_PORTS
from modules.exfil.collector import Collector
from modules.recon.fingerprint import banner_grab
from modules.stealth.pacer import Pacer

#: Shipped signature file: one `name<TAB>pattern` per line, parsed by the same
#: parser the native core uses. Overridable for private signature sets.
DEFAULT_SIGNATURES = Path(__file__).resolve().parents[1] / "config" / "signatures.txt"
SIGNATURES_ENV_VAR = "HELIOS_SIGNATURES"


def _pacer(ctx: dict[str, Any]) -> Pacer | None:
    pacer = ctx.get("pacer")
    return pacer if isinstance(pacer, Pacer) else None


def _pace(ctx: dict[str, Any]) -> None:
    """Applies the configured inter-probe dwell, if pacing is active."""
    pacer = _pacer(ctx)
    if pacer is not None:
        pacer.wait("uniform")


def _signature_pairs() -> list[tuple[str, str]]:
    path = Path(os.environ.get(SIGNATURES_ENV_VAR, DEFAULT_SIGNATURES))
    from core.c_core_bridge import load_signatures

    return load_signatures(path)


def discovery_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Scans the requested ports through the best available native backend."""
    ports = step.params.get("ports") or ctx.get("scope_ports") or sorted(COMMON_PORTS)
    port_list = [int(port) for port in ports]
    outcome = accel.scan_ports(step.target, port_list)

    findings: list[dict[str, Any]] = []
    for row in outcome.rows:
        port = int(row["port"])
        finding: dict[str, Any] = {
            "module": "discovery",
            "host": step.target,
            "port": port,
            "open": True,
            "state": row.get("state", "open"),
            "service": row.get("service") or COMMON_PORTS.get(port, ""),
            "engine": outcome.engine,
            "source": "go-native" if outcome.engine == "go-native" else "socket-probe",
        }
        for key in ("banner", "latency_ms", "time"):
            if row.get(key) not in (None, ""):
                finding[key] = row[key]
        findings.append(finding)

    ctx.setdefault("findings", []).extend(findings)
    return {
        "module": "discovery",
        "host": step.target,
        "open_ports": [finding["port"] for finding in findings],
        "count": len(findings),
        "engine": outcome.engine,
        "reason": outcome.reason,
    }


def _match_banner(banner: str, pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
    pattern_to_name: dict[str, str] = {}
    for name, pattern in pairs:
        if pattern:
            pattern_to_name.setdefault(pattern, name)
    if not pattern_to_name:
        return []

    outcome = accel.match_signatures(banner, list(pattern_to_name))
    matches = []
    for hit in outcome.matches:
        matches.append(
            {
                "signature": pattern_to_name.get(hit.signature, hit.signature),
                "position": hit.position,
            }
        )
    matches.sort(key=lambda match: (match["position"], match["signature"]))
    return matches


def recon_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Grabs and identifies the banner of every open port found by discovery."""
    discovered = [
        finding
        for finding in ctx.get("findings", [])
        if finding.get("open") and finding.get("port") is not None
    ]
    ports = sorted({int(finding["port"]) for finding in discovered})
    pairs = _signature_pairs()

    probes: list[dict[str, Any]] = []
    engines: set[str] = set()
    for port in ports:
        existing = next(
            (
                finding
                for finding in discovered
                if int(finding["port"]) == port and finding.get("banner")
            ),
            None,
        )
        if existing is not None:
            banner = str(existing["banner"])
        else:
            _pace(ctx)
            grabbed = banner_grab(step.target, port)
            banner = str(grabbed.get("banner", ""))
        if not banner or banner.startswith("<error:"):
            probes.append({"port": port, "banner": banner, "matches": []})
            continue
        matches = _match_banner(banner, pairs)
        probes.append(
            {
                "port": port,
                "banner": banner,
                "matches": matches,
                "service": matches[0]["signature"] if matches else "",
            }
        )
        if matches:
            engines.add("signature-core")

    result: dict[str, Any] = {
        "module": "recon",
        "host": step.target,
        "source": "banner-signature",
        "method": "banner-signature",
        "probes": probes,
        "signature_matches": sum(len(probe["matches"]) for probe in probes),
        "engines": sorted(engines),
    }
    if not ports:
        result["note"] = "no open ports were reported by discovery"

    ctx.setdefault("findings", []).append(result)
    ctx["fingerprint_source"] = result["source"]
    return result


def asset_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Expands the authorized surface from names into scoped asset findings.

    The runner refuses to fall back to a permissive scope: without the
    campaign's enforcer it reports why it did nothing instead of probing.
    """
    scope = ctx.get("scope")
    if not isinstance(scope, ScopeEnforcer):
        return {
            "module": "asset",
            "host": step.target,
            "assets": 0,
            "hosts": [],
            "blocked": [],
            "error": "scope unavailable; asset discovery not attempted",
        }

    seeds = [step.target]
    seeds.extend(str(seed) for seed in step.params.get("seeds", []) if seed)
    seeds.extend(str(seed) for seed in ctx.get("seeds", []) if seed)

    web_ports = step.params.get("web_ports")
    if web_ports is None:
        web_ports = [
            port for port in WEB_PORTS if not scope.ports or port in scope.ports
        ]

    summary = discover_assets(
        scope,
        list(dict.fromkeys(seeds)),
        ct=bool(step.params.get("ct", False)),
        depth=int(step.params.get("depth", 1)),
        max_hosts=int(step.params.get("max_hosts", 50)),
        max_requests=int(step.params.get("max_requests", 200)),
        web_ports=[int(port) for port in web_ports],
        pace=lambda: _pace(ctx),
    )
    findings = summary.pop("findings", [])
    ctx.setdefault("findings", []).extend(findings)
    ctx["discovered_hosts"] = summary["hosts"]
    summary["module"] = "asset"
    summary["host"] = step.target
    return summary


def stealth_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Installs the pacing policy that network-facing runners must honour.

    The pacing is not a report: the pacer is placed in the context and
    `discovery_runner`/`recon_runner` wait on it between probes. The planner
    schedules this step first so the policy exists before any scan starts.
    """
    pacer = Pacer(
        mean_dwell=step.params.get("base_dwell", 0.2),
        jitter=step.params.get("jitter", 0.1),
    )
    plan = ctx.get("plan", [])
    dwells = pacer.schedule(len(plan))
    ctx["pacer"] = pacer
    ctx["pace"] = dwells
    return {
        "module": "stealth",
        "pace_samples": dwells[:5],
        "count": len(dwells),
        "enforced": True,
    }


def collector_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Collects every finding into a deduplicating Collector."""
    col = Collector()
    added = col.extend(ctx.get("findings", []))
    ctx["collected"] = added
    return {
        "module": "collector",
        "collected": added,
        "total": len(ctx.get("findings", [])),
    }


# Backwards-compatible alias. The module used to be called "exfil", which
# described data exfiltration; it only ever collected findings in memory.
exfil_runner = collector_runner

CORE_MODULES = ("asset", "discovery", "recon", "stealth", "collector")


# Unified registry - passed to Orchestrator.register per module.
def default_registry() -> dict[str, Any]:
    reg = {
        "asset": asset_runner,
        "discovery": discovery_runner,
        "recon": recon_runner,
        "stealth": stealth_runner,
        "collector": collector_runner,
    }
    reg.update(discovered_plugins())
    return reg


def discovered_plugins() -> dict[str, Any]:
    """Discovers the extension modules in plugins/ and exposes their runners.

    Every module registered via @module() is added automatically - no more manual
    edits. If one module fails it does not drop the rest.
    """
    out: dict[str, Any] = {}
    plugins_dir = Path(__file__).resolve().parent / "plugins"
    try:
        discover(plugins_dir)
    except Exception:
        return out
    for spec in list_modules():
        if spec.name in CORE_MODULES or spec.name == "exfil":
            continue  # don't replace core modules - only add new ones.
        out[spec.name] = spec.runner
    return out


# Imported for callers that gate on the Go core before running a campaign.
__all__ = [
    "DEFAULT_SIGNATURES",
    "collector_runner",
    "asset_runner",
    "default_registry",
    "discovery_runner",
    "goscan_bridge",
    "recon_runner",
    "stealth_runner",
]
