"""HELIOS-NET :: modules/registry.py
Links the executable modules to the orchestrator's registry.

Each runner receives (step, ctx) and emits a finding dict. Here we surface the
core modules under a stable public contract — ready for registration in
core/orchestrator without touching the core.
"""

from __future__ import annotations

from pathlib import Path

from core.planner import PlanStep

from modules.core import ModuleSpec, discover, get_module, list_modules
from modules.discovery.service import discover_ports, native_syn_probe
from modules.recon.fingerprint import banner_grab, fingerprint_host, fingerprint_native
from modules.stealth.pacer import Pacer
from modules.exfil.collector import Collector


def discovery_runner(step: PlanStep, ctx: dict) -> dict:
    """Runs port discovery on the step's target, wiring in the Go core if built."""
    ports = step.params.get("ports")
    found = discover_ports(step.target, ports=ports)
    ctx.setdefault("findings", []).extend(found)

    # wire in the performance core: send a raw SYN via rawsync when available.
    native_note = None
    if ports:
        native_note = native_syn_probe(step.target, ports[0])
        if native_note.get("raw_sent"):
            ctx.setdefault("findings", []).append(native_note)

    return {"module": "discovery", "host": step.target,
            "open_ports": [f["port"] for f in found], "count": len(found),
            "native": native_note}


def recon_runner(step: PlanStep, ctx: dict) -> dict:
    """Runs fingerprinting (C core preferred) and banner grabbing on discovered ports."""
    result = fingerprint_host(step.target)
    ctx.setdefault("findings", []).append(result)
    if result.get("source") == "native(C)":
        ctx["native_fingerprint"] = True
    return result


def stealth_runner(step: PlanStep, ctx: dict) -> dict:
    """Applies a paced cadence to the steps and returns the pacing settings."""
    pacer = Pacer(base_dwell=step.params.get("base_dwell", 0.2), jitter=step.params.get("jitter", 0.1))
    plan = ctx.get("plan", [])
    dwells = pacer.schedule(len(plan))
    ctx["pace"] = dwells
    return {"module": "stealth", "pace_samples": dwells[:5], "count": len(dwells)}


def exfil_runner(step: PlanStep, ctx: dict) -> dict:
    """Collects all results into a Collector and links them to the context sample."""
    col = Collector()
    added = col.extend(ctx.get("findings", []))
    ctx["collected"] = added
    return {"module": "exfil", "collected": added, "total": len(ctx.get("findings", []))}


# Unified registry — passed to Orchestrator.register per module.
def default_registry() -> dict:
    reg = {
        "discovery": discovery_runner,
        "recon": recon_runner,
        "stealth": stealth_runner,
        "exfil": exfil_runner,
    }
    reg.update(discovered_plugins())
    return reg


def discovered_plugins() -> dict:
    """Discovers the extension modules in plugins/ and exposes their runners.

    Every module registered via @module() is added automatically — no more manual
    edits. If one module fails it does not drop the rest.
    """
    out: dict[str, callable] = {}
    plugins_dir = Path(__file__).resolve().parent / "plugins"
    try:
        discover(plugins_dir)
    except Exception:
        return out
    for spec in list_modules():
        if spec.name in ("discovery", "recon", "stealth", "exfil"):
            continue  # don't replace core modules — only add new ones.
        out[spec.name] = spec.runner
    return out
