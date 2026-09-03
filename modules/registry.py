"""HELIOS-NET :: modules/registry.py
ربط الوحدات القابلة للتنفيذ بسجل المنسّق (Orchestrator).

كل «منفّذ» (runner) يتلقى (step, ctx) ويُخرج صحيفة اكتشاف dict.
هنا نلمّع الوحدات الأساسية عقدًا عامًا ثابتًا — فتصبح جاهزة للتسجيل في
core/orchestrator دون تعديل النواة.
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
    """ينفّذ اكتشاف المنافذ على هدف الخطوة، مع ربط نواة Go إن بُنيَت."""
    ports = step.params.get("ports")
    found = discover_ports(step.target, ports=ports)
    ctx.setdefault("findings", []).extend(found)

    # ربط نواة الأداء: إرسال SYN خام عبر rawsync عند توفّره.
    native_note = None
    if ports:
        native_note = native_syn_probe(step.target, ports[0])
        if native_note.get("raw_sent"):
            ctx.setdefault("findings", []).append(native_note)

    return {"module": "discovery", "host": step.target,
            "open_ports": [f["port"] for f in found], "count": len(found),
            "native": native_note}


def recon_runner(step: PlanStep, ctx: dict) -> dict:
    """ينفّذ البصمة (أولوية لنواة C) والتقاط اللوافت من المنافذ المكتشفة."""
    result = fingerprint_host(step.target)
    ctx.setdefault("findings", []).append(result)
    if result.get("source") == "native(C)":
        ctx["native_fingerprint"] = True
    return result


def stealth_runner(step: PlanStep, ctx: dict) -> dict:
    """يطبّق إيقاعًا مسيَّرًا على الخطوات، ويُعيد إعداد الإيقاع."""
    pacer = Pacer(base_dwell=step.params.get("base_dwell", 0.2), jitter=step.params.get("jitter", 0.1))
    plan = ctx.get("plan", [])
    dwells = pacer.schedule(len(plan))
    ctx["pace"] = dwells
    return {"module": "stealth", "pace_samples": dwells[:5], "count": len(dwells)}


def exfil_runner(step: PlanStep, ctx: dict) -> dict:
    """يجمع كل النتائج في Collector ويربطها بعينة السياق."""
    col = Collector()
    added = col.extend(ctx.get("findings", []))
    ctx["collected"] = added
    return {"module": "exfil", "collected": added, "total": len(ctx.get("findings", []))}


# سجل موحّد — يُمرَّر إلى Orchestrator.register لكل وحدة.
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
    """يكتشف الوحدات الموسّعة من مجلد plugins ويكشف منفّذيها في السجل.

    كل وحدة مسجَّلة عبر @module() تُضاف تلقائيًا — لا تعديل يدوي بعد الآن.
    إن تعثّرت وحدة واحدة لا تُسقط الباقي.
    """
    out: dict[str, callable] = {}
    plugins_dir = Path(__file__).resolve().parent / "plugins"
    try:
        discover(plugins_dir)
    except Exception:
        return out
    for spec in list_modules():
        if spec.name in ("discovery", "recon", "stealth", "exfil"):
            continue  # لا نستبدل الوحدات النواة — نضيف الجديد فقط.
        out[spec.name] = spec.runner
    return out
