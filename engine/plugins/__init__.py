"""HELIOS-NET :: engine/plugins/__init__.py
The engine rules registry — an extension point without touching the core.

Each entry here builds one Rule. They are loaded via VerdictEngine.load_plugins.
"""

from __future__ import annotations

from ..verdict import Rule


def open_high_value_port() -> Rule:
    """Rule: an open port on one of the critical administrative services."""
    critical = {"22": "ssh", "3389": "rdp", "443": "https", "3306": "mysql"}
    return Rule(
        name="critical_port_open",
        weight=0.65,
        test=lambda f: str(f.get("port")) in critical or str(f.get("service", "")).lower() in critical.values(),
        note="Critical port open — flagged for deep inspection.",
    )


def web_presence() -> Rule:
    """Rule: a web interface present — an indicator of an application attack surface."""
    return Rule(
        name="web_surface",
        weight=0.5,
        test=lambda f: any(k in str(f.get("service", "")).upper() for k in ("HTTP", "HTTPS", "8080")),
        note="Web interface available for application reconnaissance.",
    )


def plugin_registry() -> dict:
    return {
        "helios_critical_port": open_high_value_port,
        "helios_web_surface": web_presence,
    }
