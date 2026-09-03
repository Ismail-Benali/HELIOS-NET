"""HELIOS-NET :: engine/plugins/__init__.py
سجل قواعد المحرّك — نقطة توسّع دون تعديل النواة.

كل عنصر هنا يصنع Rule واحدة. تُحمَّل عبر VerdictEngine.load_plugins.
"""

from __future__ import annotations

from ..verdict import Rule


def open_high_value_port() -> Rule:
    """قاعدة: منفذ مفتوح على واحدة من الخدمات الإدارية الحرجة."""
    critical = {"22": "ssh", "3389": "rdp", "443": "https", "3306": "mysql"}
    return Rule(
        name="critical_port_open",
        weight=0.65,
        test=lambda f: str(f.get("port")) in critical or str(f.get("service", "")).lower() in critical.values(),
        note="منفذ حرج مفتوح — أولوية فحص عميق.",
    )


def web_presence() -> Rule:
    """قاعدة: وجود واجهة ويب — مؤشر لسطح هجوم تطبيقاتي."""
    return Rule(
        name="web_surface",
        weight=0.5,
        test=lambda f: any(k in str(f.get("service", "")).upper() for k in ("HTTP", "HTTPS", "8080")),
        note="واجهة ويب قابلة للاستطلاع التطبيقي.",
    )


def plugin_registry() -> dict:
    return {
        "helios_critical_port": open_high_value_port,
        "helios_web_surface": web_presence,
    }
