"""HELIOS-NET :: tests/test_verdict.py
Pytest suite for Verdict Engine rule evaluation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.plugins import plugin_registry
from engine.verdict import VerdictEngine, default_rules


def test_verdict_engine():
    ve = VerdictEngine(rules=default_rules())
    ve.load_plugins(plugin_registry())
    v = ve.judge(
        {
            "module": "discovery",
            "host": "127.0.0.1",
            "port": 3306,
            "service": "MySQL",
            "open": True,
        }
    )
    assert "critical_port_open" in v.rules_hit
    assert v.to_dict()["severity"] == "medium"
