"""Regression tests for campaign planning and centralized scope authorization."""

from __future__ import annotations

import pytest

from core.orchestrator import Orchestrator
from core.planner import Planner
from core.scope import ScopeEnforcer, ScopeError
from core.state import StateStore


def test_planner_preserves_discovery_parameters():
    steps = Planner().plan(
        [{"module": "discovery", "params": {"ports": [80, 443]}}],
        "127.0.0.1",
    )

    discovery = next(step for step in steps if step.module == "discovery")
    assert discovery.params == {"ports": [80, 443]}


@pytest.mark.parametrize(
    "module,params",
    [
        ("discovery", {"ports": [22]}),
        ("asset", {"web_ports": [8443]}),
        ("discovery", {"port": 3389}),
    ],
)
def test_orchestrator_rejects_ports_outside_scope_before_execution(
    tmp_path, module, params
):
    scope = ScopeEnforcer(
        allowed_cidrs=["127.0.0.1/32"],
        ports=[80, 443],
    )
    orchestrator = Orchestrator(
        StateStore(tmp_path / "campaigns"),
        reg={},
        scope=scope,
    )
    steps = Planner().plan(
        [{"module": module, "params": params}],
        "127.0.0.1",
    )

    with pytest.raises(ScopeError, match="outside the authorized scope"):
        orchestrator._authorize_steps(steps)


def test_orchestrator_accepts_scoped_ports(tmp_path):
    scope = ScopeEnforcer(
        allowed_cidrs=["127.0.0.1/32"],
        ports=[80, 443],
    )
    orchestrator = Orchestrator(
        StateStore(tmp_path / "campaigns"),
        reg={},
        scope=scope,
    )
    steps = Planner().plan(
        [
            {"module": "discovery", "params": {"ports": [80, 443]}},
            {"module": "asset", "params": {"web_ports": [80]}},
        ],
        "127.0.0.1",
    )

    orchestrator._authorize_steps(steps)
