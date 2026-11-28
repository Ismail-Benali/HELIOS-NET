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



def test_orchestrator_passes_resolved_authorized_ips_to_runners(tmp_path, monkeypatch):
    scope = ScopeEnforcer(
        allowed_cidrs=["10.0.0.0/8"],
        allowed_domains=["app.example.test"],
        ports=[80],
    )
    monkeypatch.setattr(
        scope,
        "resolve_authorized_ips",
        lambda target: ["10.2.3.4"] if target == "app.example.test" else [],
    )
    seen: list[list[str]] = []

    def discovery(step, ctx):
        seen.append(list(ctx["authorized_ips"]))
        return {"module": "discovery", "host": step.target, "count": 0}

    orchestrator = Orchestrator(
        StateStore(tmp_path / "campaigns"),
        reg={"discovery": discovery},
        scope=scope,
    )

    state = orchestrator.run_campaign("app.example.test")

    assert seen == [["10.2.3.4"]]
    assert state.meta["authorized_ips"] == ["10.2.3.4"]



def test_daemon_scans_only_ports_permitted_by_scope(tmp_path, monkeypatch):
    import asyncio

    from core.daemon import AutonomousDaemon

    scope = ScopeEnforcer(
        allowed_cidrs=["10.0.0.0/8"],
        ports=[80, 443],
    )
    daemon = AutonomousDaemon(
        target="10.0.0.1",
        state_dir=tmp_path,
        scope=scope,
        interval_seconds=1.0,
    )
    calls: list[tuple[str, list[int]]] = []

    async def fake_recon(host, ports):
        calls.append((host, list(ports)))
        return []

    monkeypatch.setattr("core.daemon.enterprise_adaptive_recon", fake_recon)
    asyncio.run(daemon.run_mission_cycle())

    assert calls == [("10.0.0.1", [80, 443])]


def test_daemon_refuses_when_none_of_its_ports_are_authorized(tmp_path):
    from core.daemon import AutonomousDaemon

    scope = ScopeEnforcer(
        allowed_cidrs=["10.0.0.0/8"],
        ports=[8080],
    )
    with pytest.raises(ScopeError, match="none of the daemon's default ports"):
        AutonomousDaemon(
            target="10.0.0.1",
            state_dir=tmp_path,
            scope=scope,
            interval_seconds=1.0,
        )
