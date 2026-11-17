"""Tests for the authoritative native capability contract.

`core/native_contract.py` must describe the matrix that `core/accel.py` actually
dispatches on. These tests fail if a backend advertises a capability it does not
derive from the registry, if a capability has no callable entrypoint, if a
normalized result leaves the documented state set, or if degraded and failed
dispatches stop explaining themselves.
"""

from __future__ import annotations

import argparse
import importlib

import pytest

import cli.main as cli
from core import accel
from core import native_contract as contract
from core.accel import (
    BackendInfo,
    FingerprintOutcome,
    GraphOutcome,
    Match,
    MatchOutcome,
    PortScanOutcome,
)

ALL_CAPABILITIES = set().union(*contract.SUPPORTED_CAPABILITIES.values())


def _force_available(monkeypatch: pytest.MonkeyPatch, available: bool) -> None:
    from core import c_core_bridge, rust_bridge
    from modules.discovery import goscan_bridge

    monkeypatch.setattr(c_core_bridge, "core_available", lambda: available)
    monkeypatch.setattr(c_core_bridge, "availability_note", lambda: "")
    monkeypatch.setattr(c_core_bridge, "staleness_note", lambda: "")
    monkeypatch.setattr(rust_bridge, "rust_available", lambda: available)
    monkeypatch.setattr(goscan_bridge, "core_available", lambda: available)


def _offline(name: str) -> BackendInfo:
    return BackendInfo(name, False, "offline for this test")


def test_every_capability_names_a_callable_entrypoint() -> None:
    assert set(contract.CAPABILITY_ENTRYPOINTS) == ALL_CAPABILITIES
    for capability, dotted in contract.CAPABILITY_ENTRYPOINTS.items():
        module_name, _, attribute = dotted.rpartition(".")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attribute)), capability


@pytest.mark.parametrize("backend", sorted(contract.SUPPORTED_CAPABILITIES))
def test_backend_capabilities_come_from_the_registry(monkeypatch, backend) -> None:
    _force_available(monkeypatch, available=True)
    info = accel._BACKENDS[backend]()
    assert info.capabilities == frozenset(contract.SUPPORTED_CAPABILITIES[backend])


def test_unavailable_backends_advertise_no_capabilities(monkeypatch) -> None:
    _force_available(monkeypatch, available=False)
    for backend in ("c", "rust", "go"):
        assert accel._BACKENDS[backend]().capabilities == frozenset()
    assert accel._BACKENDS["python"]().capabilities == frozenset(
        contract.SUPPORTED_CAPABILITIES["python"]
    )


def test_registry_covers_every_backend_capability_pair() -> None:
    report = contract.capability_registry()
    assert report["contract_version"] == contract.CONTRACT_VERSION
    assert report["capabilities"] == sorted(ALL_CAPABILITIES)
    assert report["entrypoints"] == contract.CAPABILITY_ENTRYPOINTS

    expected = {
        (backend, capability)
        for backend, supported in contract.SUPPORTED_CAPABILITIES.items()
        for capability in ALL_CAPABILITIES
    }
    actual = {(entry["backend"], entry["capability"]) for entry in report["entries"]}
    assert actual == expected
    assert {entry["state"] for entry in report["entries"]} <= contract.STATES


def test_normalized_outcome_states_are_closed() -> None:
    cases = [
        ("match", MatchOutcome((Match("ssh", 0),), "c-native"), "success"),
        ("match", MatchOutcome((), "python-fallback", "C unavailable"), "degraded"),
        ("fingerprint", FingerprintOutcome("0x1", engine="c-native"), "success"),
        ("scan_ports", PortScanOutcome((22,), (), "go-native"), "success"),
        ("graph_degree", GraphOutcome([(0, 1.0)], "rust-native"), "success"),
        (
            "scan_ports",
            PortScanOutcome(
                (), (), "none", "no backend could serve the request: go: offline"
            ),
            "unavailable",
        ),
        (
            "match",
            MatchOutcome((), "none", "native worker raised TimeoutError"),
            "failed",
        ),
    ]
    for capability, outcome, expected in cases:
        normalized = contract.normalize_outcome(capability, outcome)
        assert normalized["status"] == expected
        assert normalized["status"] in contract.OUTCOME_STATES
        assert set(normalized) == {
            "contract_version",
            "capability",
            "status",
            "backend",
            "reason",
            "result",
        }


def test_scan_ports_degrades_and_explains(monkeypatch) -> None:
    monkeypatch.setitem(accel._BACKENDS, "go", lambda: _offline("go"))
    outcome = accel.scan_ports("127.0.0.1", [1])
    assert outcome.engine == "python-fallback"
    assert "go: offline for this test" in outcome.reason
    normalized = contract.normalize_outcome("scan_ports", outcome)
    assert normalized["status"] == "degraded"
    assert normalized["backend"] == "python-fallback"


def test_scan_ports_fails_closed_when_no_backend_can_run(monkeypatch) -> None:
    monkeypatch.setitem(accel._BACKENDS, "go", lambda: _offline("go"))
    monkeypatch.setitem(accel._BACKENDS, "python", lambda: _offline("python"))
    outcome = accel.scan_ports("127.0.0.1", [1])
    assert outcome.engine == "none"
    assert outcome.ports == ()
    normalized = contract.normalize_outcome("scan_ports", outcome)
    assert normalized["status"] == "unavailable"
    assert normalized["backend"] == "none"
    assert normalized["result"] == {"ports": [], "rows": []}


def test_match_uses_the_next_backend_when_one_raises(monkeypatch) -> None:
    monkeypatch.setitem(
        accel._BACKENDS,
        "c",
        lambda: BackendInfo("c", True, capabilities=frozenset({"match"})),
    )
    monkeypatch.setitem(accel._BACKENDS, "rust", lambda: _offline("rust"))

    def boom(text: str, patterns) -> tuple[Match, ...]:
        raise RuntimeError("boom")

    monkeypatch.setattr(accel, "_c_match", boom)
    outcome = accel.match_signatures("hello", ["hel"])
    assert outcome.engine == "python-fallback"
    assert "c: raised RuntimeError: boom" in outcome.reason
    assert outcome.matches == (Match("hel", 0),)


def test_match_fails_closed_when_every_backend_is_unavailable(monkeypatch) -> None:
    for backend in ("c", "rust", "python"):
        monkeypatch.setitem(
            accel._BACKENDS, backend, lambda name=backend: _offline(name)
        )
    outcome = accel.match_signatures("hello", ["hel"])
    assert outcome.engine == "none"
    assert outcome.matches == ()
    normalized = contract.normalize_outcome("match", outcome)
    assert normalized["status"] == "unavailable"
    assert normalized["result"] == []


def test_graph_degrades_per_operation_and_explains(monkeypatch) -> None:
    monkeypatch.setitem(accel._BACKENDS, "rust", lambda: _offline("rust"))
    outcome = accel.graph_degree_centrality(2, [(0, 1)])
    assert outcome.engine == "python-fallback"
    assert "rust: offline for this test" in outcome.reason
    assert sorted(outcome.value) == [(0, 1.0), (1, 1.0)]


def test_graph_fails_closed_when_every_backend_is_unavailable(monkeypatch) -> None:
    for backend in ("rust", "python"):
        monkeypatch.setitem(
            accel._BACKENDS, backend, lambda name=backend: _offline(name)
        )
    outcome = accel.graph_components(2, [(0, 1)])
    assert outcome.engine == "none"
    assert outcome.value is None
    normalized = contract.normalize_outcome("graph_components", outcome)
    assert normalized["status"] == "unavailable"


def test_doctor_prints_the_capability_contract(tmp_path, capsys) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(cli._SCOPE_TEMPLATE, encoding="utf-8")
    args = argparse.Namespace(data=str(tmp_path / "not-created"), scope=str(scope))
    code = cli.cmd_doctor(args)
    output = capsys.readouterr().out
    assert code in (0, 1)
    assert f"[INFO] Capability contract: {contract.CONTRACT_VERSION}" in output
    assert "[INFO] python:" in output
    assert "fallback" in output
