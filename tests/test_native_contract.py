"""Tests for the versioned native capability/result contract."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from core import native_contract as contract
from core.accel import BackendInfo, Match, MatchOutcome


def test_registry_is_versioned_and_preserves_transport_boundaries(monkeypatch):
    monkeypatch.setattr(contract, "CONTRACT_VERSION", "1.0.0")
    monkeypatch.setattr(
        "core.accel.backend_infos",
        lambda: [
            BackendInfo("go", True, capabilities=frozenset({"scan_ports"})),
            BackendInfo("c", False, "application control policy refused execution"),
            BackendInfo("rust", False, "library not found"),
            BackendInfo("python", True, "always available"),
        ],
    )
    report = contract.capability_registry()
    assert report["contract_version"] == "1.0.0"
    assert {b["name"]: b["transport"] for b in report["backends"]} == {
        "go": "ndjson-process",
        "c": "ndjson-process-or-ffi",
        "rust": "c-abi",
        "python": "in-process",
    }
    states = {(e["backend"], e["capability"]): e["state"] for e in report["entries"]}
    assert states[("go", "scan_ports")] == "ready"
    assert states[("c", "match")] == "blocked"
    assert states[("rust", "graph_degree")] == "unavailable"
    assert states[("c", "graph_degree")] == "unsupported"
    assert states[("python", "match")] == "fallback"


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("application control policy refused execution", "blocked"),
        ("binary is stale", "failed"),
        ("library not found", "unavailable"),
    ],
)
def test_unavailable_backend_states_are_not_collapsed(reason, expected):
    assert contract._unavailable_state(reason) == expected


def test_normalized_native_success_keeps_backend_and_result():
    outcome = MatchOutcome((Match("ssh", 0),), "c-native")
    normalized = contract.normalize_outcome("match", outcome)
    assert normalized == {
        "contract_version": "1.0.0",
        "capability": "match",
        "status": "success",
        "backend": "c-native",
        "reason": "",
        "result": [{"signature": "ssh", "position": 0}],
    }


def test_normalized_fallback_is_explicitly_degraded():
    outcome = MatchOutcome((Match("ssh", 0),), "python-fallback", "C unavailable")
    normalized = contract.normalize_outcome("match", outcome)
    assert normalized["status"] == "degraded"
    assert normalized["backend"] == "python-fallback"
    assert normalized["reason"] == "C unavailable"


@dataclass
class NoBackendOutcome:
    engine: str = "none"
    reason: str = "native worker raised TimeoutError"


def test_normalized_failure_is_not_an_empty_success():
    normalized = contract.normalize_outcome("scan_ports", NoBackendOutcome())
    assert normalized["status"] == "failed"
    assert normalized["backend"] == "none"
    assert normalized["result"] is None


def test_unknown_capability_is_rejected():
    with pytest.raises(ValueError, match="unknown capability"):
        contract.normalize_outcome("stealth_mode", MatchOutcome((), "none"))
