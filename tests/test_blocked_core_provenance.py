"""HELIOS-NET :: tests/test_blocked_core_provenance.py

The C core is not always runnable. A host application-control policy - Smart
App Control, AppLocker, WDAC - refuses to execute it with WinError 4551 while
the binary sits on disk, newer than every source file, looking perfectly
healthy.

That condition was mishandled, and the failure was invisible: `core_available()`
tested for the file's *existence*, so a blocked core reported itself available;
`scan_banners` then failed to spawn it, fell back to the Python matcher, and
returned those results as if they had come from C. `core.accel` labelled the
outcome `c-native` with an empty reason, and `compare_backends` reported a
three-way agreement in which the "C" arm was Python - so a cross-backend check
quietly compared two implementations instead of three, and looked green.

These tests pin the rule: a core that cannot execute is absent from the registry,
never the source of an answer, and always carries the reason it was skipped.
"""

from __future__ import annotations

import subprocess

import pytest

from core import accel
from core import c_core_bridge


def _refuse_4551(*args, **kwargs):
    """Stands in for the host refusing to execute the binary."""
    raise OSError(4551, "Une stratégie de contrôle d'application a bloqué ce fichier.")


@pytest.fixture
def blocked_core(monkeypatch):
    """A C core that exists on disk but the host will not execute."""
    monkeypatch.setattr(c_core_bridge, "_BINARY", c_core_bridge.Path("helios_core.exe"))
    monkeypatch.setattr(c_core_bridge.subprocess, "run", _refuse_4551)
    c_core_bridge.reset_availability()
    yield
    c_core_bridge.reset_availability()


# ------------------------------------------------- the availability answer
def test_a_core_that_cannot_execute_is_not_available(blocked_core):
    assert c_core_bridge.core_available() is False, (
        "existence is not executability: a blocked binary was reported as usable"
    )


def test_the_policy_refusal_is_named_rather_than_reported_as_missing(blocked_core):
    note = c_core_bridge.availability_note()
    assert "4551" in note, f"the refusal must be identifiable in: {note!r}"
    assert "policy" in note.lower()
    assert "not found" not in note, "a refusal is not a missing file"


def test_a_blocked_core_reports_unavailable_not_unknown(blocked_core):
    """`unknown` is what a healthy binary that printed something odd returns.

    Collapsing the two hides a host decision behind an oddity.
    """
    assert c_core_bridge.core_version() == "unavailable"


def test_the_execution_probe_is_probed_once_not_per_call(blocked_core, monkeypatch):
    calls: list = []

    def counting(*args, **kwargs):
        calls.append(args)
        return _refuse_4551()

    c_core_bridge.reset_availability()
    monkeypatch.setattr(c_core_bridge.subprocess, "run", counting)

    for _ in range(5):
        c_core_bridge.core_available()
    assert len(calls) == 1, f"the probe ran {len(calls)} times; it is on a dispatch path"


def test_reset_allows_the_probe_to_run_again(blocked_core):
    assert c_core_bridge.core_available() is False
    c_core_bridge.reset_availability()
    assert c_core_bridge.core_available() is False, "re-probing must reach the same verdict"


# -------------------------------------------------------- the accel answer
def test_a_blocked_core_is_absent_from_the_registry(blocked_core):
    info = accel.backend_infos_by_name()["c"]
    assert info.available is False
    assert "4551" in info.reason
    assert info.capabilities == frozenset(), (
        "an unusable core must not advertise what it cannot do"
    )


def test_results_from_a_blocked_core_are_never_labelled_c_native(blocked_core):
    """The defect this file exists for."""
    outcome = accel.match_signatures("SSH-2.0-OpenSSH_9.6", ["SSH", "OpenSSH"])
    assert outcome.engine != "c-native", (
        "a C core that could not run produced the answer that was labelled c-native"
    )
    assert outcome.engine in ("rust-native", "python-fallback")
    assert "c" in outcome.reason and "4551" in outcome.reason, (
        f"the reason for skipping C must travel with the result: {outcome.reason!r}"
    )
    # The answer itself is still right: degradation must not cost correctness.
    assert [m.signature for m in outcome.matches] == ["SSH", "OpenSSH", "SSH"]


def test_a_fingerprint_is_never_attributed_to_a_blocked_core(blocked_core):
    outcome = accel.fingerprint("abc")
    assert outcome.engine != "c-native"
    assert outcome.fnv1a32, "a digest must still be produced by some core"
    assert "4551" in outcome.reason


def test_the_cross_backend_check_does_not_count_the_blocked_core(blocked_core):
    """A three-way agreement in which one arm is really Python is not a check."""
    report = accel.compare_backends("SSH-2.0-OpenSSH", ["SSH", "OpenSSH"])
    assert "c" not in report["backends"], (
        f"the blocked core was counted as having run: {list(report['backends'])}"
    )
    assert "c" in report["skipped"]
    assert "4551" in report["skipped"]["c"]
    if report["agree"] is not None:
        assert len(report["backends"]) >= 2, (
            "an agreement needs at least two real backends to be meaningful"
        )


def test_agreeing_with_a_single_survivor_is_not_reported_as_a_cross_check(blocked_core):
    """One backend cannot corroborate itself."""
    report = accel.compare_backends("SSH-2.0-OpenSSH", ["SSH"])
    if len(report["backends"]) < 2:
        assert report["agree"] is None, (
            "a single backend agreeing with itself must not be reported as agreement"
        )
