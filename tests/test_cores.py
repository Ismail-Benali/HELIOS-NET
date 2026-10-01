"""
HELIOS-NET :: tests/test_cores.py
Contract tests for the unified native core health layer and the Go bridge.

The central guarantee these tests defend: a core that is present but not
working is never reported as a healthy scan, and never reported as an empty
result set. That distinction is the whole reason `core/cores.py` and
`GoscanError` exist.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys

import pytest

from core import cores
from core.cores import BLOCKED, FAILED, FALLBACK, OK, CoreStatus
from modules.discovery import goscan_bridge


# --------------------------------------------------------------------------
# core/cores.py
# --------------------------------------------------------------------------

def test_health_report_shape():
    report = cores.health_report()
    assert report["platform"]
    assert report["python"] == sys.version.split()[0]
    names = {c["name"] for c in report["cores"]}
    assert names == {"python", "rust", "c", "go"}, f"missing cores: {names}"
    assert report["native_total"] == 3


def test_every_core_is_described_in_the_same_terms():
    """Each core must answer the same contract, so results stay comparable."""
    report = cores.health_report()
    for core in report["cores"]:
        assert core["state"] in {OK, FALLBACK, FAILED, BLOCKED}
        assert isinstance(core["usable"], bool)
        assert core["version"]
        for key in ("name", "language", "role", "detail", "tests"):
            assert key in core
        # usable must be derived from state, never asserted independently.
        assert core["usable"] is (core["state"] == OK)


def test_python_core_is_always_usable():
    """The reference implementation is the floor everything else falls back to."""
    status = cores.check_python()
    assert status.state == OK
    assert status.usable


def test_absent_core_is_fallback_not_failed():
    """A core that was never built must not be reported as broken."""
    status = CoreStatus(name="absent", language="Nope", role="none", state=FALLBACK)
    assert not status.usable


def test_failed_core_is_not_usable():
    status = CoreStatus(name="c", language="C", role="x", state=FAILED)
    assert not status.usable


def test_policy_blocked_detection():
    """App Control refusals must be classified as an environment condition."""
    err = OSError("Une strategie de controle d'application a bloque ce fichier")
    err.winerror = 4551
    assert cores._policy_blocked(err)

    # Not every error is a policy decision, and a bare number is not evidence.
    assert not cores._policy_blocked(OSError("disk on fire"))
    assert not cores._policy_blocked(OSError("exit status 4551 (bad checksum)"))

    # Hosts that surface the policy only in text are still recognised.
    assert cores._policy_blocked(OSError("blocked by application control policy"))
    assert cores._policy_blocked(
        OSError("Une strategie de controle d'application a bloque ce fichier")
    )


def test_probe_that_raises_does_not_abort_the_report(monkeypatch):
    """One broken import must not hide the state of the other cores."""

    def explode():
        raise ImportError("simulated broken dependency")

    monkeypatch.setattr(cores, "_CHECKS", ((explode,), (cores.check_python,)))
    report = cores.health_report()
    assert len(report["cores"]) == 2
    assert report["cores"][0]["state"] == FAILED
    assert "simulated broken dependency" in report["cores"][0]["detail"]
    assert report["cores"][1]["state"] == OK


def test_failed_core_is_counted_and_degrades_the_report(monkeypatch):
    """A present-but-broken core must be counted as unusable, and must show."""
    def broken():
        return CoreStatus(name="go", language="Go", role="scanning",
                          state=FAILED, version="1.0.0", detail="selftest failed")

    monkeypatch.setattr(cores, "_CHECKS", ((cores.check_python,), (broken,)))
    report = cores.health_report()

    go = report["cores"][1]
    assert go["usable"] is False
    assert report["native_usable"] == 0
    assert report["native_total"] == 1
    # A shipped core that cannot run is not a healthy pipeline.
    assert report["status"] == "degraded"
    assert "selftest failed" in cores.format_report(report)


def test_format_report_mentions_a_non_usable_core():
    report = {
        "platform": "test", "python": "3.12", "native_usable": 1, "native_total": 3,
        "cores": [
            {"name": "go", "language": "Go", "role": "x", "state": OK,
             "usable": True, "version": "1.0", "detail": "19 checks", "tests": {}},
            {"name": "c", "language": "C", "role": "x", "state": BLOCKED,
             "usable": False, "version": "2.1.0", "detail": "host policy", "tests": {}},
            {"name": "rust", "language": "Rust", "role": "x", "state": FAILED,
             "usable": False, "version": "3.0.0", "detail": "broken", "tests": {}},
        ],
    }
    text = cores.format_report(report)
    assert "BLOCKED" in text and "FAILED" in text
    assert "1/3" in text


# --------------------------------------------------------------------------
# Go bridge: a failure must never masquerade as an empty scan
# --------------------------------------------------------------------------

def test_missing_binary_is_recorded_not_swallowed(monkeypatch):
    monkeypatch.setattr(goscan_bridge, "GOSCAN_BIN", goscan_bridge.ROOT / "nope.exe")
    assert goscan_bridge.run_go_scan("127.0.0.1") == []
    assert goscan_bridge.LAST_ERROR is not None
    assert "not found" in goscan_bridge.LAST_ERROR


def test_missing_binary_raises_in_strict_mode(monkeypatch):
    monkeypatch.setattr(goscan_bridge, "GOSCAN_BIN", goscan_bridge.ROOT / "nope.exe")
    with pytest.raises(goscan_bridge.GoscanError):
        goscan_bridge.run_go_scan("127.0.0.1", strict=True)


def test_nonzero_exit_is_reported(monkeypatch, tmp_path):
    """A crashed core must not look like a clean scan."""
    fake = tmp_path / "fake.exe"
    fake.write_text("not a real binary", encoding="utf-8")
    monkeypatch.setattr(goscan_bridge, "GOSCAN_BIN", fake)

    results = goscan_bridge.run_go_scan("127.0.0.1")
    assert results == []
    assert goscan_bridge.LAST_ERROR is not None


def _skip_unless_go_runnable() -> None:
    """Skip when the Go core is absent or the host refuses to execute it.

    The bridges deliberately let a WinError 4551 application-control refusal
    propagate rather than swallow it, so on a locked-down host these tests now
    raise instead of returning None. That raise is correct behaviour for the
    bridge, but reporting it as a test failure would blame the code for an
    environment decision and prove nothing about the core.
    """
    if not goscan_bridge.core_available():
        pytest.skip("Go binary not built in this environment")
    if cores.check_go().state == BLOCKED:
        pytest.skip("host application-control policy refuses to execute the Go core")


def test_last_error_is_cleared_on_success():
    """A previous failure must not contaminate a later good run."""
    _skip_unless_go_runnable()
    goscan_bridge.LAST_ERROR = "stale error from an earlier run"
    goscan_bridge.run_go_scan("127.0.0.1", "1")
    assert goscan_bridge.LAST_ERROR is None


def _stream_of(*lines: str):
    """A minimal async byte-line reader that needs no running event loop."""
    pending = [(ln + "\n").encode() for ln in lines]

    class Stream:
        async def readline(self) -> bytes:
            return pending.pop(0) if pending else b""

    return Stream()


def test_fields_from_the_core_survive_the_bridge(monkeypatch):
    """Banner, service and latency are the reason the Go core exists.

    The previous bridge hardcoded a generic service name and dropped the rest,
    silently discarding the native work.
    """
    payload = {"port": 22, "open": True, "service": "ssh",
               "banner": "SSH-2.0-OpenSSH_9.6", "latency_ms": 3,
               "time": "2026-01-01T00:00:00Z"}

    class FakeProc:
        def __init__(self):
            self.stdout = _stream_of(json.dumps(payload))
            self.stderr = None

        async def wait(self):
            return 0

    async def fake_create(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge.asyncio, "create_subprocess_exec", fake_create)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.5", "22"))
    assert len(results) == 1
    row = results[0]
    assert row["port"] == 22
    assert row["service"] == "ssh"
    assert row["banner"] == "SSH-2.0-OpenSSH_9.6"
    assert row["latency_ms"] == 3
    assert row["host"] == "10.0.0.5"
    assert row["open"] is True
    assert "Go" in row["source"]


def test_unidentified_service_is_not_given_an_invented_name(monkeypatch):
    """An unidentified service must stay unidentified.

    The bridge used to fall back to `data.get("service") or "tcp-native"`. That
    string reads like a detection the core made, but it was a label the bridge
    invented, so a report could claim a service that was never identified.
    """
    payload = {"port": 4444, "open": True, "banner": "", "latency_ms": 7}

    class FakeProc:
        def __init__(self):
            self.stdout = _stream_of(json.dumps(payload))
            self.stderr = None

        async def wait(self):
            return 0

    async def fake_create(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge.asyncio, "create_subprocess_exec", fake_create)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.9", "4444"))
    assert len(results) == 1
    row = results[0]
    assert not row["service"], (
        f"an unidentified service must be empty, not {row['service']!r}"
    )
    # Empty is the falsy value every consumer already handles, so the field
    # stays truthful without breaking the service graph in modules/core.py.
    assert "tcp-native" not in json.dumps(row)


def test_closed_ports_are_not_reported_as_open(monkeypatch):
    """`open: false` lines are results of their own and must not leak through."""
    class FakeProc:
        def __init__(self):
            self.stdout = _stream_of(json.dumps({"port": 1, "open": False}))
            self.stderr = None

        async def wait(self):
            return 0

    async def fake_create(*args, **kwargs):
        return FakeProc()

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge.asyncio, "create_subprocess_exec", fake_create)

    results = asyncio.run(goscan_bridge.run_go_scan_async("127.0.0.1", "1"))
    assert results == []
    assert goscan_bridge.LAST_ERROR is None, "an all-closed sweep is a valid answer"


# --------------------------------------------------------------------------
# Go self test: the proof the core actually runs
# --------------------------------------------------------------------------

def test_go_selftest_reports_success_when_the_core_runs():
    _skip_unless_go_runnable()
    report = goscan_bridge.selftest()
    if report is None:
        pytest.skip("Go binary not built in this environment")
    assert report["status"] == "ok"
    assert report["failures"] == 0
    assert report["checks"] > 0


def test_go_version_is_reported():
    version = goscan_bridge.core_version()
    if version == "unavailable":
        pytest.skip("Go binary not built in this environment")
    assert "Go Scanner" in version


def test_go_bridge_agrees_with_the_health_probe():
    """Two independent code paths must not disagree about the core."""
    _skip_unless_go_runnable()
    status = cores.check_go()
    assert status.state == OK, status.detail
    assert status.tests["selftest"]["failures"] == 0


# --------------------------------------------------------------------------
# BLOCKED must survive the bridge, not be flattened into FAILED
# --------------------------------------------------------------------------
#
# Both bridges originally caught OSError and returned None or an error dict. That
# silently converted a WinError 4551 application-control refusal into FAILED, so
# a host policy decision was reported as a broken core and failed the build. The
# winerror only reaches _policy_blocked through the exception itself, so these
# tests pin the propagation rather than the message text, which is localised.

def _policy_error():
    exc = OSError(4551, "Une strat\u00e9gie de contr\u00f4le d'application a bloqu\u00e9 ce fichier")
    exc.winerror = 4551
    return exc


def test_go_selftest_propagates_a_policy_refusal(monkeypatch):
    from core import c_core_bridge

    def refuse(*args, **kwargs):
        raise _policy_error()

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge.subprocess, "run", refuse)
    monkeypatch.setattr(c_core_bridge, "core_available", lambda: True)
    monkeypatch.setattr(c_core_bridge, "_BINARY", "helios_core.exe")
    monkeypatch.setattr(c_core_bridge.subprocess, "run", refuse)

    with pytest.raises(OSError) as go_exc:
        goscan_bridge.selftest()
    assert go_exc.value.winerror == 4551

    with pytest.raises(OSError) as c_exc:
        c_core_bridge.selftest()
    assert c_exc.value.winerror == 4551


def test_policy_refusal_is_reported_as_blocked_not_failed(monkeypatch):
    """The end-to-end classification, which is what the build gate depends on."""
    from core import c_core_bridge

    def refuse(*args, **kwargs):
        raise _policy_error()

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge, "core_version", lambda: "v")
    monkeypatch.setattr(goscan_bridge.subprocess, "run", refuse)

    go_status = cores.check_go()
    assert go_status.state == BLOCKED, (
        f"a policy refusal was reported as {go_status.state}: {go_status.detail}"
    )

    monkeypatch.setattr(c_core_bridge, "core_available", lambda: True)
    monkeypatch.setattr(c_core_bridge, "core_version", lambda: "v")
    monkeypatch.setattr(c_core_bridge, "_BINARY", "helios_core.exe")
    monkeypatch.setattr(c_core_bridge.subprocess, "run", refuse)

    c_status = cores.check_c()
    assert c_status.state == BLOCKED, (
        f"a policy refusal was reported as {c_status.state}: {c_status.detail}"
    )


def test_a_genuine_execution_error_is_still_failed(monkeypatch):
    """BLOCKED must not become a catch-all that hides real failures."""
    from core import c_core_bridge

    def broken(*args, **kwargs):
        exc = OSError(5, "Access is denied")
        exc.winerror = 5
        raise exc

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge, "core_version", lambda: "v")
    monkeypatch.setattr(goscan_bridge.subprocess, "run", broken)

    go_status = cores.check_go()
    assert go_status.state == FAILED, go_status.detail

    monkeypatch.setattr(c_core_bridge, "core_available", lambda: True)
    monkeypatch.setattr(c_core_bridge, "core_version", lambda: "v")
    monkeypatch.setattr(c_core_bridge, "_BINARY", "helios_core.exe")
    monkeypatch.setattr(c_core_bridge.subprocess, "run", broken)

    c_status = cores.check_c()
    assert c_status.state == FAILED, c_status.detail
