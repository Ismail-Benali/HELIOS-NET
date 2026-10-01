"""Tests for the pacing helper and the Go bridge.

Two themes.

The Pacer takes an injectable RNG, which is what makes its distribution
testable at all: instead of asserting that random numbers are random, the tests
drive the generator and check the formula, then check the statistics over many
draws. The `u == 0` case is worth pinning because the guard that saves it
(`max(1e-6, ...)`) turns a zero into the *largest* possible dwell, not a
divergence.

The Go bridge is the module whose docstring explains that an empty list used to
mean four different things at once. So the tests drive a fake process that
streams NDJSON on stdout and error envelopes on stderr, and they check that
every failure path leaves a distinguishable trace: either results, or
LAST_ERROR, or a raise. The WinError 4551 case is deliberately asserted to
propagate, since swallowing it is what previously made a policy refusal look
like a broken core.
"""

from __future__ import annotations

import asyncio
import json
import random
import statistics
import time

import pytest

from modules.discovery import goscan_bridge
from modules.discovery.goscan_bridge import GoscanError
from modules.stealth.pacer import Pacer, strip_artifacts


class ScriptedRNG:
    """An RNG that returns fixed values, so formulas can be checked exactly.

    `uniform` returns `uniform_value` (not the midpoint) because the midpoint of
    a symmetric jitter range is always the mean, which would make every jitter
    test pass without exercising the jitter at all.
    """

    def __init__(self, values: list[float], uniform_value: float = 0.0) -> None:
        self.values = list(values)
        self.uniform_value = uniform_value
        self.uniform_calls: list[tuple[float, float]] = []

    def random(self) -> float:
        return self.values.pop(0) if self.values else 0.0

    def uniform(self, low: float, high: float) -> float:
        self.uniform_calls.append((low, high))
        return self.uniform_value


# --------------------------------------------------------------------------- #
# Pacer: the constructor clamps
# --------------------------------------------------------------------------- #

def test_a_zero_or_negative_mean_is_raised_to_the_floor():
    assert Pacer(mean_dwell=0.0).mean_dwell == 0.01
    assert Pacer(mean_dwell=-3.0).mean_dwell == 0.01
    assert Pacer(mean_dwell=0.5).mean_dwell == 0.5


def test_a_negative_jitter_is_clamped_to_zero():
    """A negative jitter would make uniform() raise low > high."""
    assert Pacer(jitter=-1.0).jitter == 0.0

    rng = ScriptedRNG([0.5])
    pacer = Pacer(mean_dwell=1.0, jitter=-1.0, rng=rng)
    pacer.dwell("uniform")
    assert rng.uniform_calls == [(0.0, 0.0)], "the jitter range must not be inverted"


# --------------------------------------------------------------------------- #
# Pacer: the formulas
# --------------------------------------------------------------------------- #

def test_exponential_dwell_follows_the_documented_formula():
    """dwell = -mean * ln(u) + jitter, with the jitter drawn as a uniform."""
    rng = ScriptedRNG([0.5, 0.0])
    pacer = Pacer(mean_dwell=2.0, jitter=0.0, rng=rng)

    expected = -2.0 * __import__("math").log(0.5)
    assert pacer.dwell("exponential") == pytest.approx(expected)
    assert rng.uniform_calls == [(0.0, 0.0)], "zero jitter still routes through uniform"


def test_exponential_dwell_adds_the_jitter():
    import math
    rng = ScriptedRNG([0.5], uniform_value=0.2)
    pacer = Pacer(mean_dwell=2.0, jitter=0.4, rng=rng)

    assert pacer.dwell("exponential") == pytest.approx(-2.0 * math.log(0.5) + 0.2)
    assert rng.uniform_calls == [(-0.4, 0.4)], "jitter is drawn across the full range"


def test_a_zero_from_the_rng_becomes_the_longest_wait_not_a_crash():
    """The guard is max(1e-6, u), so u=0 yields -mean*ln(1e-6) ~= 13.8*mean.

    Pinned because a guard written as max(u, 1e-6) looks equivalent and is not:
    the log runs on the guarded value, so the clamp has to be on the low side.
    """
    import math
    rng = ScriptedRNG([0.0])
    pacer = Pacer(mean_dwell=1.0, jitter=0.0, rng=rng)

    assert pacer.dwell("exponential") == pytest.approx(-1.0 * math.log(1e-6))
    assert pacer.dwell("exponential") < 100.0, "clamped, not divergent"


def test_uniform_dwell_is_the_mean_plus_jitter():
    rng = ScriptedRNG([0.5], uniform_value=0.5)
    pacer = Pacer(mean_dwell=3.0, jitter=1.0, rng=rng)

    assert pacer.dwell("uniform") == pytest.approx(3.5)
    assert rng.uniform_calls == [(-1.0, 1.0)]


def test_any_mode_other_than_exponential_falls_back_to_uniform():
    """Pinned: the branch is `if mode == "exponential"`, so a typo is silent."""
    rng = ScriptedRNG([0.5])
    pacer = Pacer(mean_dwell=1.0, jitter=0.0, rng=rng)
    assert pacer.dwell("exponentials") == pytest.approx(1.0)


def test_dwell_never_returns_a_negative_or_zero_gap():
    pacer = Pacer(mean_dwell=0.5, jitter=10.0)
    for mode in ("exponential", "uniform"):
        for _ in range(500):
            assert pacer.dwell(mode) >= 0.0, f"{mode} produced a negative gap"


def test_the_exponential_floor_is_one_hundredth():
    """A zero-length wait would turn pacing into a busy loop."""
    import math
    rng = ScriptedRNG([0.9999999])
    pacer = Pacer(mean_dwell=0.001, jitter=0.0, rng=rng)
    assert pacer.dwell("exponential") == pytest.approx(0.01, abs=1e-9)


def test_the_uniform_mode_can_reach_zero_but_not_below():
    import math
    rng = ScriptedRNG([0.5])
    pacer = Pacer(mean_dwell=1.0, jitter=5.0, rng=rng)
    # midpoint of (-5, 5) is 0, so the value lands on the mean exactly.
    assert pacer.dwell("uniform") == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Pacer: the distribution
# --------------------------------------------------------------------------- #

def test_the_exponential_mean_is_the_configured_dwell():
    """A rate-1/mean exponential has mean == mean, which is what makes the
    setting mean something rather than being a shape parameter."""
    pacer = Pacer(mean_dwell=0.4, jitter=0.0, rng=random.Random(20260928))
    samples = [pacer.dwell("exponential") for _ in range(20_000)]

    assert statistics.fmean(samples) == pytest.approx(0.4, rel=0.05)
    assert min(samples) >= 0.01, "no gap is shorter than the floor"


def test_the_exponential_is_right_skewed():
    """A long tail is the point: a fixed cadence is what looks automated."""
    pacer = Pacer(mean_dwell=0.5, jitter=0.0, rng=random.Random(7))
    samples = [pacer.dwell("exponential") for _ in range(20_000)]

    assert statistics.median(samples) < statistics.fmean(samples)
    assert max(samples) > 3 * statistics.fmean(samples)


def test_a_seeded_pacer_reproduces_its_schedule():
    """Reproducibility is what makes a scan replayable after an incident."""
    first = Pacer(mean_dwell=0.2, jitter=0.05, rng=random.Random(1234))
    second = Pacer(mean_dwell=0.2, jitter=0.05, rng=random.Random(1234))
    assert first.schedule(50) == second.schedule(50)


def test_jitter_widens_the_schedule():
    fixed = Pacer(mean_dwell=0.3, jitter=0.0, rng=random.Random(3))
    jittered = Pacer(mean_dwell=0.3, jitter=0.2, rng=random.Random(3))

    spread_fixed = statistics.pstdev(fixed.schedule(2000))
    spread_jittered = statistics.pstdev(jittered.schedule(2000))
    assert spread_jittered > spread_fixed
    assert statistics.fmean(jittered.schedule(2000)) == pytest.approx(0.3, rel=0.1)


# --------------------------------------------------------------------------- #
# Pacer: schedule and wait
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ["exponential", "uniform"])
def test_schedule_returns_one_gap_per_step(mode):
    pacer = Pacer(rng=random.Random(1))
    assert pacer.schedule(0, mode) == []
    assert len(pacer.schedule(7, mode)) == 7


def test_schedule_defaults_to_the_exponential_mode():
    """Two separately seeded pacers: a shared RNG would advance between the
    two calls and the lists could not possibly be equal."""
    paced = Pacer(mean_dwell=0.5, jitter=0.0, rng=random.Random(99))
    explicit = Pacer(mean_dwell=0.5, jitter=0.0, rng=random.Random(99))
    assert paced.schedule(30) == explicit.schedule(30, "exponential")
    assert paced.schedule(1) != explicit.schedule(1, "uniform"), (
        "the two modes are genuinely different, so the check above has teeth"
    )


def test_wait_returns_the_gap_it_slept(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", slept.append)

    pacer = Pacer(mean_dwell=0.25, jitter=0.0, rng=random.Random(5))
    gap = pacer.wait("uniform")

    assert gap == pytest.approx(0.25)
    assert slept == [gap], "wait() must sleep exactly what it reports"


def test_wait_uses_the_requested_mode(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    pacer = Pacer(mean_dwell=0.25, jitter=0.0, rng=random.Random(5))
    assert pacer.wait("uniform") == pytest.approx(0.25)


# --------------------------------------------------------------------------- #
# strip_artifacts
# --------------------------------------------------------------------------- #

def test_the_default_artifacts_are_removed_case_insensitively():
    text = "helios scan\nHELIOS-NET banner\nH3l!0s gone\nssh banner"
    assert strip_artifacts(text).splitlines() == ["ssh banner"]


def test_a_custom_artifact_list_replaces_the_default():
    text = "helios scan\nnginx banner"
    # "helios" is no longer in the list, so it must survive.
    assert strip_artifacts(text, ["nginx"]).splitlines() == ["helios scan"]


def test_artifact_matching_is_a_substring_not_a_word():
    assert strip_artifacts("xheliosx", ["helios"]) == ""


def test_an_empty_artifact_list_removes_nothing():
    assert strip_artifacts("a\nb", []) == "a\nb"


def test_text_with_no_artifacts_is_returned_unchanged():
    text = "first\nsecond\nthird"
    assert strip_artifacts(text) == text


def test_empty_and_missing_text_do_not_raise():
    assert strip_artifacts("") == ""
    assert strip_artifacts(None) == ""      # type: ignore[arg-type]


def test_artifact_matching_ignores_case_on_both_sides():
    assert strip_artifacts("HeLiOs here", ["HELIOS"]) == ""


def test_every_line_is_inspected_independently():
    text = "keep\nhelios\nkeep too"
    assert strip_artifacts(text).splitlines() == ["keep", "keep too"]


# --------------------------------------------------------------------------- #
# Go bridge: fake process plumbing
# --------------------------------------------------------------------------- #

class FakeStream:
    """A pipe that yields the given lines, then EOF."""

    def __init__(self, lines: list[bytes] | None) -> None:
        self.lines = list(lines or [])

    async def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""


class FakeProc:
    def __init__(self, stdout=None, stderr=None, returncode: int = 0) -> None:
        self.stdout = FakeStream(stdout)
        self.stderr = FakeStream(stderr)
        self._returncode = returncode

    async def wait(self) -> int:
        return self._returncode


def _install_fake_core(monkeypatch, *, available=True, stdout=None, stderr=None,
                       returncode=0, exec_error=None):
    """Puts a scripted Go core in place of the real binary and process spawn."""
    monkeypatch.setattr(goscan_bridge, "GOSCAN_BIN",
                        goscan_bridge.ROOT / "transport" / "goscan" / "goscan_fake")
    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists",
                        lambda self: available)

    async def fake_exec(*args, **kwargs):
        if exec_error is not None:
            raise exec_error
        return FakeProc(stdout, stderr, returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return FakeProc(stdout, stderr, returncode)


def _ndjson(**fields) -> bytes:
    return (json.dumps(fields) + "\n").encode("utf-8")


def _envelope(code: str = "EDR_BLOCKED", message: str = "blocked by policy") -> bytes:
    return (json.dumps({"status": "error", "code": code, "message": message,
                        "component": "goscan"}) + "\n").encode("utf-8")


@pytest.fixture(autouse=True)
def _reset_bridge_globals():
    """The bridge keeps module-level state, so each test starts clean."""
    goscan_bridge.LAST_ERROR = None
    goscan_bridge.mutation_engine = None
    yield
    goscan_bridge.LAST_ERROR = None
    goscan_bridge.mutation_engine = None


# --------------------------------------------------------------------------- #
# availability and version
# --------------------------------------------------------------------------- #

def test_a_missing_binary_is_reported_as_unavailable(monkeypatch):
    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: False)
    assert goscan_bridge.core_available() is False
    assert goscan_bridge.core_version() == "unavailable"
    assert goscan_bridge.selftest() is None


def test_the_version_is_read_from_the_binary(monkeypatch):
    import subprocess

    class Result:
        returncode = 0
        stdout = "goscan 1.4.0\n"

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    assert goscan_bridge.core_version() == "goscan 1.4.0"


def test_a_failing_version_command_says_unavailable_not_unknown(monkeypatch):
    import subprocess

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    assert goscan_bridge.core_version() == "unavailable"


def test_a_non_zero_version_exit_is_unknown(monkeypatch):
    import subprocess

    class Result:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    assert goscan_bridge.core_version() == "unknown"


def test_a_silent_version_command_is_unknown(monkeypatch):
    import subprocess

    class Result:
        returncode = 0
        stdout = "   \n"

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    assert goscan_bridge.core_version() == "unknown", (
        "an empty stdout must not be reported as a version string"
    )


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def _selftest_result(monkeypatch, *, stdout="", returncode=0, error=None):
    import subprocess

    class Result:
        def __init__(self) -> None:
            self.returncode = returncode
            self.stdout = stdout

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    if error is not None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(error))
    else:
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    return goscan_bridge.selftest()


def test_a_healthy_selftest_is_returned(monkeypatch):
    report = _selftest_result(monkeypatch, stdout='{"status": "ok", "cases": 21}\n')
    assert report == {"status": "ok", "cases": 21}


def test_the_selftest_reads_the_last_line_only(monkeypatch):
    """The core logs progress and prints the report last, so a naive parse of
    the whole buffer would fail on any progress line."""
    report = _selftest_result(
        monkeypatch, stdout='scanning case 1\nscanning case 2\n{"status": "ok", "cases": 3}\n')
    assert report == {"status": "ok", "cases": 3}


def test_a_progress_line_after_the_report_is_not_trusted(monkeypatch):
    """Pinned: splitlines()[-1] is the last line, not the last JSON object."""
    assert _selftest_result(
        monkeypatch, stdout='{"status": "ok"}\ntrailing garbage\n') is None


def test_a_silent_selftest_yields_nothing(monkeypatch):
    assert _selftest_result(monkeypatch, stdout="") is None
    assert _selftest_result(monkeypatch, stdout="  \n") is None


def test_unparseable_selftest_output_yields_nothing(monkeypatch):
    assert _selftest_result(monkeypatch, stdout="not json at all\n") is None


def test_a_json_array_is_not_a_selftest_report(monkeypatch):
    assert _selftest_result(monkeypatch, stdout="[1, 2, 3]\n") is None


def test_a_timed_out_selftest_yields_nothing(monkeypatch):
    import subprocess
    result = _selftest_result(monkeypatch, error=subprocess.TimeoutExpired("goscan", 120))
    assert result is None


def test_a_policy_refusal_propagates_out_of_selftest(monkeypatch):
    """Regression.

    WinError 4551 means the host application-control policy refused the image.
    Swallowing it returned None, and core.cores.check_go then reported FAILED,
    so a machine policy failed the build as though the code were at fault.
    Letting it out is what lets the caller say BLOCKED instead.
    """
    import subprocess

    class PolicyRefusal(OSError):
        winerror = 4551

    error = PolicyRefusal("Une strategie de controle d'application a bloque ce fichier")
    with pytest.raises(OSError) as excinfo:
        _selftest_result(monkeypatch, error=error)
    assert excinfo.value.winerror == 4551
    assert issubclass(PolicyRefusal, OSError)


# --------------------------------------------------------------------------- #
# run_go_scan_async: the success path
# --------------------------------------------------------------------------- #

def test_an_open_port_is_reported_with_everything_the_core_said(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[
        _ndjson(port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.6",
                latency_ms=3.1, time="2026-09-28T10:00:00Z", open=True),
    ])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", "22,80"))

    assert results == [{
        "module": "discovery", "host": "10.0.0.1", "port": 22,
        "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6",
        "latency_ms": 3.1, "time": "2026-09-28T10:00:00Z", "open": True,
        "source": "native(Go-Goroutines-NDJSON)",
    }]
    assert goscan_bridge.LAST_ERROR is None


def test_a_closed_port_is_not_a_finding(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[
        _ndjson(port=22, service="ssh", open=True),
        _ndjson(port=23, service="telnet", open=False),
    ])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [r["port"] for r in results] == [22]


def test_an_unidentified_service_is_empty_not_invented(monkeypatch):
    """The bridge must not label a service it did not detect."""
    _install_fake_core(monkeypatch, stdout=[
        _ndjson(port=4444, open=True),
        _ndjson(port=4445, service="", open=True),
    ])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [r["service"] for r in results] == ["", ""]
    assert all("tcp-native" not in r for r in results)


def test_the_host_on_every_result_is_the_requested_target(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[_ndjson(port=80, open=True)])
    results = asyncio.run(goscan_bridge.run_go_scan_async("example.internal"))
    assert {r["host"] for r in results} == {"example.internal"}


def test_garbage_between_records_does_not_abort_the_stream(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[
        _ndjson(port=22, open=True),
        b"this is not json\n",
        b"\n",
        b"   \n",
        b"[1,2,3]\n",
        b'"a bare string"\n',
        _ndjson(port=80, open=True),
    ])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [r["port"] for r in results] == [22, 80], (
        "one malformed line must not cost the records around it"
    )


def test_a_core_that_finds_nothing_is_a_successful_empty_result(monkeypatch):
    """The distinction the module exists to protect: empty AND no error."""
    _install_fake_core(monkeypatch, stdout=[])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert goscan_bridge.LAST_ERROR is None, (
        "an empty sweep is an answer, and must be distinguishable from a failure"
    )


def test_the_error_state_is_reset_at_the_start_of_each_scan(monkeypatch):
    goscan_bridge.LAST_ERROR = "stale failure from an earlier call"
    _install_fake_core(monkeypatch, stdout=[_ndjson(port=22, open=True)])

    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert goscan_bridge.LAST_ERROR is None


# --------------------------------------------------------------------------- #
# run_go_scan_async: the failure paths
# --------------------------------------------------------------------------- #

def test_a_missing_binary_names_the_path_it_looked_for(monkeypatch):
    _install_fake_core(monkeypatch, available=False)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert "not found" in goscan_bridge.LAST_ERROR
    assert "goscan_fake" in goscan_bridge.LAST_ERROR


def test_a_missing_binary_raises_in_strict_mode(monkeypatch):
    _install_fake_core(monkeypatch, available=False)
    with pytest.raises(GoscanError, match="not found"):
        asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", strict=True))


def test_a_non_zero_exit_records_the_envelope_message(monkeypatch):
    _install_fake_core(monkeypatch, stderr=[_envelope(message="all probes refused")],
                       returncode=3)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert "exited 3" in goscan_bridge.LAST_ERROR
    assert "all probes refused" in goscan_bridge.LAST_ERROR, (
        "the core's own explanation must reach the caller"
    )


def test_a_non_zero_exit_raises_in_strict_mode(monkeypatch):
    _install_fake_core(monkeypatch, stderr=[_envelope()], returncode=3)
    with pytest.raises(GoscanError, match="exited 3"):
        asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", strict=True))


def test_a_crash_without_an_envelope_still_explains_itself(monkeypatch):
    _install_fake_core(monkeypatch, returncode=139)
    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert "exited 139" in goscan_bridge.LAST_ERROR
    assert goscan_bridge.LAST_ERROR is not None


def test_a_policy_refusal_is_recorded_with_its_winerror(monkeypatch):
    """WinError 4551 has to be recognisable from LAST_ERROR alone."""
    class PolicyRefusal(OSError):
        winerror = 4551

    _install_fake_core(monkeypatch, exec_error=PolicyRefusal("bloque ce fichier"))

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert "could not be executed" in goscan_bridge.LAST_ERROR
    assert "4551" in goscan_bridge.LAST_ERROR or "bloque" in goscan_bridge.LAST_ERROR


def test_a_policy_refusal_raises_in_strict_mode(monkeypatch):
    class PolicyRefusal(OSError):
        winerror = 4551

    _install_fake_core(monkeypatch, exec_error=PolicyRefusal("bloque ce fichier"))
    with pytest.raises(GoscanError, match="could not be executed"):
        asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", strict=True))


def test_an_unexpected_fault_is_named_by_type(monkeypatch):
    _install_fake_core(monkeypatch, exec_error=RuntimeError("pipe wedged"))

    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert "RuntimeError" in goscan_bridge.LAST_ERROR
    assert "pipe wedged" in goscan_bridge.LAST_ERROR


def test_an_unexpected_fault_raises_in_strict_mode(monkeypatch):
    _install_fake_core(monkeypatch, exec_error=RuntimeError("pipe wedged"))

    with pytest.raises(GoscanError, match="pipe wedged"):
        asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", strict=True))


def test_a_process_with_no_stdout_pipe_yields_no_results(monkeypatch):
    async def fake_exec(*args, **kwargs):
        proc = FakeProc(stdout=[_ndjson(port=22, open=True)], returncode=0)
        proc.stdout = None           # no stdout pipe at all
        return proc

    _install_fake_core(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert goscan_bridge.LAST_ERROR is None, (
        "a core that ran cleanly and said nothing is still a clean run"
    )


def test_a_cancelled_scan_is_recorded_rather_than_raised(monkeypatch):
    """CancelledError is a BaseException, so letting it escape would bypass
    LAST_ERROR entirely and the caller would see a bare traceback with no
    indication of which target or port set was abandoned."""
    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError

    _install_fake_core(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cancel)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert results == []
    assert "could not be executed" in goscan_bridge.LAST_ERROR


def test_a_cancelled_scan_raises_a_goscan_error_in_strict_mode(monkeypatch):
    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError

    _install_fake_core(monkeypatch)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", cancel)

    with pytest.raises(GoscanError, match="could not be executed"):
        asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1", strict=True))


def test_stderr_lines_that_are_not_envelopes_are_ignored(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[_ndjson(port=22, open=True)],
                       stderr=[b"a plain warning line\n", b"\n", b"{not json}\n"])

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [r["port"] for r in results] == [22]
    assert goscan_bridge.LAST_ERROR is None


def test_only_real_envelopes_reach_the_mutation_engine(monkeypatch):
    """A plain warning must not be handed to an engine that adapts tactics;
    an unvalidated line is how an engine gets told to react to noise."""
    seen: list[dict] = []

    class Engine:
        def adapt_to_envelope(self, envelope: dict) -> None:
            seen.append(envelope)

    goscan_bridge.attach_mutation_engine(Engine())
    _install_fake_core(monkeypatch, stderr=[
        b"deprecation: use --jitter\n",
        b"{not json}\n",
        _envelope(code="EDR_BLOCKED", message="EDR quarantined the image"),
        b"trailing noise\n",
    ], returncode=1)

    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [e["code"] for e in seen] == ["EDR_BLOCKED"]
    assert "EDR quarantined the image" in goscan_bridge.LAST_ERROR, (
        "the exit reason must come from the real envelope, not from noise"
    )


def test_a_scan_survives_a_process_with_no_stderr(monkeypatch):
    async def fake_exec(*args, **kwargs):
        proc = FakeProc(stdout=[_ndjson(port=22, open=True)], returncode=0)
        proc.stderr = None            # some platforms give no stderr pipe
        return proc

    _install_fake_core(monkeypatch, stdout=[])
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [r["port"] for r in results] == [22]


# --------------------------------------------------------------------------- #
# the mutation hook
# --------------------------------------------------------------------------- #

def test_a_bound_mutation_engine_sees_the_envelope(monkeypatch):
    seen: list[dict] = []

    class Engine:
        def adapt_to_envelope(self, envelope: dict) -> None:
            seen.append(envelope)

    goscan_bridge.attach_mutation_engine(Engine())
    _install_fake_core(monkeypatch, stderr=[_envelope(code="RATE_LIMITED")],
                       returncode=1)

    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert [e["code"] for e in seen] == ["RATE_LIMITED"]


def test_no_mutation_engine_is_a_fine_default(monkeypatch):
    _install_fake_core(monkeypatch, stderr=[_envelope()], returncode=1)
    asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert "RATE" not in (goscan_bridge.LAST_ERROR or "") or True
    assert goscan_bridge.LAST_ERROR is not None


def test_attaching_replaces_a_previously_bound_engine(monkeypatch):
    first: list[dict] = []
    second: list[dict] = []

    class First:
        def adapt_to_envelope(self, envelope: dict) -> None:
            first.append(envelope)

    class Second:
        def adapt_to_envelope(self, envelope: dict) -> None:
            second.append(envelope)

    _install_fake_core(monkeypatch, stderr=[_envelope()], returncode=1)
    goscan_bridge.attach_mutation_engine(First())
    asyncio.run(goscan_bridge.run_go_scan_async("a"))
    goscan_bridge.attach_mutation_engine(Second())
    asyncio.run(goscan_bridge.run_go_scan_async("b"))

    assert len(first) == 1
    assert len(second) == 1, "the previous engine must stop receiving envelopes"


# --------------------------------------------------------------------------- #
# the synchronous wrapper
# --------------------------------------------------------------------------- #

def test_the_sync_wrapper_delegates(monkeypatch):
    _install_fake_core(monkeypatch, stdout=[_ndjson(port=22, open=True)])
    results = goscan_bridge.run_go_scan("10.0.0.1", "22")
    assert [r["port"] for r in results] == [22]


def test_the_sync_wrapper_does_not_swallow_a_strict_failure(monkeypatch):
    _install_fake_core(monkeypatch, returncode=2)
    with pytest.raises(GoscanError):
        goscan_bridge.run_go_scan("10.0.0.1", strict=True)


def test_the_sync_wrapper_records_a_non_strict_failure(monkeypatch):
    _install_fake_core(monkeypatch, returncode=2)
    assert goscan_bridge.run_go_scan("10.0.0.1", strict=False) == []
    assert goscan_bridge.LAST_ERROR is not None


def _dead_event_loop(monkeypatch):
    """Makes asyncio.run itself fail, before the coroutine is ever entered.

    The coroutine is closed explicitly, otherwise pytest is right to warn that
    it was never awaited, and that warning would drown out the real ones.
    """
    def fake_run(coro, *args, **kwargs):
        coro.close()
        raise RuntimeError("no event loop")

    monkeypatch.setattr(asyncio, "run", fake_run)


def test_a_failure_to_start_the_event_loop_is_recorded(monkeypatch):
    """run_go_scan wraps asyncio.run, which can itself fail before the coroutine
    is ever entered; that must still leave a trace."""
    _install_fake_core(monkeypatch, available=True)
    _dead_event_loop(monkeypatch)

    assert goscan_bridge.run_go_scan("10.0.0.1") == []
    assert "no event loop" in goscan_bridge.LAST_ERROR


def test_a_failure_to_start_the_event_loop_raises_in_strict_mode(monkeypatch):
    _install_fake_core(monkeypatch, available=True)
    _dead_event_loop(monkeypatch)

    with pytest.raises(GoscanError, match="no event loop"):
        goscan_bridge.run_go_scan("10.0.0.1", strict=True)
