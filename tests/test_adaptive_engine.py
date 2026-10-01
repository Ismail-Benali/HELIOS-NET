"""Tests for the adaptive scan engine and the autonomous daemon.

The AIMD controller is a congestion-control loop: it must grow on success and
shrink on failure, inside its configured bounds. Several of these tests pin that
because the failure branch is easy to write in a way that never runs.

The daemon is a supervisory loop, so the tests check the properties that make it
safe to leave running: a cycle is recorded transactionally, a failing cycle rolls
back instead of half-committing, and a no-signal cycle is recorded as a warning
rather than a success.
"""

from __future__ import annotations

import asyncio

import pytest

from core import async_engine
from core.async_engine import (
    AIMDController,
    adaptive_banner_probe,
    enterprise_adaptive_recon,
    jittered_backoff,
)
from core.daemon import AutonomousDaemon


class FakeReader:
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload

    async def read(self, size: int) -> bytes:
        return self.payload


class FakeWriter:
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def write(self, payload: bytes) -> None:
        self.written += payload

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _patch_connection(monkeypatch, reader_payload=b"", exception=None) -> list[FakeWriter]:
    made: list[FakeWriter] = []

    async def fake_open_connection(host, port, **kwargs):
        if exception is not None:
            raise exception
        writer = FakeWriter()
        made.append(writer)
        return FakeReader(reader_payload), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return made


# --------------------------------------------------------------------------- #
# AIMD controller
# --------------------------------------------------------------------------- #

def test_success_grows_the_window_additively():
    controller = AIMDController(initial_concurrency=10, min_c=2, max_c=20)
    asyncio.run(controller.onSuccess())
    assert controller.concurrency == 10.5


def test_failure_shrinks_the_window_multiplicatively():
    controller = AIMDController(initial_concurrency=10, min_c=2, max_c=20)
    asyncio.run(controller.onError())
    assert controller.concurrency == 5.0
    asyncio.run(controller.onError())
    assert controller.concurrency == 2.5


def test_the_window_never_exceeds_the_ceiling():
    controller = AIMDController(initial_concurrency=95, min_c=2, max_c=100)
    for _ in range(50):
        asyncio.run(controller.onSuccess())
    assert controller.concurrency == 100.0


def test_the_window_never_falls_below_the_floor():
    controller = AIMDController(initial_concurrency=10, min_c=2, max_c=100)
    for _ in range(50):
        asyncio.run(controller.onError())
    assert controller.concurrency == 2.0


def test_the_controller_reports_a_whole_number():
    controller = AIMDController(initial_concurrency=10)
    assert asyncio.run(controller.get()) == 10
    asyncio.run(controller.onSuccess())
    assert asyncio.run(controller.get()) == 10, "0.5 steps truncate, they do not round up"


def test_concurrent_updates_do_not_lose_a_step(monkeypatch):
    """The lock must serialise the read-modify-write, or an await inside the
    critical section would let two updates both read the same value."""
    controller = AIMDController(initial_concurrency=10, min_c=2, max_c=1000)

    async def run() -> None:
        await asyncio.gather(*[controller.onSuccess() for _ in range(20)])

    asyncio.run(run())
    assert controller.concurrency == 20.0, "10 + 20 * 0.5, with no lost updates"


# --------------------------------------------------------------------------- #
# jittered backoff
# --------------------------------------------------------------------------- #

def test_backoff_doubles_per_attempt(monkeypatch):
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def run() -> None:
        for attempt in range(1, 5):
            await jittered_backoff(base_delay=0.1, max_delay=100.0, attempt=attempt)

    asyncio.run(run())
    # Each call sleeps base * 2**(attempt-1) plus a jitter of up to half of it.
    for index, actual in enumerate(slept):
        expected = 0.1 * (2 ** index)
        assert expected <= actual <= expected * 1.5, (expected, actual)


def test_backoff_is_capped(monkeypatch):
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def run() -> None:
        await jittered_backoff(base_delay=1.0, max_delay=5.0, attempt=20)

    asyncio.run(run())
    assert slept[0] <= 5.0 * 1.5, "the cap must bound the sleep, jitter included"


# --------------------------------------------------------------------------- #
# adaptive_banner_probe
# --------------------------------------------------------------------------- #

def test_an_open_port_is_probed_with_a_head_request(monkeypatch):
    made = _patch_connection(monkeypatch, b"HTTP/1.1 200 OK\r\n")
    result = asyncio.run(adaptive_banner_probe("10.0.0.1", 80))

    assert result["open"] is True
    assert result["banner"] == "HTTP/1.1 200 OK"
    assert made[0].written == b"HEAD / HTTP/1.0\r\n\r\n"
    assert made[0].closed is True


def test_a_silent_service_is_still_open(monkeypatch):
    """A connection that answers with nothing is open, just uninformative."""
    _patch_connection(monkeypatch, b"")
    result = asyncio.run(adaptive_banner_probe("10.0.0.1", 8080))
    assert result["open"] is True
    assert result["banner"] == ""


class ExplodingReader(FakeReader):
    async def read(self, size: int) -> bytes:
        raise ConnectionResetError("peer reset mid-read")


def test_a_read_failure_does_not_downgrade_an_open_port(monkeypatch):
    """The port answered, so it is open. Only the banner is lost.

    Simulated by failing the read rather than wait_for, because wait_for also
    wraps the connect and that would change what is under test.
    """
    async def fake_open_connection(host, port, **kwargs):
        return ExplodingReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(adaptive_banner_probe("10.0.0.1", 80))
    assert result["open"] is True
    assert result["banner"] == ""


def test_a_refused_connection_is_closed(monkeypatch):
    _patch_connection(monkeypatch, exception=ConnectionRefusedError("refused"))
    result = asyncio.run(adaptive_banner_probe("10.0.0.1", 22))
    assert result["open"] is False
    assert result["banner"] == ""


def test_a_timed_out_connection_is_closed(monkeypatch):
    _patch_connection(monkeypatch, exception=asyncio.TimeoutError())
    result = asyncio.run(adaptive_banner_probe("10.0.0.1", 22))
    assert result["open"] is False


def test_the_reported_rtt_is_elapsed_time_and_may_round_to_zero(monkeypatch):
    """Pinned because rtt cannot be used as a success test in either direction.

    It is wall-clock time rather than a status, and it is rounded to four
    places, so a fast probe can report exactly 0.0. The recon loop's old
    `res["rtt"] > 0` check was true for essentially every probe.
    """
    _patch_connection(monkeypatch, b"ok")
    instant = asyncio.run(adaptive_banner_probe("10.0.0.1", 80))
    assert instant["rtt"] == 0.0, "a sub-50us probe rounds to zero"
    assert instant["rtt"] >= 0.0


# --------------------------------------------------------------------------- #
# enterprise_adaptive_recon
# --------------------------------------------------------------------------- #

def test_recon_returns_only_the_open_ports(monkeypatch):
    async def fake_probe(host, port, timeout=2.0):
        return {"host": host, "port": port, "open": port in (22, 443),
                "banner": "", "rtt": 0.001}

    monkeypatch.setattr(async_engine, "adaptive_banner_probe", fake_probe)
    results = asyncio.run(enterprise_adaptive_recon("10.0.0.1", [22, 80, 443]))
    assert {r["port"] for r in results} == {22, 443}


def test_every_port_is_probed_exactly_once(monkeypatch):
    seen: list[int] = []

    async def fake_probe(host, port, timeout=2.0):
        seen.append(port)
        return {"host": host, "port": port, "open": False, "banner": "", "rtt": 0.0}

    monkeypatch.setattr(async_engine, "adaptive_banner_probe", fake_probe)
    ports = list(range(1, 25))
    asyncio.run(enterprise_adaptive_recon("10.0.0.1", ports))
    assert sorted(seen) == ports, "a port must not be skipped or double-visited"


def test_a_closed_port_makes_the_controller_back_off(monkeypatch):
    """Regression.

    The loop treated `res["rtt"] > 0` as success. rtt is elapsed wall-clock
    time and is positive on every returned probe, so the failure branch was
    unreachable: the controller could only ever grow, and a fully filtered
    subnet would drive the concurrency to the ceiling.
    """
    seen: list[float] = []

    class Recording(AIMDController):
        async def onSuccess(self) -> None:
            seen.append(self.concurrency)
            await super().onSuccess()

        async def onError(self) -> None:
            seen.append(self.concurrency)
            await super().onError()

    async def fake_probe(host, port, timeout=2.0):
        return {"host": host, "port": port, "open": False, "banner": "", "rtt": 0.002}

    monkeypatch.setattr(async_engine, "adaptive_banner_probe", fake_probe)
    monkeypatch.setattr(async_engine, "AIMDController", Recording)
    monkeypatch.setattr(async_engine, "jittered_backoff", _no_backoff)

    asyncio.run(enterprise_adaptive_recon("10.0.0.1", [1, 2, 3, 4]))
    assert seen, "the controller must be consulted at all"
    assert seen == sorted(seen, reverse=True), f"must decrease on failure: {seen}"


def test_an_open_port_makes_the_controller_grow(monkeypatch):
    seen: list[float] = []

    class Recording(AIMDController):
        async def onSuccess(self) -> None:
            seen.append(self.concurrency)
            await super().onSuccess()

        async def onError(self) -> None:
            seen.append(self.concurrency)
            await super().onError()

    async def fake_probe(host, port, timeout=2.0):
        return {"host": host, "port": port, "open": True, "banner": "", "rtt": 0.002}

    monkeypatch.setattr(async_engine, "adaptive_banner_probe", fake_probe)
    monkeypatch.setattr(async_engine, "AIMDController", Recording)
    monkeypatch.setattr(async_engine, "jittered_backoff", _no_backoff)

    asyncio.run(enterprise_adaptive_recon("10.0.0.1", [1, 2, 3, 4]))
    assert seen == sorted(seen), f"must increase on success: {seen}"


async def _no_backoff(*args, **kwargs) -> None:
    return None


def test_no_ports_means_no_results(monkeypatch):
    async def fake_probe(host, port, timeout=2.0):
        raise AssertionError("nothing to probe")

    monkeypatch.setattr(async_engine, "adaptive_banner_probe", fake_probe)
    assert asyncio.run(enterprise_adaptive_recon("10.0.0.1", [])) == []


# --------------------------------------------------------------------------- #
# AutonomousDaemon
# --------------------------------------------------------------------------- #

@pytest.fixture()
def services(monkeypatch):
    """Lets each test decide what the recon sweep finds."""
    import core.daemon as daemon_module

    box: dict = {"active": []}

    async def fake_recon(target, ports):
        return box["active"]

    monkeypatch.setattr(daemon_module, "enterprise_adaptive_recon", fake_recon)
    return box


def _replayed_ops(tmp_path) -> list[str]:
    """Reads the WAL back through its own decrypting interface.

    The file on disk is encrypted, so the operation names cannot be found by
    reading the bytes; only replay() can see them.
    """
    from core.wal import TransactionalWAL

    return [str(record.get("op")) for record in
            TransactionalWAL(tmp_path / "daemon_missions.wal").replay()]


def test_a_cycle_with_findings_is_committed(tmp_path, services):
    services["active"] = [{"host": "10.0.0.1", "port": 22, "open": True,
                           "banner": "", "rtt": 0.0}]
    daemon = AutonomousDaemon("10.0.0.1", tmp_path)
    asyncio.run(daemon.run_mission_cycle())

    ops = _replayed_ops(tmp_path)
    assert "MISSION_START" in ops
    assert "MISSION_SUCCESS" in ops


def test_a_committed_cycle_is_recoverable_after_a_restart(tmp_path, services):
    """A daemon that is killed and restarted must find its last cycle."""
    from core.wal import TransactionalWAL

    services["active"] = [{"host": "10.0.0.1", "port": 22, "open": True,
                           "banner": "", "rtt": 0.0}]
    asyncio.run(AutonomousDaemon("10.0.0.1", tmp_path).run_mission_cycle())

    records = TransactionalWAL(tmp_path / "daemon_missions.wal").replay()
    assert records, "an encrypted WAL must still replay its own records"
    assert all("lsn" in record for record in records), "records must be sequenced"


def test_a_cycle_with_nothing_found_is_a_warning_not_a_success(tmp_path, services):
    """A quiet network must not be recorded as a successful mission."""
    services["active"] = []
    daemon = AutonomousDaemon("10.0.0.1", tmp_path)
    asyncio.run(daemon.run_mission_cycle())

    ops = _replayed_ops(tmp_path)
    assert "MISSION_WARNING" in ops
    assert "MISSION_SUCCESS" not in ops


def test_a_failing_cycle_rolls_back_instead_of_committing(tmp_path, monkeypatch, services):
    """Nothing may survive a cycle that raised, not even its MISSION_START."""
    import core.daemon as daemon_module

    async def boom(target, ports):
        raise RuntimeError("recon exploded")

    monkeypatch.setattr(daemon_module, "enterprise_adaptive_recon", boom)
    asyncio.run(AutonomousDaemon("10.0.0.1", tmp_path).run_mission_cycle())

    ops = _replayed_ops(tmp_path)
    assert "MISSION_SUCCESS" not in ops
    assert "MISSION_WARNING" not in ops
    assert "MISSION_START" not in ops, "a rolled-back cycle leaves no partial trace"


def test_a_failing_cycle_does_not_propagate(tmp_path, monkeypatch, services):
    """The daemon is unsupervised, so a bad cycle must not kill the loop."""
    import core.daemon as daemon_module

    async def boom(target, ports):
        raise RuntimeError("recon exploded")

    monkeypatch.setattr(daemon_module, "enterprise_adaptive_recon", boom)
    daemon = AutonomousDaemon("10.0.0.1", tmp_path)
    asyncio.run(daemon.run_mission_cycle())       # must not raise


def test_the_pacer_is_built_from_the_interval(tmp_path, services):
    daemon = AutonomousDaemon("10.0.0.1", tmp_path, interval_seconds=5.0)
    assert daemon.pacer.mean_dwell == 5.0
    assert daemon.pacer.jitter == pytest.approx(1.75)


def test_stop_ends_the_loop(tmp_path, services, monkeypatch):
    cycles: list[int] = []
    daemon = AutonomousDaemon("10.0.0.1", tmp_path, interval_seconds=0.001)

    async def counting_cycle() -> None:
        cycles.append(1)
        daemon.stop()               # ask the loop to end after one cycle

    async def instant_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(daemon, "run_mission_cycle", counting_cycle)
    monkeypatch.setattr(asyncio, "sleep", instant_sleep)
    asyncio.run(daemon.start())

    assert cycles == [1], "the loop must exit once stopped"
    assert daemon._running is False


def test_start_really_keeps_going(tmp_path, services, monkeypatch):
    """The counterpart to the stop test: without a stop, the loop must not
    exit after one cycle, which is the whole point of a daemon."""
    daemon = AutonomousDaemon("10.0.0.1", tmp_path, interval_seconds=0.001)
    cycles: list[int] = []

    async def counting_cycle() -> None:
        cycles.append(1)
        if len(cycles) >= 3:
            daemon.stop()

    async def instant_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(daemon, "run_mission_cycle", counting_cycle)
    monkeypatch.setattr(asyncio, "sleep", instant_sleep)
    asyncio.run(daemon.start())

    assert len(cycles) == 3
