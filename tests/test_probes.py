"""Tests for the service and fingerprint probes.

Both modules reach the network through a plain `socket.socket`, so a single
fake socket drives the open, refused, reset and silent paths. The point of these
tests is the *honesty* of the output: the code documents that it reports which
method produced an answer and that a refusal is not a timeout, and the tests
check exactly that.
"""

from __future__ import annotations

import socket as socket_module

import pytest

from modules.discovery import service
from modules.recon import fingerprint


class FakeSocket:
    """A socket whose connect outcome and reply are scripted."""

    def __init__(self, outcome, reply: bytes = b"", error: BaseException | None = None):
        self.outcome = outcome
        self.reply = reply
        self.error = error
        self.connected: tuple | None = None
        self.sent = bytearray()
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, address) -> None:
        self.connected = address
        if self.error is not None:
            raise self.error
        if self.outcome == "refused":
            raise ConnectionRefusedError(f"{address[0]}:{address[1]} refused")
        if self.outcome == "filtered":
            raise socket_module.timeout("timed out")

    def sendall(self, payload: bytes) -> None:
        self.sent += payload

    def recv(self, size: int) -> bytes:
        return self.reply

    def close(self) -> None:
        self.closed = True


def _patch_socket(monkeypatch, outcome, reply=b"", error=None) -> list[FakeSocket]:
    made: list[FakeSocket] = []

    def factory(*args, **kwargs):
        sock = FakeSocket(outcome, reply=reply, error=error)
        made.append(sock)
        return sock

    monkeypatch.setattr(service.socket, "socket", factory)
    return made


# --------------------------------------------------------------------------- #
# discover_ports
# --------------------------------------------------------------------------- #

def test_only_open_ports_are_reported(monkeypatch):
    _patch_socket(monkeypatch, "open")
    results = service.discover_ports("10.0.0.1", ports=[22, 80, 443])

    assert [r["port"] for r in results] == [22, 80, 443]
    assert all(r["open"] is True for r in results)


def test_refused_and_filtered_ports_are_absent_from_the_sheet(monkeypatch):
    _patch_socket(monkeypatch, "refused")
    assert service.discover_ports("10.0.0.1", ports=[22]) == []


def test_a_timeout_is_not_reported_as_open(monkeypatch):
    _patch_socket(monkeypatch, "filtered")
    assert service.discover_ports("10.0.0.1", ports=[22]) == []


def test_results_are_sorted_by_port(monkeypatch):
    _patch_socket(monkeypatch, "open")
    results = service.discover_ports("10.0.0.1", ports=[443, 22, 8080, 80])
    assert [r["port"] for r in results] == [22, 80, 443, 8080]


def test_a_known_port_carries_its_service_name(monkeypatch):
    _patch_socket(monkeypatch, "open")
    by_port = {r["port"]: r["service"] for r in
               service.discover_ports("10.0.0.1", ports=[22, 80])}
    assert by_port == {22: "SSH", 80: "HTTP"}


def test_an_unofficial_port_is_labelled_unknown(monkeypatch):
    _patch_socket(monkeypatch, "open")
    results = service.discover_ports("10.0.0.1", ports=[31337])
    assert results[0]["service"] == "unknown", (
        "an unrecognised port must not borrow another service's name"
    )


def test_the_default_port_set_is_the_common_one(monkeypatch):
    made = _patch_socket(monkeypatch, "open")
    results = service.discover_ports("10.0.0.1")
    assert len(results) == len(service.COMMON_PORTS)
    assert {r["port"] for r in results} == set(service.COMMON_PORTS)
    assert len(made) == len(service.COMMON_PORTS), "every port must actually be probed"


def test_every_socket_is_closed_even_when_the_probe_fails(monkeypatch):
    made = _patch_socket(monkeypatch, "refused")
    service.discover_ports("10.0.0.1", ports=[22, 80])
    assert made and all(s.closed for s in made), "a failed probe must not leak its socket"


def test_the_probe_connects_to_the_requested_host(monkeypatch):
    made = _patch_socket(monkeypatch, "open")
    service.discover_ports("10.0.0.1", ports=[22])
    assert made[0].connected == ("10.0.0.1", 22)


def test_the_timeout_is_passed_to_the_socket(monkeypatch):
    made = _patch_socket(monkeypatch, "open")
    service.discover_ports("10.0.0.1", ports=[22], timeout=0.25)
    assert made[0].timeout == 0.25


# --------------------------------------------------------------------------- #
# native_connect_probe: the honest-reporting contract
# --------------------------------------------------------------------------- #

def _go_available(monkeypatch) -> None:
    """Marks the Go backend usable.

    `core.accel` checks availability before dispatching, so a test that only
    stubs `run_go_scan` would silently exercise the socket probe instead of the
    backend it means to test.
    """
    from modules.discovery import goscan_bridge

    monkeypatch.setattr(goscan_bridge, "core_available", lambda: True)
    monkeypatch.setattr(goscan_bridge, "LAST_ERROR", None)


def test_a_go_hit_is_reported_as_open_with_its_own_source(monkeypatch):
    from modules.discovery import goscan_bridge

    _go_available(monkeypatch)
    monkeypatch.setattr(goscan_bridge, "run_go_scan", lambda *a, **k: [
        {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6",
         "latency_ms": 3, "source": "native(Go)"}])

    result = service.native_connect_probe("10.0.0.1", 22)
    assert result["open"] is True
    assert result["state"] == "open"
    assert result["service"] == "ssh"
    assert result["banner"] == "SSH-2.0-OpenSSH_9.6"
    assert result["latency_ms"] == 3
    assert result["source"] == "native(Go)"
    assert result["engine"] == "go-native", "the core that answered is named"


def test_a_go_miss_with_no_error_is_reported_as_closed_by_the_go_core(monkeypatch):
    from modules.discovery import goscan_bridge

    _go_available(monkeypatch)
    monkeypatch.setattr(goscan_bridge, "run_go_scan", lambda *a, **k: [])

    result = service.native_connect_probe("10.0.0.1", 22)
    assert result["open"] is False
    assert result["state"] == "closed"
    assert result["source"] == "native(Go)", "an empty answer is still an answer"
    assert result["engine"] == "go-native"


def test_a_failed_go_core_falls_back_and_says_so(monkeypatch):
    """Pinned: the fallback must name itself, or a caller cannot tell which
    method answered."""
    from modules.discovery import goscan_bridge

    _go_available(monkeypatch)
    monkeypatch.setattr(goscan_bridge, "run_go_scan",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no go core")))
    made = _patch_socket(monkeypatch, "open")

    result = service.native_connect_probe("10.0.0.1", 22)
    assert result["source"] == "fallback(socket)"
    assert result["state"] == "unknown", "a socket connect proves less than a Go scan"
    assert "no go core" in result["note"]
    assert result["open"] is True
    assert result["engine"] == "python-fallback"
    assert made, "the socket fallback must actually have been used"


def test_a_go_core_that_could_not_run_is_not_reported_as_closed(monkeypatch):
    """An empty result set plus a recorded failure is not a clean sweep.

    The bridge records failures on a module global; treating an empty answer as
    "closed" would report a confident verdict for a probe that never ran.
    """
    from modules.discovery import goscan_bridge

    _go_available(monkeypatch)
    monkeypatch.setattr(goscan_bridge, "run_go_scan", lambda *a, **k: [])
    monkeypatch.setattr(goscan_bridge, "LAST_ERROR", "go core blocked by policy")
    _patch_socket(monkeypatch, "refused")

    result = service.native_connect_probe("10.0.0.1", 22)
    assert result["state"] == "unknown"
    assert result["open"] is False
    # The recorded failure survives into the note, so the empty answer is never
    # read as a clean sweep. Matched as a substring: the reason also names the
    # exception type, which is not part of this contract.
    assert "go core blocked by policy" in result["note"]
    assert result["note"].startswith("skipped go:")
    assert "fallback" in result["source"]


def test_the_deprecated_syn_alias_delegates_and_does_not_claim_a_syn_probe(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(service, "native_connect_probe",
                        lambda host, port, timeout: calls.append((host, port, timeout))
                        or {"state": "open"})

    result = service.native_syn_probe("10.0.0.1", 22, 1.5)
    assert calls == [("10.0.0.1", 22, 1.5)]
    assert result["state"] == "open"


# --------------------------------------------------------------------------- #
# TTL heuristic
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ttl,expected", [
    (None, "Unknown (no TTL observed)"),
    (0, "Linux/Unix-like (TTL<=64)"),
    (64, "Linux/Unix-like (TTL<=64)"),
    (65, "Linux/Unix-like (TTL 65-128)"),
    (128, "Linux/Unix-like (TTL 65-128)"),
    (129, "Windows-like (TTL>128)"),
    (255, "Windows-like (TTL>128)"),
])
def test_the_ttl_bands_match_their_documented_thresholds(ttl, expected):
    assert fingerprint._ttl_family(ttl) == expected


# --------------------------------------------------------------------------- #
# fingerprint_host
# --------------------------------------------------------------------------- #

def test_the_default_signal_resolves_to_linux():
    result = fingerprint.fingerprint_host("10.0.0.1")
    assert result["source"] == "bayes-multi-signal"
    assert result["method"] == "bayes"
    assert result["os_guess"].startswith("Linux")
    assert 0.0 < result["confidence"] <= 1.0


def test_a_windows_signal_is_identified_as_windows():
    result = fingerprint.fingerprint_host(
        "10.0.0.1", {"ttl": 128, "window": 65535, "tcp_options_len": 40})
    assert result["os_guess"].startswith("Windows")


def test_the_confidence_is_carried_through_to_the_sheet():
    result = fingerprint.fingerprint_host("10.0.0.1")
    assert isinstance(result["confidence"], float)


def test_a_signal_the_bayesian_model_rejects_falls_back_and_stays_humble():
    """A broken signal must not crash recon, and the fallback must say it is
    a weaker method.

    Regression: the fallback then passed the same unusable TTL to the band
    comparison, which raised TypeError and took the campaign down on exactly
    the input the fallback exists to survive.
    """
    result = fingerprint.fingerprint_host("10.0.0.1", {"ttl": "not-a-number"})

    assert result["method"] == "ttl-heuristic"
    assert result["confidence"] == "low"
    assert result["source"] == "local-model"
    assert "rejected the signal" in result["note"]


def test_the_fallback_reports_an_unusable_ttl_instead_of_guessing():
    result = fingerprint.fingerprint_host("10.0.0.1", {"ttl": "not-a-number"})
    assert result["os_guess"] == "Unknown (TTL unusable)", (
        "a value it cannot read must not be presented as an OS family"
    )


def test_a_numeric_ttl_still_uses_the_bayesian_path():
    result = fingerprint.fingerprint_host("10.0.0.1", {"ttl": 200})
    assert result["method"] == "bayes"
    assert result["os_guess"].startswith("Windows")


# --------------------------------------------------------------------------- #
# banner_grab
# --------------------------------------------------------------------------- #

def test_a_banner_is_returned_decoded_and_trimmed(monkeypatch):
    _patch_socket(monkeypatch, "open", reply=b"  SSH-2.0-OpenSSH_9.6\r\n  ")
    result = fingerprint.banner_grab("10.0.0.1", 22)
    assert result["banner"] == "SSH-2.0-OpenSSH_9.6"
    assert result["port"] == 22


def test_the_default_probe_is_sent_before_reading(monkeypatch):
    made = _patch_socket(monkeypatch, "open", reply=b"hi")
    fingerprint.banner_grab("10.0.0.1", 80)
    assert made[0].sent == b"\r\n", "a bare CRLF is enough to make many services speak"


def test_a_custom_probe_is_sent_when_asked(monkeypatch):
    made = _patch_socket(monkeypatch, "open", reply=b"220 ready")
    fingerprint.banner_grab("10.0.0.1", 25, probe=b"HELO test\r\n")
    assert made[0].sent == b"HELO test\r\n"


def test_an_unreadable_banner_becomes_an_error_marker_not_an_exception(monkeypatch):
    _patch_socket(monkeypatch, "refused")
    result = fingerprint.banner_grab("10.0.0.1", 22)
    assert result["banner"].startswith("<error:")
    assert "refused" in result["banner"]


def test_a_silent_service_yields_an_empty_banner(monkeypatch):
    _patch_socket(monkeypatch, "open", reply=b"")
    assert fingerprint.banner_grab("10.0.0.1", 22)["banner"] == ""


def test_the_banner_is_capped_so_a_dumping_service_cannot_blow_up_the_sheet(monkeypatch):
    _patch_socket(monkeypatch, "open", reply=b"A" * 5000)
    result = fingerprint.banner_grab("10.0.0.1", 80)
    assert len(result["banner"]) == 200


def test_undecodable_bytes_are_replaced_rather_than_raising(monkeypatch):
    _patch_socket(monkeypatch, "open", reply=b"\xff\xfe\x00bad")
    assert fingerprint.banner_grab("10.0.0.1", 22)["banner"]


def test_the_socket_is_always_closed(monkeypatch):
    made = _patch_socket(monkeypatch, "open", reply=b"x")
    fingerprint.banner_grab("10.0.0.1", 22)
    assert made[0].closed is True
