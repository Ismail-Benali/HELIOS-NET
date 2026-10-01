"""HELIOS-NET :: tests/test_scan_parity.py
Cross-backend tests for the port-scan capability in `core.accel`.

The Go core and the Python socket probe are two answers to the same question:
which of these ports answered. They were wired up as a hand-rolled try/except,
so nothing compared them and the fallback's weaker claims were easy to lose - a
regression in this file caught the socket probe reporting a confident
`state: "open"` where the contract reserves that verdict for the native core.

The invariant: on the same host and port list both backends must agree on *which*
ports are open. They deliberately disagree on *how much they know* about a port,
and that difference is part of the contract rather than a defect.
"""

from __future__ import annotations

import pytest

from core import accel


class FakeSocket:
    """Records the connects it is asked for and answers a fixed way."""

    def __init__(self, made: list, open_ports: set[int], host: str) -> None:
        self._made = made
        self._open = open_ports
        self._host = host
        self.settimeout_calls: list[float] = []
        self.closed_called = False

    def settimeout(self, value: float) -> None:
        self.settimeout_calls.append(value)

    def connect(self, address) -> None:
        self._made.append(address)
        _, port = address
        if port not in self._open:
            raise ConnectionRefusedError(f"refused {address}")

    def close(self) -> None:
        self.closed_called = True


@pytest.fixture
def fake_socket(monkeypatch):
    import socket as socket_module

    def install(host: str, open_ports: set[int]) -> list:
        made: list = []

        def factory(*args, **kwargs):
            return FakeSocket(made, open_ports, host)

        monkeypatch.setattr(socket_module, "socket", factory)
        return made

    return install


# ------------------------------------------------------------- the comparison
def test_both_backends_agree_on_which_ports_are_open(fake_socket):
    """The headline invariant, checked with the Go core stubbed to one answer and
    the socket probe to the same one."""
    from modules.discovery import goscan_bridge

    ports = [22, 80, 443]
    open_ports = {22, 443}

    # Go core: reports exactly the open ports.
    monkey_go = lambda *a, **k: [  # noqa: E731 - a stub, kept on one line
        {"port": p, "open": True, "state": "open", "service": None} for p in sorted(open_ports)
    ]
    original_run, original_avail, original_err = (
        goscan_bridge.run_go_scan, goscan_bridge.core_available, goscan_bridge.LAST_ERROR
    )
    goscan_bridge.run_go_scan, goscan_bridge.core_available = monkey_go, lambda: True
    goscan_bridge.LAST_ERROR = None
    try:
        from_go = accel.scan_ports("10.0.0.1", ports)
    finally:
        goscan_bridge.run_go_scan = original_run
        goscan_bridge.core_available = original_avail
        goscan_bridge.LAST_ERROR = original_err

    made = fake_socket("10.0.0.1", open_ports)
    from_python = accel.scan_ports("10.0.0.1", ports, prefer="python")

    assert from_go.engine == "go-native"
    assert from_python.engine == "python-fallback"
    assert from_go.ports == tuple(sorted(open_ports))
    assert from_go.ports == from_python.ports, (
        f"the backends disagree about which ports are open: "
        f"{from_go.ports} vs {from_python.ports}"
    )
    assert made, "the socket probe must actually have connected"


def test_the_socket_probe_never_reports_a_closed_port_as_open(fake_socket):
    fake_socket("10.0.0.1", set())
    outcome = accel.scan_ports("10.0.0.1", [22, 80], prefer="python")
    assert outcome.ports == ()
    assert outcome.rows == ()


def test_the_probe_asks_for_exactly_the_requested_ports(fake_socket):
    made = fake_socket("10.0.0.1", {22})
    accel.scan_ports("10.0.0.1", [22, 80, 443], prefer="python")
    assert sorted(port for _, port in made) == [22, 80, 443]


def test_the_caller_port_list_reaches_the_go_core_not_its_own_default():
    """The Go core defaults to its own "common" set, so an unspecified list would
    silently probe a different set of ports than the caller asked for."""
    from modules.discovery import goscan_bridge

    seen: list[str] = []

    def capture(target, port_arg="common", strict=False):
        seen.append(port_arg)
        return []

    original_run, original_avail, original_err = (
        goscan_bridge.run_go_scan, goscan_bridge.core_available, goscan_bridge.LAST_ERROR
    )
    goscan_bridge.run_go_scan, goscan_bridge.core_available = capture, lambda: True
    goscan_bridge.LAST_ERROR = None
    try:
        accel.scan_ports("10.0.0.1", [8080, 8443])
    finally:
        goscan_bridge.run_go_scan = original_run
        goscan_bridge.core_available = original_avail
        goscan_bridge.LAST_ERROR = original_err

    assert seen == ["8080,8443"], f"the Go core was asked for {seen}"


# ------------------------------------------------------------ the honest claims
def test_a_recorded_core_failure_is_not_read_as_a_clean_sweep():
    """An empty result plus a recorded failure is a failure, not "nothing open"."""
    from modules.discovery import goscan_bridge

    original_run, original_avail, original_err = (
        goscan_bridge.run_go_scan, goscan_bridge.core_available, goscan_bridge.LAST_ERROR
    )
    goscan_bridge.run_go_scan = lambda *a, **k: []
    goscan_bridge.core_available = lambda: True
    goscan_bridge.LAST_ERROR = "go core blocked by policy"
    try:
        outcome = accel.scan_ports("10.0.0.1", [22])
    finally:
        goscan_bridge.run_go_scan = original_run
        goscan_bridge.core_available = original_avail
        goscan_bridge.LAST_ERROR = original_err

    assert "go core blocked by policy" in outcome.reason, (
        "the recorded failure must reach the caller, or an empty answer is "
        "indistinguishable from a clean sweep"
    )
    assert outcome.engine == "python-fallback"


def test_a_failing_backend_records_why_it_was_skipped(fake_socket):
    from modules.discovery import goscan_bridge

    original_run, original_avail, original_err = (
        goscan_bridge.run_go_scan, goscan_bridge.core_available, goscan_bridge.LAST_ERROR
    )

    def boom(*args, **kwargs):
        raise RuntimeError("no go core")

    goscan_bridge.run_go_scan = boom
    goscan_bridge.core_available = lambda: True
    goscan_bridge.LAST_ERROR = None
    try:
        fake_socket("10.0.0.1", {22})
        outcome = accel.scan_ports("10.0.0.1", [22])
    finally:
        goscan_bridge.run_go_scan = original_run
        goscan_bridge.core_available = original_avail
        goscan_bridge.LAST_ERROR = original_err

    assert outcome.engine == "python-fallback"
    assert outcome.ports == (22,)
    assert "no go core" in outcome.reason


def test_nothing_to_probe_is_not_a_failure():
    assert accel.scan_ports("", [22]).engine == "none"
    assert accel.scan_ports("10.0.0.1", []).engine == "none"
    assert accel.scan_ports("", []).ports == ()


def test_an_unknown_backend_name_is_rejected():
    with pytest.raises(ValueError, match="unknown backend"):
        accel.scan_ports("10.0.0.1", [22], prefer="cobol")


def test_only_the_go_and_python_backends_can_probe():
    by_name = accel.backend_infos_by_name()
    assert "scan_ports" in by_name["go"].capabilities
    assert "scan_ports" in by_name["python"].capabilities
    for name in ("c", "rust"):
        assert "scan_ports" not in by_name[name].capabilities, (
            f"{name} ships no network code and must not claim the capability"
        )
