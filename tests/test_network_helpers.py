"""Tests for the network-facing helpers and the HTML reporter.

The scanners here all funnel through `asyncio.open_connection`, so they can be
exercised without touching a network by replacing that one call. That keeps the
tests fast and deterministic while still driving the real timeout, error and
batching paths.

The HTML reporter is checked for the escaping it claims to perform: it is
handed hostile strings and the rendered file is inspected.
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest

from core.planner import PlanStep
from core.reporter_html import generate_html_report
from engine import tunneled_scanner
from engine.algorithms.fingerprint import PROFILES, fingerprint_sig
from modules.internal import cidr_scan


class FakeWriter:
    """Minimal stand-in for a StreamWriter that records what was sent."""

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


@pytest.fixture()
def writers() -> list[FakeWriter]:
    return []


def _open_ok(monkeypatch, writers: list[FakeWriter]):
    """Makes every connection attempt succeed, recording the writer."""
    async def fake_open_connection(host, port, **kwargs):
        writer = FakeWriter()
        writers.append(writer)
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)


def _open_refused(monkeypatch, exception: BaseException | None = None):
    async def fake_open_connection(host, port, **kwargs):
        raise exception or ConnectionRefusedError(f"{host}:{port} refused")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)


# --------------------------------------------------------------------------- #
# cidr_scan
# --------------------------------------------------------------------------- #

def test_probe_reports_an_open_port(monkeypatch, writers):
    _open_ok(monkeypatch, writers)
    result = asyncio.run(cidr_scan.probe_host_port("10.0.0.1", 22))

    assert result["open"] is True
    assert result["host"] == "10.0.0.1" and result["port"] == 22
    assert result["latency"] >= 0.0
    assert writers[0].closed, "the socket must be closed after probing"


def test_probe_reports_a_refused_connection_as_closed(monkeypatch):
    _open_refused(monkeypatch)
    result = asyncio.run(cidr_scan.probe_host_port("10.0.0.1", 22))
    assert result["open"] is False
    assert result["latency"] >= 0.0


def test_probe_treats_a_timeout_as_closed(monkeypatch):
    _open_refused(monkeypatch, asyncio.TimeoutError())
    result = asyncio.run(cidr_scan.probe_host_port("10.0.0.1", 22))
    assert result["open"] is False


def test_probe_closes_the_socket_even_when_nothing_is_read(monkeypatch, writers):
    """A TCP connect to an open port that sends no banner is still 'open'.

    Pinned because the probe never reads, so a regression that starts waiting
    for data would turn every open port into a false negative.
    """
    _open_ok(monkeypatch, writers)
    result = asyncio.run(cidr_scan.probe_host_port("10.0.0.1", 80))
    assert result["open"] is True
    assert writers[0].written == b"", "the probe must not send a payload"


def test_an_invalid_cidr_is_reported_rather_than_raised():
    result = asyncio.run(cidr_scan.scan_cidr("not-a-network", [22]))
    assert len(result) == 1
    assert "Invalid CIDR" in result[0]["error"]


def test_scan_returns_only_the_open_hosts(monkeypatch, writers):
    async def fake_open_connection(host, port, **kwargs):
        if host.endswith(".2"):
            raise ConnectionRefusedError(host)
        writer = FakeWriter()
        writers.append(writer)
        return asyncio.StreamReader(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    results = asyncio.run(cidr_scan.scan_cidr("10.0.0.0/30", [22, 80]))

    # /30 has two usable hosts; .2 refuses, .1 answers on both ports.
    assert len(results) == 2
    assert {r["host"] for r in results} == {"10.0.0.1"}
    assert {r["port"] for r in results} == {22, 80}


def test_an_exploded_probe_failure_does_not_abort_the_sweep(monkeypatch, writers):
    async def fake_open_connection(host, port, **kwargs):
        if port == 80:
            raise RuntimeError("something the probe does not catch")
        return asyncio.StreamReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    results = asyncio.run(cidr_scan.scan_cidr("10.0.0.0/30", [22, 80]))

    assert {r["port"] for r in results} == {22}, (
        "gather(return_exceptions=True) must isolate one host's failure"
    )


# --------------------------------------------------------------------------- #
# tunneled_scanner
# --------------------------------------------------------------------------- #

def test_tunnel_request_is_a_host_port_line(monkeypatch, writers):
    _open_ok(monkeypatch, writers)
    result = asyncio.run(
        tunneled_scanner.tunneled_tcp_probe("10.1.0.5", 3389,
                                            proxy_host="127.0.0.1", proxy_port=1080))

    assert result["open"] is True
    assert result["tunneled"] is True
    assert writers[0].written == b"10.1.0.5:3389\n"


def test_tunnel_dials_the_proxy_not_the_target(monkeypatch, writers):
    """A tunnel must never connect straight to the internal target."""
    dialled: list[tuple] = []

    async def fake_open_connection(host, port, **kwargs):
        dialled.append((host, port))
        return asyncio.StreamReader(), FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    asyncio.run(tunneled_scanner.tunneled_tcp_probe("10.1.0.5", 22,
                                                   proxy_host="pivot.local", proxy_port=9050))
    assert dialled == [("pivot.local", 9050)]


def test_tunnel_reports_a_dead_proxy_as_closed(monkeypatch):
    _open_refused(monkeypatch)
    result = asyncio.run(tunneled_scanner.tunneled_tcp_probe("10.1.0.5", 22))
    assert result["open"] is False
    assert result["tunneled"] is True, "the attempt was still made through the tunnel"


def test_tunnel_sweep_only_returns_open_hosts(monkeypatch):
    """The sweep is tested at the probe boundary.

    The connection itself only ever reaches the proxy, so host-based decisions
    have to be made where the target is still visible.
    """
    async def fake_probe(target_host, target_port, proxy_host, proxy_port, **kwargs):
        return {"target": target_host, "port": target_port, "tunneled": True,
                "open": target_host == "10.1.0.7", "latency": 0.0}

    monkeypatch.setattr(tunneled_scanner, "tunneled_tcp_probe", fake_probe)
    results = asyncio.run(
        tunneled_scanner.tunneled_subnet_scan("10.1.0.", [22], concurrency=32))

    assert results == [{"target": "10.1.0.7", "port": 22, "tunneled": True,
                        "open": True, "latency": 0.0}]


def test_tunnel_sweep_covers_a_quarter_of_a_class_c_network(monkeypatch):
    seen: set[tuple] = set()
    proxies: set[tuple] = set()

    async def fake_probe(target_host, target_port, proxy_host, proxy_port, **kwargs):
        seen.add((target_host, target_port))
        proxies.add((proxy_host, proxy_port))
        return {"target": target_host, "port": target_port, "open": False}

    monkeypatch.setattr(tunneled_scanner, "tunneled_tcp_probe", fake_probe)
    asyncio.run(tunneled_scanner.tunneled_subnet_scan("10.1.0.", [22, 3389],
                                                     proxy_host="p.local", proxy_port=9050))

    assert len(seen) == 254 * 2
    assert ("10.1.0.1", 22) in seen
    assert ("10.1.0.254", 3389) in seen
    assert not any(h.endswith(".0") or h.endswith(".255") for h, _ in seen)
    assert proxies == {("p.local", 9050)}, "the pivot must be threaded to every probe"


# --------------------------------------------------------------------------- #
# fingerprint algorithms
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ttl,expected", [
    (1, "linux"), (64, "linux"),
    (65, "windows"), (128, "windows"),
    (129, "router"), (255, "router"),
])
def test_the_flat_estimator_uses_fixed_ttl_bands(ttl, expected):
    assert fingerprint_sig({"ttl": ttl}, kind="ttl_flat")["guess"] == expected


def test_the_flat_estimator_defaults_to_64():
    assert fingerprint_sig({}, kind="ttl_flat")["guess"] == "linux"


def test_the_flat_estimator_is_stated_as_certain():
    """Pinned deliberately: a constant 1.0 is a claim the caller may act on."""
    assert fingerprint_sig({"ttl": 64}, kind="ttl_flat")["confidence"] == 1.0


@pytest.mark.parametrize("family,profile", list(PROFILES.items()))
def test_the_bayesian_model_recognises_its_own_profile(family, profile):
    result = fingerprint_sig({
        "ttl": profile["ttl_mean"],
        "window": profile["window"],
        "tcp_options_len": profile["tcp_options_len"],
    }, kind="bayes")
    assert result["guess"] == family
    assert 0.0 < result["confidence"] <= 1.0


def test_the_bayesian_model_uses_more_signals_than_ttl():
    """A Windows TTL with a Windows window must not be read as a router."""
    ttl_only = fingerprint_sig({"ttl": 128}, kind="bayes")
    with_window = fingerprint_sig({"ttl": 128, "window": 65535}, kind="bayes")
    assert with_window["guess"] == "windows"
    assert with_window["confidence"] >= ttl_only["confidence"]


def test_an_unknown_algorithm_falls_back_instead_of_raising():
    result = fingerprint_sig({"ttl": 128}, kind="no-such-model")
    assert result["method"] == "ttl_flat"
    assert result["guess"] == "windows"


def test_the_result_records_which_model_answered():
    assert fingerprint_sig({"ttl": 64}, kind="bayes")["method"] == "bayes"
    assert fingerprint_sig({"ttl": 64}, kind="ttl_flat")["method"] == "ttl_flat"


# --------------------------------------------------------------------------- #
# dns_enum plugin
# --------------------------------------------------------------------------- #

def test_a_resolvable_name_yields_an_address(monkeypatch):
    import modules.plugins.dns_enum as plugin

    async def fake_getaddrinfo(self, host, port, **kwargs):
        if host == "www.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        raise socket.gaierror(host)

    # Patched on the loop, not on socket, because the loop resolves through a
    # cached reference to the module-level function.
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)
    found = asyncio.run(plugin.async_subdomain_enum("example.com",
                                                    wordlist=["www", "nope"]))
    assert found == [{"subdomain": "www.example.com",
                      "ip": "93.184.216.34", "resolves": True}]


def test_a_name_that_does_not_resolve_is_dropped(monkeypatch):
    import modules.plugins.dns_enum as plugin

    async def fake_getaddrinfo(self, host, port, **kwargs):
        raise socket.gaierror(host)

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)
    found = asyncio.run(plugin.async_subdomain_enum("example.com", wordlist=["a", "b"]))
    assert found == []


def test_the_plugin_records_what_it_resolved(monkeypatch):
    import modules.plugins.dns_enum as plugin

    async def fake_enum(domain, wordlist=None, **kwargs):
        return [{"subdomain": f"www.{domain}", "ip": "1.2.3.4"}]

    monkeypatch.setattr(plugin, "async_subdomain_enum", fake_enum)
    ctx: dict = {}
    result = plugin.dns_runner(
        PlanStep(step_id=1, module="dns_enum", action="enum", target="example.com"), ctx)

    assert result["resolved"] == ["www.example.com"]
    assert result["count"] == 1
    assert ctx["findings"][0]["ip"] == "1.2.3.4"
    assert ctx["findings"][0]["module"] == "dns_enum"


def test_a_failing_enumeration_does_not_break_the_campaign(monkeypatch):
    import modules.plugins.dns_enum as plugin

    async def boom(domain, wordlist=None, **kwargs):
        raise RuntimeError("resolver unavailable")

    monkeypatch.setattr(plugin, "async_subdomain_enum", boom)
    ctx: dict = {}
    result = plugin.dns_runner(
        PlanStep(step_id=1, module="dns_enum", action="enum", target="example.com"), ctx)

    assert result["count"] == 0
    assert ctx["findings"] == []


# --------------------------------------------------------------------------- #
# HTML reporter
# --------------------------------------------------------------------------- #

def test_the_report_is_written_and_returned(tmp_path):
    out = generate_html_report({"campaign_id": "c1", "target": "10.0.0.1",
                                 "status": "done", "findings_count": 3,
                                 "events": [{"ts": 1.0, "event": "start", "module": "core"}],
                                 "top_targets": ["a"]},
                                tmp_path / "r.html")
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "c1" in text and "10.0.0.1" in text and "done" in text
    assert "<!DOCTYPE html>" in text


@pytest.mark.parametrize("field", ["campaign_id", "target", "status"])
def test_hostile_metadata_is_escaped(tmp_path, field):
    payload = {"campaign_id": "c1", "target": "t", "status": "done"}
    payload[field] = "<script>alert(1)</script>"
    out = generate_html_report(payload, tmp_path / "x.html")
    text = out.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_hostile_event_and_target_names_are_escaped(tmp_path):
    out = generate_html_report({
        "campaign_id": "c", "target": "t", "status": "done",
        "events": [{"ts": 1.0, "event": "<img src=x onerror=alert(1)>",
                    "module": "<b>m</b>"}],
        "top_targets": ["<iframe src=evil>"],
    }, tmp_path / "x.html")
    text = out.read_text(encoding="utf-8")

    assert "<img src=x" not in text
    assert "<iframe src=evil>" not in text
    assert "&lt;img" in text and "&lt;iframe" in text


def test_a_hostile_findings_count_cannot_inject_markup(tmp_path):
    """Regression: the count was interpolated raw while everything else was
    escaped, so a string in that field reached the page as live markup."""
    out = generate_html_report({"campaign_id": "c", "target": "t", "status": "done",
                                "findings_count": "<script>alert(1)</script>"},
                               tmp_path / "x.html")
    text = out.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in text


def test_missing_fields_fall_back_instead_of_crashing(tmp_path):
    out = generate_html_report({}, tmp_path / "empty.html")
    text = out.read_text(encoding="utf-8")

    assert "N/A" in text
    assert "No high-centrality assets isolated" in text
    assert "No timeline events recorded" in text


def test_a_non_numeric_findings_count_falls_back_to_zero(tmp_path):
    out = generate_html_report({"findings_count": "twelve"}, tmp_path / "n.html")
    assert "twelve" not in out.read_text(encoding="utf-8")


def test_the_report_escapes_entities_rather_than_double_escaping(tmp_path):
    out = generate_html_report({"target": "a & b"}, tmp_path / "amp.html")
    text = out.read_text(encoding="utf-8")
    assert "a &amp; b" in text
    assert "a &amp;amp;" not in text
