"""Tests for scope-bound asset discovery.

The rules pinned here are the ones that decide whether the loop is safe and
useful: a name never authorizes its resolved addresses, wildcards and malformed
CT entries are dropped, every request is budgeted, and a virtual host is only
claimed when its response actually differs from the address default.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import modules.registry as registry
from core.planner import PlanStep
from core.scope import ScopeEnforcer
from modules.discovery.assets import (
    decode_certificate,
    discover_assets,
    probe_http,
)
from modules.discovery.ct import fetch_ct_names, parse_ct_payload


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        host = self.headers.get("Host", "")
        if getattr(self.server, "vhost_mode", False) and "vhost.test" in host:
            status = getattr(self.server, "vhost_status", 200)
            title = getattr(self.server, "vhost_title", "Vhost App")
            server = getattr(self.server, "vhost_server", "vhost-edge")
            powered = ""
        else:
            status = getattr(self.server, "default_status", 404)
            title = getattr(self.server, "default_title", "Default")
            server = getattr(self.server, "default_server", "default-edge")
            powered = getattr(self.server, "powered", "")
        body = (
            f"<html><head><title>{title}</title></head><body>ok</body></html>"
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", server)
        if powered:
            self.send_header("X-Powered-By", powered)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture()
def make_server():
    servers: list[ThreadingHTTPServer] = []

    def factory(**attributes: object) -> int:
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        for name, value in attributes.items():
            setattr(httpd, name, value)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        servers.append(httpd)
        return int(httpd.server_address[1])

    yield factory
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# Certificate Transparency
# --------------------------------------------------------------------------- #


def test_ct_payload_keeps_valid_names_and_drops_wildcards_and_junk():
    payload = json.dumps(
        [
            {"name_value": "*.Example.test\nwww.example.test"},
            {"name_value": "WWW.example.test."},
            {"name_value": "bad name\r\nHost: evil"},
            {"name_value": "a..example.test"},
            {"name_value": "api.example.test"},
        ]
    )

    names = parse_ct_payload(payload)

    assert names == ["api.example.test", "example.test", "www.example.test"]


def test_ct_payload_tolerates_a_malformed_or_html_response():
    assert parse_ct_payload("<html>rate limited</html>") == []
    assert parse_ct_payload(b"\xff\xfe") == []
    assert parse_ct_payload("{}") == []


def test_ct_fetch_uses_the_injected_fetcher_and_encodes_the_domain():
    seen: list[str] = []

    def fetcher(url: str) -> bytes:
        seen.append(url)
        return b'[{"name_value": "api.example.test"}]'

    names = fetch_ct_names("example.test", fetcher=fetcher)

    assert names == ["api.example.test"]
    assert seen and "example.test" in seen[0]


def test_ct_fetch_returns_empty_when_the_log_fails():
    def broken(url: str) -> bytes:
        raise OSError("network down")

    assert fetch_ct_names("example.test", fetcher=broken) == []


# --------------------------------------------------------------------------- #
# Scope gating before any socket
# --------------------------------------------------------------------------- #


def test_a_name_is_not_permission_to_reach_its_addresses():
    def exploding_probe(*args: object, **kwargs: object) -> dict:
        raise AssertionError("an out-of-scope address must never be probed")

    summary = discover_assets(
        ScopeEnforcer(allowed_cidrs=["127.0.0.1/32"], allowed_domains=["example.test"]),
        ["internal.example.test"],
        resolve=lambda name: ["8.8.8.8"],
        probe=exploding_probe,
    )

    assert summary["findings"] == []
    assert summary["blocked"] == [
        {
            "host": "internal.example.test",
            "reason": "resolved-outside-scope",
            "addresses": ["8.8.8.8"],
        }
    ]


def test_an_out_of_scope_name_is_never_resolved():
    resolved: list[str] = []

    def resolve(name: str) -> list[str]:
        resolved.append(name)
        return ["127.0.0.1"]

    summary = discover_assets(
        ScopeEnforcer(allowed_cidrs=["127.0.0.1/32"]),
        ["not-authorized.test"],
        resolve=resolve,
        probe=lambda *a, **k: {"open": False},
    )

    assert resolved == []
    assert summary["blocked"][0]["reason"] == "name-outside-scope"


# --------------------------------------------------------------------------- #
# HTTP metadata and virtual hosts
# --------------------------------------------------------------------------- #


def test_http_metadata_reports_status_title_server_and_technology(make_server):
    port = make_server(default_status=200, default_title="Admin", powered="PHP/8.2")

    meta = probe_http("app.test", "127.0.0.1", port, timeout=1.0)

    assert meta["open"] is True
    assert meta["status"] == 200
    assert meta["title"] == "Admin"
    assert "default-edge" in meta["server"]
    assert "php" in meta["technologies"]


def test_a_refused_port_is_reported_as_closed_not_raised():
    meta = probe_http("app.test", "127.0.0.1", 1, timeout=0.2)

    assert meta["open"] is False
    assert "error" in meta


def test_tls_metadata_is_absent_for_plain_http(make_server):
    port = make_server(default_status=200)

    meta = probe_http("app.test", "127.0.0.1", port, timeout=1.0)

    assert "tls" not in meta


def test_certificate_decoding_degrades_to_empty_on_garbage():
    assert decode_certificate(b"not a certificate") == {}


def test_a_host_specific_response_is_recorded_as_a_vhost(make_server):
    port = make_server(
        vhost_mode=True,
        default_status=404,
        default_title="Default",
        default_server="default-edge",
    )

    summary = discover_assets(
        ScopeEnforcer(
            allowed_cidrs=["127.0.0.1/32"],
            allowed_domains=["vhost.test"],
            ports=[port],
        ),
        ["vhost.test"],
        resolve=lambda name: ["127.0.0.1"],
        web_ports=[port],
        max_requests=10,
        timeout=1.0,
    )

    assert summary["assets"] == 1
    finding = summary["findings"][0]
    assert finding["vhost"] is True
    assert finding["status"] == 200
    assert finding["title"] == "Vhost App"
    assert finding["service"] == "http"


def test_an_identical_response_is_not_labelled_a_vhost(make_server):
    port = make_server(
        vhost_mode=True,
        default_status=200,
        default_title="Same",
        default_server="default-edge",
        vhost_title="Same",
        vhost_server="default-edge",
    )

    summary = discover_assets(
        ScopeEnforcer(
            allowed_cidrs=["127.0.0.1/32"],
            allowed_domains=["vhost.test"],
            ports=[port],
        ),
        ["vhost.test"],
        resolve=lambda name: ["127.0.0.1"],
        web_ports=[port],
        max_requests=10,
        timeout=1.0,
    )

    assert summary["findings"][0].get("vhost") is not True


# --------------------------------------------------------------------------- #
# Bounded expansion
# --------------------------------------------------------------------------- #


def test_expansion_honours_the_host_and_request_budgets():
    many = json.dumps([{"name_value": f"h{i}.example.test"} for i in range(20)])

    calls: list[tuple[str, str, int]] = []

    def probe(host: str, ip: str, port: int, **kwargs: object) -> dict:
        calls.append((host, ip, port))
        return {
            "open": True,
            "scheme": "http",
            "status": 200,
            "server": "s",
            "title": "t",
        }

    summary = discover_assets(
        ScopeEnforcer(allowed_domains=["example.test"]),
        ["seed.example.test"],
        ct=True,
        fetcher=lambda url: many.encode(),
        depth=3,
        max_hosts=3,
        max_requests=5,
        web_ports=[80],
        resolve=lambda name: ["127.0.0.1"],
        probe=probe,
    )

    assert len(summary["hosts"]) <= 3
    assert summary["requests"] <= 5
    assert len(calls) <= 5


def test_depth_zero_disables_ct_expansion():
    fetched: list[str] = []

    def fetcher(url: str) -> bytes:
        fetched.append(url)
        return b'[{"name_value": "child.example.test"}]'

    summary = discover_assets(
        ScopeEnforcer(allowed_domains=["example.test"]),
        ["seed.example.test"],
        ct=True,
        fetcher=fetcher,
        depth=0,
        max_requests=5,
        web_ports=[80],
        resolve=lambda name: [],
        probe=lambda *a, **k: {"open": False},
    )

    assert fetched == []
    assert summary["hosts"] == []
    assert summary["blocked"][0]["reason"] == "unresolved"


def test_ct_children_outside_the_scope_are_blocked_not_queued():
    payload = b'[{"name_value": "ok.example.test"}, {"name_value": "other.test"}]'

    summary = discover_assets(
        ScopeEnforcer(allowed_domains=["example.test"]),
        ["seed.example.test"],
        ct=True,
        fetcher=lambda url: payload,
        depth=1,
        max_requests=5,
        web_ports=[80],
        resolve=lambda name: [],
        probe=lambda *a, **k: {"open": False},
    )

    blocked = {entry["host"]: entry["reason"] for entry in summary["blocked"]}
    assert blocked["other.test"] == "name-outside-scope"
    assert blocked["ok.example.test"] == "unresolved"


# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #


def test_asset_runner_refuses_to_run_without_a_scope():
    result = registry.asset_runner(
        PlanStep(step_id=1, module="asset", action="discover", target="app.test"), {}
    )

    assert result["assets"] == 0
    assert "scope unavailable" in result["error"]


def test_asset_runner_merges_findings_into_the_context(make_server):
    port = make_server(default_status=200, default_title="Service")

    ctx = {
        "scope": ScopeEnforcer(allowed_cidrs=["127.0.0.1/32"], ports=[port]),
        "scope_ports": [port],
    }
    step = PlanStep(
        step_id=1,
        module="asset",
        action="discover",
        target="127.0.0.1",
        params={"web_ports": [port], "max_requests": 4},
    )

    result = registry.asset_runner(step, ctx)

    assert result["module"] == "asset"
    assert result["assets"] >= 1
    assert ctx["discovered_hosts"] == ["127.0.0.1"]
    assert any(f.get("title") == "Service" for f in ctx["findings"])
