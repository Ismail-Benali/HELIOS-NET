"""Nmap XML ingest: parsing, flattening, scope filtering and JSONL output.

The importer exists so an operator can keep collecting with Nmap and still use
the graph, risk and reporting layers. These tests pin the parts that could
silently corrupt data: attribute mapping, CPE capture, state filtering, and the
refusal path when every host is outside the authorized scope.
"""

from __future__ import annotations

import json

import pytest

import cli.main as cli
from modules.ingest.nmap import NmapError, findings, parse_nmap_xml, read_nmap_xml

DOCUMENT = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1">
  <host>
    <status state="up"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/><service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="203.0.113.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/><service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture()
def scope_file(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "scope": {
                    "domains": ["localhost"],
                    "cidrs": ["127.0.0.0/24"],
                    "ports": [80, 443],
                }
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_parse_prefers_ip_address_and_keeps_service_data():
    hosts = parse_nmap_xml(DOCUMENT)
    assert [host.address for host in hosts] == ["127.0.0.1", "203.0.113.9"]
    first = hosts[0]
    assert first.hostname == "localhost"
    assert first.status == "up"
    assert [port.port for port in first.ports] == [80, 81]
    open_port = first.ports[0]
    assert open_port.protocol == "tcp"
    assert open_port.state == "open"
    assert open_port.service == "http"
    assert open_port.product == "nginx"
    assert open_port.version == "1.24.0"
    assert open_port.cpes == ("cpe:/a:nginx:nginx:1.24.0",)
    assert hosts[1].hostname == ""


def test_findings_default_to_open_ports_only():
    hosts = parse_nmap_xml(DOCUMENT)
    rows = findings(hosts, reference="scan.xml")
    assert [(row["host"], row["port"]) for row in rows] == [
        ("127.0.0.1", 80),
        ("203.0.113.9", 443),
    ]
    assert rows[0]["evidence"] == {"source": "nmap", "reference": "scan.xml"}
    assert rows[0]["cpe"] == ["cpe:/a:nginx:nginx:1.24.0"]
    assert "hostname" not in rows[1]
    assert findings(hosts, states=None) and len(findings(hosts, states=None)) == 3


def test_parse_rejects_documents_it_cannot_trust():
    with pytest.raises(NmapError, match="unexpected root"):
        parse_nmap_xml("<report><host/></report>")
    with pytest.raises(NmapError, match="not valid XML"):
        parse_nmap_xml("<nmaprun>")
    with pytest.raises(NmapError, match="no host records"):
        parse_nmap_xml("<nmaprun scanner='nmap'></nmaprun>")


def test_doctype_and_entity_declarations_are_refused():
    with pytest.raises(NmapError, match="DOCTYPE"):
        parse_nmap_xml('<!DOCTYPE nmaprun [<!ENTITY x "y">]><nmaprun/>')
    with pytest.raises(NmapError, match="DOCTYPE"):
        parse_nmap_xml("<nmaprun><!ENTITY x 'y'></nmaprun>")


def test_read_reports_missing_file(tmp_path):
    with pytest.raises(NmapError, match="cannot read"):
        read_nmap_xml(tmp_path / "absent.xml")


def test_cli_ingest_filters_scope_and_writes_jsonl(tmp_path, scope_file):
    source = tmp_path / "scan.xml"
    source.write_text(DOCUMENT, encoding="utf-8")
    destination = tmp_path / "out" / "findings.jsonl"

    code = cli.main(
        [
            "ingest",
            "--nmap",
            str(source),
            "--scope",
            scope_file,
            "--output",
            str(destination),
        ]
    )

    assert code == 0
    rows = [json.loads(line) for line in destination.read_text().splitlines()]
    assert [(row["host"], row["port"]) for row in rows] == [("127.0.0.1", 80)]
    assert all(row["source"] == "nmap" for row in rows)


def test_cli_ingest_stdout_and_closed_ports(tmp_path, capsys):
    source = tmp_path / "scan.xml"
    source.write_text(DOCUMENT, encoding="utf-8")
    scope = tmp_path / "closed.json"
    scope.write_text(
        json.dumps({"scope": {"cidrs": ["127.0.0.0/24"], "ports": [80, 81]}}),
        encoding="utf-8",
    )

    code = cli.main(
        ["ingest", "--nmap", str(source), "--scope", str(scope), "--include-closed"]
    )

    assert code == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {(row["host"], row["port"]) for row in lines} == {
        ("127.0.0.1", 80),
        ("127.0.0.1", 81),
    }


def test_cli_ingest_refuses_when_everything_is_out_of_scope(tmp_path, scope_file):
    source = tmp_path / "scan.xml"
    source.write_text(DOCUMENT, encoding="utf-8")
    scoped = tmp_path / "narrow.json"
    scoped.write_text(
        json.dumps({"scope": {"cidrs": ["192.0.2.0/24"], "ports": []}}),
        encoding="utf-8",
    )

    code = cli.main(
        [
            "ingest",
            "--nmap",
            str(source),
            "--scope",
            str(scoped),
            "--output",
            str(tmp_path / "x"),
        ]
    )

    assert code == 2


def test_cli_ingest_reports_unreadable_documents(tmp_path, scope_file):
    broken = tmp_path / "broken.xml"
    broken.write_text("<report/>", encoding="utf-8")
    assert cli.main(["ingest", "--nmap", str(broken), "--scope", scope_file]) == 2
    assert (
        cli.main(
            ["ingest", "--nmap", str(tmp_path / "absent.xml"), "--scope", scope_file]
        )
        == 2
    )
