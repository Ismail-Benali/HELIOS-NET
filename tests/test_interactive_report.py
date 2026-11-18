"""Offline interactive report: single file, no network, no HTML injection.

The report embeds attacker-controlled asset values, so the tests care about two
things above all: markup in the graph must never become markup in the page, and
the page must not reference anything outside itself.
"""

from __future__ import annotations

import json

import pytest

import cli.main as cli
from core.reporter_interactive import generate_interactive_report

PAYLOAD = {
    "schema_version": "1.0",
    "assets": [
        {
            "id": "host:10.0.0.1",
            "type": "host",
            "value": "10.0.0.1",
            "metadata": {"owner": "lab"},
            "evidence": [{"source": "nmap"}],
        },
        {
            "id": "service:10.0.0.1:80",
            "type": "service",
            "value": "http://10.0.0.1",
            "metadata": {},
            "evidence": [],
        },
    ],
    "relationships": [
        {
            "id": "r1",
            "source": "service:10.0.0.1:80",
            "target": "host:10.0.0.1",
            "type": "runs_on",
            "metadata": {},
            "evidence": [],
        }
    ],
}


def test_report_is_self_contained_and_counts_records(tmp_path):
    destination = generate_interactive_report(PAYLOAD, tmp_path / "report.html")
    document = destination.read_text(encoding="utf-8")

    assert destination.is_file()
    assert "<h1>HELIOS-NET</h1>" in document
    assert '"host:10.0.0.1"' in document
    assert 'id="asset-rows"' in document
    assert 'id="edge-rows"' in document
    assert "fetch(" not in document
    assert "<script src" not in document
    assert "<link" not in document
    assert "Content-Security-Policy" in document
    assert "default-src 'none'" in document


def test_markup_in_asset_data_stays_data(tmp_path):
    hostile = {
        "schema_version": "1.0",
        "assets": [
            {
                "id": "</script><img src=x onerror=alert(1)>",
                "type": "host",
                "value": "<b>not bold</b>",
                "metadata": {"note": "</SCRIPT >"},
                "evidence": [],
            }
        ],
        "relationships": [],
    }

    document = generate_interactive_report(
        hostile, tmp_path / "hostile.html"
    ).read_text(encoding="utf-8")

    assert "</script><img" not in document
    assert "\\u003c/script>" in document
    embedded = (
        document.split('id="graph-data"', 1)[1].split(">", 1)[1].split("</script>")[0]
    )
    assert "<" not in embedded
    assert json.loads(embedded)["assets"][0]["value"] == "<b>not bold</b>"


def test_title_is_escaped(tmp_path):
    document = generate_interactive_report(
        PAYLOAD, tmp_path / "t.html", title="<script>alert(1)</script>"
    ).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document


def test_invalid_graphs_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="JSON object"):
        generate_interactive_report([], tmp_path / "x.html")
    with pytest.raises(ValueError, match="arrays"):
        generate_interactive_report({"assets": []}, tmp_path / "x.html")
    with pytest.raises(ValueError, match="cannot write"):
        generate_interactive_report(PAYLOAD, tmp_path)


def test_cli_report_accepts_bom_and_rejects_broken_json(tmp_path):
    graph = tmp_path / "graph.json"
    graph.write_text("\ufeff" + json.dumps(PAYLOAD), encoding="utf-8")
    output = tmp_path / "report.html"
    assert cli.main(["report", "--input", str(graph), "--output", str(output)]) == 0
    assert output.is_file()

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert cli.main(["report", "--input", str(broken)]) == 2
    assert cli.main(["report", "--input", str(tmp_path / "absent.json")]) == 2
