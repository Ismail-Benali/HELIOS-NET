"""The benchmark harness must itself be deterministic and machine-readable.

Published numbers are only useful if the harness runs everywhere, uses the same
input for each backend, and emits JSON that a release script can diff.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_bench():
    spec = importlib.util.spec_from_file_location(
        "helios_bench", ROOT / "tools" / "bench.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["helios_bench"] = module
    spec.loader.exec_module(module)
    return module


bench = _load_bench()


def test_cases_cover_every_measured_component():
    names = {case.name for case in bench.cases("auto")}
    assert names == {
        "nmap-parse",
        "match-signatures",
        "fingerprint",
        "graph-degree",
        "graph-betweenness",
        "graph-pagerank",
        "graph-weighted-path",
        "graph-articulation",
        "html-report",
    }


def test_generators_are_deterministic():
    assert bench._graph(50, 120) == bench._graph(50, 120)
    assert bench._nmap_document(2, 2) == bench._nmap_document(2, 2)
    assert bench._report_payload(5, 5) == bench._report_payload(5, 5)


def test_report_payload_is_a_valid_graph():
    payload = bench._report_payload(10, 12)
    assert len(payload["assets"]) == 10
    assert len(payload["relationships"]) == 12
    assert payload["schema_version"]


def test_json_output_is_parseable(monkeypatch, capsys):
    monkeypatch.setattr(bench, "cases", lambda backend: [])
    assert bench.main(["--json", "--repeat", "1"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["results"] == []
    assert document["host"]["python"]
    assert document["host"]["backends"]


def test_repeat_must_be_positive(capsys):
    with pytest.raises(SystemExit):
        bench.main(["--repeat", "0"])
