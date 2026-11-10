"""Tests for the versioned typed-graph projection and terminal analysis."""

from __future__ import annotations

import json

import pytest

from engine.graph.model import AssetType, Evidence, RelationshipType, TypedAssetGraph
from engine.graph.native import (
    PROJECTION_SCHEMA,
    analyze_typed_graph,
    build_projection,
    load_typed_graph,
)


@pytest.fixture
def typed_graph() -> TypedAssetGraph:
    graph = TypedAssetGraph()
    evidence = Evidence(
        source="unit-test",
        observed_at="2026-11-10T20:00:00+00:00",
        reference="fixture-1",
        attributes={"status": 200},
    )
    host = graph.add_asset(AssetType.HOST, "api.example.test", evidence=evidence)
    address = graph.add_asset(AssetType.IP, "192.0.2.10", evidence=evidence)
    service = graph.add_asset(AssetType.SERVICE, "tcp/443/https", evidence=evidence)
    graph.add_relationship(
        host, address, RelationshipType.RESOLVES_TO, evidence=evidence
    )
    graph.add_relationship(
        host, service, RelationshipType.HOSTS_SERVICE, evidence=evidence
    )
    return graph


def test_projection_is_stable_and_keeps_directed_typed_relationship_records(
    typed_graph,
):
    first = build_projection(typed_graph)
    second = build_projection(typed_graph)

    assert first == second
    assert first.schema == PROJECTION_SCHEMA
    assert len(first.node_ids) == 3
    assert len(first.edges) == 2
    assert all(row["directed"] is True for row in first.relationships)
    assert {row["type"] for row in first.relationships} == {
        "resolves_to",
        "hosts_service",
    }
    assert first.to_dict()["semantics"].startswith("undirected-topology-only")


def test_typed_graph_round_trip_preserves_evidence_and_relationships(typed_graph):
    loaded = load_typed_graph(typed_graph.to_dict())

    assert loaded.to_dict() == typed_graph.to_dict()


def test_loader_rejects_unknown_schema_and_tampered_identity(typed_graph):
    payload = typed_graph.to_dict()
    payload["schema_version"] = "99.0"
    with pytest.raises(ValueError, match="schema_version"):
        load_typed_graph(payload)

    payload = typed_graph.to_dict()
    payload["assets"][0]["value"] = "changed.example.test"
    with pytest.raises(ValueError, match="identity mismatch"):
        load_typed_graph(payload)


def test_python_projection_analysis_maps_indices_back_to_assets(typed_graph):
    host_id = next(
        asset.id
        for asset in typed_graph.assets.values()
        if asset.canonical_value == "api.example.test"
    )
    ip_id = next(
        asset.id
        for asset in typed_graph.assets.values()
        if asset.canonical_value == "192.0.2.10"
    )
    result = analyze_typed_graph(
        typed_graph,
        source_asset=host_id,
        target_asset=ip_id,
        backend="python",
    )

    assert result["summary"] == {
        "assets": 3,
        "typed_relationships": 2,
        "topology_edges": 2,
        "components": 1,
    }
    assert result["degree_centrality"][0]["id"] == host_id
    assert result["connected_components"][0]
    assert result["shortest_path"]["hops"] == 1
    assert [row["id"] for row in result["shortest_path"]["path"]] == [
        host_id,
        ip_id,
    ]
    assert all(
        item["engine"] == "python-fallback" for item in result["engines"].values()
    )


def test_shortest_path_requires_both_endpoints(typed_graph):
    with pytest.raises(ValueError, match="must be supplied together"):
        analyze_typed_graph(typed_graph, source_asset=next(iter(typed_graph.assets)))


def test_cli_graph_analyze_reads_export_and_writes_json(tmp_path, typed_graph, capsys):
    from argparse import Namespace

    from cli.main import cmd_graph

    source = tmp_path / "typed-graph.json"
    output = tmp_path / "analysis" / "result.json"
    source.write_text(json.dumps(typed_graph.to_dict()), encoding="utf-8")
    args = Namespace(
        input=str(source),
        source_asset=None,
        target_asset=None,
        backend="python",
        limit=10,
        json_output=str(output),
    )

    assert cmd_graph(args) == 0
    terminal = capsys.readouterr().out
    assert "HELIOS-NET :: TYPED ASSET GRAPH" in terminal
    assert "python-fallback" in terminal
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["summary"]["assets"] == 3


def test_cli_graph_rejects_malformed_input(tmp_path, capsys):
    from argparse import Namespace

    from cli.main import cmd_graph

    source = tmp_path / "bad.json"
    source.write_text('{"schema_version":"99.0","assets":[],"relationships":[]}')
    args = Namespace(
        input=str(source),
        source_asset=None,
        target_asset=None,
        backend="auto",
        limit=10,
        json_output=None,
    )

    assert cmd_graph(args) == 2
    assert "graph analysis failed" in capsys.readouterr().out


def test_native_and_python_projection_analytics_have_parity(typed_graph):
    from core.rust_bridge import rust_available

    if not rust_available():
        pytest.skip("native Rust core is not available in this test environment")

    native = analyze_typed_graph(typed_graph, backend="rust")
    reference = analyze_typed_graph(typed_graph, backend="python")

    for operation in (
        "degree_centrality",
        "betweenness_centrality",
        "connected_components",
    ):
        assert native[operation] == reference[operation]
        assert native["engines"][operation]["engine"] == "rust-native"
        assert reference["engines"][operation]["engine"] == "python-fallback"
