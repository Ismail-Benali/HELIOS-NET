"""Parity tests for directed, weighted graph analytics.

The Rust CSR implementation and the Python reference must produce the same
answer, because which one runs depends only on whether the native library is
present. These tests cover the three new questions: PageRank, weighted routing,
and articulation/bridges, including the cases where direction changes the
answer.
"""

from __future__ import annotations

import random

import pytest

from core import accel, rust_bridge
from engine.graph import analytics

requires_rust = pytest.mark.skipif(
    not rust_bridge.rust_available(), reason="rust core not built"
)

Edge = tuple[int, int, int]


def random_graph(seed: int, nodes: int = 12, edges: int = 24) -> list[Edge]:
    rng = random.Random(seed)
    rows: list[Edge] = []
    for _ in range(edges):
        source = rng.randrange(nodes)
        target = rng.randrange(nodes)
        weight = rng.randrange(1, 10)
        rows.append((source, target, weight))
    return rows


def test_duplicate_edges_keep_the_cheapest_weight() -> None:
    edges = [(0, 1, 9), (0, 1, 2)]
    assert analytics.weighted_shortest_path(2, edges, True, 0, 1) == (2, [0, 1])


def test_direction_changes_reachability() -> None:
    edges = [(0, 1, 1), (1, 2, 1)]
    assert analytics.weighted_shortest_path(3, edges, True, 0, 2) == (2, [0, 1, 2])
    assert analytics.weighted_shortest_path(3, edges, True, 2, 0) is None
    assert analytics.weighted_shortest_path(3, edges, False, 2, 0) == (2, [2, 1, 0])


def test_overflowing_route_is_unreachable() -> None:
    huge = 2**63 + 1
    assert (
        analytics.weighted_shortest_path(3, [(0, 1, huge), (1, 2, huge)], True, 0, 2)
        is None
    )


def test_pagerank_of_a_cycle_is_uniform() -> None:
    edges = [(0, 1, 1), (1, 2, 1), (2, 3, 1), (3, 0, 1)]
    values = analytics.pagerank(4, edges, directed=True)
    assert values == pytest.approx([0.25, 0.25, 0.25, 0.25])
    assert sum(values) == pytest.approx(1.0)


def test_isolated_nodes_share_the_mass() -> None:
    values = analytics.pagerank(2, [], directed=True)
    assert values == pytest.approx([0.5, 0.5])


def test_path_graph_articulation_points_and_bridges() -> None:
    edges = [(0, 1, 1), (1, 2, 1), (2, 3, 1)]
    points, bridges = analytics.articulation_and_bridges(4, edges)
    assert points == [1, 2]
    assert bridges == [(0, 1), (1, 2), (2, 3)]


def test_triangle_has_no_single_point_of_failure() -> None:
    edges = [(0, 1, 1), (1, 2, 1), (2, 0, 1)]
    assert analytics.articulation_and_bridges(3, edges) == ([], [])


def test_articulation_ignores_direction() -> None:
    edges = [(2, 1, 9), (0, 1, 3)]
    assert analytics.articulation_and_bridges(3, edges) == (
        [1],
        [(0, 1), (1, 2)],
    )


@pytest.mark.parametrize("seed", range(5))
@requires_rust
def test_pagerank_agrees_with_the_native_core(seed: int) -> None:
    edges = random_graph(seed)
    native = rust_bridge.graph_pagerank_rust(12, edges, directed=True)
    reference = analytics.pagerank(12, edges, directed=True)
    assert native == pytest.approx(reference, abs=1e-7)


@pytest.mark.parametrize("seed", range(5))
@requires_rust
def test_weighted_routes_agree_with_the_native_core(seed: int) -> None:
    edges = random_graph(seed)
    for source in range(12):
        for target in range(12):
            native = rust_bridge.graph_weighted_path_rust(
                12, edges, True, source, target
            )
            reference = analytics.weighted_shortest_path(
                12, edges, True, source, target
            )
            assert native == reference, (source, target, edges)


@pytest.mark.parametrize("seed", range(5))
@requires_rust
def test_articulation_agrees_with_the_native_core(seed: int) -> None:
    pairs = [(source, target) for source, target, _ in random_graph(seed)]
    assert rust_bridge.graph_articulation_rust(12, pairs) == (
        analytics.articulation_and_bridges(12, random_graph(seed))
    )


@requires_rust
def test_accel_prefers_the_native_core_and_reports_it() -> None:
    edges = [(0, 1, 2), (1, 2, 3)]
    outcome = accel.graph_pagerank(3, edges, directed=True, prefer="rust")
    assert outcome.engine == "rust-native"
    assert sum(outcome.value) == pytest.approx(1.0)

    route = accel.graph_weighted_shortest_path(3, edges, 0, 2, prefer="rust")
    assert route.engine == "rust-native"
    assert route.value == (5, [0, 1, 2])

    articulation = accel.graph_articulation(3, [(0, 1), (1, 2)], prefer="rust")
    assert articulation.engine == "rust-native"
    assert articulation.value == ([1], [(0, 1), (1, 2)])


def test_accel_python_fallback_matches_the_reference() -> None:
    edges = [(0, 1, 2), (1, 2, 3), (0, 2, 10)]
    outcome = accel.graph_weighted_shortest_path(3, edges, 0, 2, prefer="python")
    assert outcome.engine == "python-fallback"
    assert outcome.value == analytics.weighted_shortest_path(3, edges, True, 0, 2)

    ranked = accel.graph_pagerank(3, edges, directed=True, prefer="python")
    assert ranked.engine == "python-fallback"
    assert ranked.value == analytics.pagerank(3, edges, directed=True)


def test_bridge_is_total_without_the_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rust_bridge, "_LIB", None)
    assert rust_bridge.graph_pagerank_rust(2, [(0, 1, 1)]) == []
    assert rust_bridge.graph_weighted_path_rust(2, [(0, 1, 1)], True, 0, 1) is None
    assert rust_bridge.graph_articulation_rust(2, [(0, 1)]) == ([], [])
