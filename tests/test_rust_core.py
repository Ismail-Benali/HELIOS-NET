"""HELIOS-NET :: tests/test_rust_core.py
Tests for the native Rust core and its ctypes bridge.

Two things are being defended here:

1. Correctness of the native library, proven from Python through the same
   boundary production uses.
2. Parity with the pure-Python reference. `engine/graph/core.py` now has two
   implementations of every graph algorithm, so a divergence between them would
   silently change results depending on whether Rust happened to be built.
"""

from __future__ import annotations

import random

import pytest

from core.rust_bridge import (
    fnv1a32_rust,
    graph_betweenness_rust,
    graph_centrality_rust,
    graph_components_rust,
    graph_shortest_path_rust,
    match_json_rust,
    match_signatures_rust,
    rust_abi_version,
    rust_available,
    rust_selftest,
    rust_version,
)
from engine.graph.core import AssetGraph

requires_core = pytest.mark.skipif(
    not rust_available(), reason="Rust core not built; run `cargo build --release`"
)

# The published FNV-1a 32-bit vector, also asserted for the C core and Python.
FNV_FOOBAR_32 = 0xBF9CF968


# ----------------------------------------------------------------- discovery


def test_library_is_found():
    assert rust_available()


@requires_core
def test_selftest_proves_the_library_executes():
    """Presence on disk is not proof of a working core."""
    assert rust_selftest() is True


@requires_core
def test_abi_version_matches_the_python_constant():
    from core.rust_bridge import ABI_VERSION

    assert rust_abi_version() == ABI_VERSION


@requires_core
def test_version_string_is_readable_and_stable():
    version = rust_version()
    assert "Rust Core" in version
    assert version == rust_version(), "version must be a static string, not a fresh alloc"


def test_version_is_sane_even_without_the_library():
    from core import rust_bridge

    original = rust_bridge._LIB
    try:
        rust_bridge._LIB = None
        assert rust_bridge.rust_version() == "unavailable"
        assert rust_bridge.rust_selftest() is False
        assert rust_bridge.match_signatures_rust("x", ["x"]) == []
        assert rust_bridge.graph_components_rust(1, []) == []
    finally:
        rust_bridge._LIB = original


# ------------------------------------------------------------------ matching


@requires_core
def test_matches_expected_signatures():
    hits = match_signatures_rust(
        "SSH-2.0-OpenSSH_9.6p1 and Server: nginx/1.24",
        ["openssh", "nginx", "mariadb"],
    )
    assert sorted(hits) == ["nginx", "openssh"]


@requires_core
def test_json_matches_report_positions():
    hits = match_json_rust("Server: nginx/1.24", ["nginx", "mariadb"])
    assert hits == [{"signature": "nginx", "position": 8}]


@requires_core
def test_matching_is_case_insensitive():
    assert match_signatures_rust("SERVER: NGINX", ["nginx"]) == ["nginx"]


@requires_core
def test_reported_label_is_verbatim_not_folded():
    """Matching folds case, but the reported signature keeps its original spelling.

    Signatures carry names such as "Microsoft-IIS"; lowercasing the label would
    lose the vendor's own casing and diverge from the C core's contract.
    """
    assert match_signatures_rust("server: nginx", ["NGINX"]) == ["NGINX"]
    assert match_signatures_rust("Microsoft-IIS/10.0", ["microsoft-iis"]) == ["microsoft-iis"]


@requires_core
def test_overlapping_patterns_all_report():
    hits = match_json_rust("ab-ab-ab", ["ab"])
    assert [h["position"] for h in hits] == [0, 3, 6]


@requires_core
def test_digest_matches_the_published_vector():
    assert fnv1a32_rust("foobar") == f"0x{FNV_FOOBAR_32:08X}"


@requires_core
def test_digest_agrees_with_the_python_fallback():
    from core.c_core_bridge import fnv1a32_py

    samples = ["", "a", "foobar", "HTTP/1.1 200 OK", "x" * 5000, "unicode: \u00e9\u00e8"]
    for sample in samples:
        if not sample:
            continue
        assert fnv1a32_rust(sample) == f"0x{fnv1a32_py(sample):08X}"


@requires_core
def test_handles_non_ascii_without_diverging():
    """ASCII-only folding must still work and must not crash on UTF-8."""
    assert match_signatures_rust("caf\u00e9 bar", ["bar"]) == ["bar"]
    assert match_signatures_rust("\u4e2d\u6587 banner", ["banner"]) == ["banner"]


@requires_core
def test_no_matches_returns_empty():
    assert match_signatures_rust("nothing relevant", ["nginx"]) == []
    assert match_json_rust("nothing relevant", ["nginx"]) == []


def test_empty_inputs_are_safe_without_the_library():
    from core import rust_bridge

    original = rust_bridge._LIB
    try:
        rust_bridge._LIB = None
        assert rust_bridge.match_signatures_rust("", ["a"]) == []
        assert rust_bridge.match_signatures_rust("a", []) == []
    finally:
        rust_bridge._LIB = original


# --------------------------------------------------------------------- graph


@requires_core
def test_components_split_islands():
    comps = graph_components_rust(6, [(0, 1), (1, 2), (3, 4)])
    assert comps == [[0, 1, 2], [3, 4], [5]]


@requires_core
def test_centrality_ranks_the_hub_first():
    ranking = graph_centrality_rust(4, [(0, 1), (0, 2), (0, 3), (1, 2)])
    assert ranking[0][0] == 0
    assert ranking[0][1] == 1.0
    assert all(0.0 <= v <= 1.0 for _, v in ranking)


@requires_core
def test_betweenness_peaks_at_the_bridge():
    values = graph_betweenness_rust(3, [(0, 1), (1, 2)])
    assert values[1] == pytest.approx(1.0)
    assert values[0] == pytest.approx(0.0)


@requires_core
def test_shortest_path_returns_hops_and_route():
    hops, path = graph_shortest_path_rust(4, [(0, 1), (1, 2)], 0, 2)
    assert hops == 2
    assert path == [0, 1, 2]


@requires_core
def test_shortest_path_reports_unreachable_as_none():
    assert graph_shortest_path_rust(4, [(0, 1), (1, 2)], 3, 0) is None


@requires_core
def test_empty_and_degenerate_graphs_are_safe():
    assert graph_components_rust(0, []) == []
    assert graph_centrality_rust(0, []) == []
    assert graph_betweenness_rust(0, []) == []
    assert graph_shortest_path_rust(0, [], 0, 0) is None
    # A lone node must not produce NaN.
    assert graph_centrality_rust(1, []) == [(0, 0.0)]


@requires_core
def test_out_of_range_edges_are_ignored_not_fatal():
    comps = graph_components_rust(3, [(0, 1), (0, 99), (0, 0)])
    assert comps == [[0, 1], [2]]


# ---------------------------------------------------- engine / native parity


def _random_graph(rng: random.Random, nodes: int, density: float) -> AssetGraph:
    g = AssetGraph()
    for i in range(nodes):
        g.add_node(f"n{i}", "host")
    for i in range(nodes):
        for j in range(i + 1, nodes):
            if rng.random() < density:
                g.add_edge(f"n{i}", f"n{j}")
    return g


@pytest.mark.parametrize("seed", [1, 7, 42, 1337, 90210])
def test_engine_agrees_with_its_python_reference(seed):
    """The Rust path and the Python fallback must produce identical output.

    This is the test that stops a graph result from depending on whether the
    native library happened to be built on the host.
    """
    from core import rust_bridge

    rng = random.Random(seed)
    graph = _random_graph(rng, nodes=18, density=0.18)

    native_available = rust_bridge._LIB is not None
    assert native_available, "parity test is only meaningful with the native core"

    assert graph.degree_centrality() == graph.degree_centrality()
    assert graph.connected_components() == graph.connected_components()
    assert graph.betweenness_centrality() == graph.betweenness_centrality()

    # Force the pure-Python branches and compare against the native results.
    original = rust_bridge.rust_available
    try:
        rust_bridge.rust_available = lambda: False
        python_centrality = graph.degree_centrality()
        python_components = graph.connected_components()
        python_betweenness = graph.betweenness_centrality()
        python_paths = [
            graph.shortest_path(a, b)
            for a in list(graph.nodes)[:6]
            for b in list(graph.nodes)[:6]
        ]
    finally:
        rust_bridge.rust_available = original

    assert graph.degree_centrality() == python_centrality
    assert graph.connected_components() == python_components
    assert graph.betweenness_centrality() == python_betweenness

    # Shortest path is a *minimum-hop route*, and several routes can tie for the
    # minimum. Each implementation is therefore free to return a different one,
    # so the contract checked here is "same cost, and a genuine chain of edges"
    # rather than "the same list".
    pairs = [
        (a, b) for a in list(graph.nodes)[:6] for b in list(graph.nodes)[:6]
    ]
    for a, b in pairs:
        native_path = graph.shortest_path(a, b)
        python_path = _reference_path(graph, a, b)
        assert (native_path is None) == (python_path is None)
        if native_path is None:
            continue
        assert len(native_path) == len(python_path), f"different hop count {a}->{b}"
        assert _is_valid_route(graph, native_path), f"invalid native route {native_path}"
        assert _is_valid_route(graph, python_path), f"invalid python route {python_path}"


def _reference_path(graph: AssetGraph, source: str, target: str) -> list[str] | None:
    """Calls the private pure-Python reference directly."""
    return graph._shortest_path_python(source, target)


def _is_valid_route(graph: AssetGraph, path: list[str]) -> bool:
    """True when `path` starts and ends correctly and every hop is a real edge."""
    if not path or path[0] not in graph.nodes or path[-1] not in graph.nodes:
        return False
    return all(b in graph.adj.get(a, ()) for a, b in zip(path, path[1:]))


def test_shortest_path_python_fallback_agrees():
    graph = AssetGraph()
    for name in ("a", "b", "c", "lonely"):
        graph.add_node(name, "host")
    graph.add_edge("a", "b")
    graph.add_edge("b", "c")

    assert graph.shortest_path("a", "c") == ["a", "b", "c"]
    assert graph.shortest_path("a", "a") == ["a"]
    assert graph.shortest_path("a", "lonely") is None
    assert graph.shortest_path("a", "missing") is None
