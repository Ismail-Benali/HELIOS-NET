"""HELIOS-NET :: tests/test_graph_parity.py
Regression tests for the asset-graph engine.

Every analysis in `AssetGraph` has a native (Rust) path and a pure-Python
fallback. The two must be indistinguishable, because which one runs is decided
by whether the Rust cdylib happens to be present on the machine - it must never
change an answer a report or a killchain route depends on.

These tests came out of two real defects:

  - `shortest_path` and `betweenness` iterated `self.adj`, a `set`, so the
    order of discovery - and therefore the chosen equal-length route and the
    last digits of the scores - followed `PYTHONHASHSEED`. The same graph
    produced a different answer on every process start.
  - degree counted a node as its own neighbour when the graph held a self-edge,
    because the Rust core drops `a == b` and the Python side did not.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from core import rust_bridge
from engine.graph.core import AssetGraph

ROOT = Path(__file__).resolve().parents[1]
requires_rust = pytest.mark.skipif(
    not rust_bridge.rust_available(), reason="rust core not built"
)


# ---------------------------------------------------------------- helpers
def build(nodes: list[str], edges: list[tuple[str, str]], loops: int = 0) -> AssetGraph:
    g = AssetGraph()
    for n in nodes:
        g.add_node(n, "asset")
    for a, b in edges:
        g.add_edge(a, b)
    for i in range(loops):
        node = nodes[i % len(nodes)]
        g.add_edge(node, node)
    return g


def every_result(g: AssetGraph) -> dict:
    return {
        "degree": g.degree_centrality(),
        "betweenness": g.betweenness_centrality(),
        "components": g.connected_components(),
        "top": g.top_targets(4),
        "paths": {f"{a}->{b}": g.shortest_path(a, b) for a in g.nodes for b in g.nodes},
    }


def both_ways(g: AssetGraph) -> tuple[dict, dict]:
    """Run the analyses with and without the native core."""
    native = every_result(g)
    original = rust_bridge.rust_available
    rust_bridge.rust_available = lambda: False
    try:
        fallback = every_result(g)
    finally:
        rust_bridge.rust_available = original
    return native, fallback


def random_graphs(count: int, seed: int) -> list[AssetGraph]:
    rng = random.Random(seed)
    out: list[AssetGraph] = []
    for _ in range(count):
        n = rng.randint(1, 10)
        nodes = [f"n{i:02d}" for i in range(n)]
        edges = [
            (nodes[i], nodes[j])
            for i in range(n)
            for j in range(n)
            if i != j and rng.random() < rng.choice([0.15, 0.3, 0.5])
        ]
        for _ in range(rng.randint(0, 4)):
            if edges:
                edges.append(rng.choice(edges))
        out.append(build(nodes, edges, loops=rng.randint(0, 2)))
    return out


# ------------------------------------------------------- parity with Rust
@requires_rust
def test_the_two_engines_agree_on_random_graphs():
    """The headline check: one graph set, two engines, zero differences."""
    for i, g in enumerate(random_graphs(150, seed=20240917)):
        native, fallback = both_ways(g)
        for key in native:
            assert native[key] == fallback[key], (
                f"graph #{i} disagrees on {key}\n"
                f"  native  : {native[key]}\n"
                f"  fallback: {fallback[key]}"
            )


@requires_rust
@pytest.mark.parametrize(
    "g",
    [
        build(["solo"], [], loops=1),
        build(["a", "b"], [("a", "b"), ("b", "a")], loops=1),
        build(["a", "b", "c"], [("a", "b"), ("a", "c")]),
        build(["x"], []),
        build(["a", "b", "c", "d"], [("a", "b"), ("b", "c"), ("c", "d")]),
    ],
    ids=["self-loop-solo", "self-loop-pair", "duplicate-edges", "empty", "chain"],
)
def test_the_two_engines_agree_on_edge_case_graphs(g):
    native, fallback = both_ways(g)
    assert native == fallback


# --------------------------------------------- the specific old behaviours
def test_a_self_edge_does_not_inflate_degree():
    """Regression: a node used to score 2.0 where the native core scored 1.0."""
    g = build(["a", "b"], [("a", "b"), ("b", "a")])
    g.add_edge("a", "a")
    assert g.adj["a"] == {"a", "b"}, "the raw structure still records the self-edge"
    scores = dict(g.degree_centrality())
    assert scores["a"] == 1.0, "degree must count other assets, not the node itself"
    assert scores["b"] == 1.0


def test_neighbours_are_sorted_and_skip_the_node_itself():
    g = build(["c", "a", "b"], [("c", "b"), ("c", "a")])
    g.add_edge("c", "c")
    assert g._neighbours("c") == ["a", "b"], "ascending node index, self-edge dropped"
    assert g._neighbours("a") == ["c"]


def test_an_isolated_node_still_appears_in_the_ranking():
    g = build(["a", "b", "lonely"], [("a", "b")])
    ranked = dict(g.degree_centrality())
    assert "lonely" in ranked, "an asset with no edges must not vanish from top_targets"
    assert ranked["lonely"] == 0.0


# ------------------------------------------------------- the accel interface
@requires_rust
def test_accel_reports_node_indices_and_not_ranks():
    """Regression found while wiring the graph family into `core.accel`.

    The Python fallback for `graph_degree_centrality` briefly returned each
    node's *position in the ranking* in place of its index. On the chain
    a-b-c-d that reported `a` with b's score, so `AssetGraph` then resolved the
    indices back to the wrong assets and `top_targets` led with the wrong host.
    """
    from core import accel

    outcome = accel.graph_degree_centrality(4, [(0, 1), (1, 2), (2, 3)])
    assert outcome.engine in ("rust-native", "python-fallback")

    for index, score in outcome.value:
        assert 0 <= index < 4, f"{index} is not a node index of a 4-node graph"

    scores = {index: score for index, score in outcome.value}
    # `accel` returns raw scores; rounding to 3 places is `AssetGraph`'s job.
    assert scores == {
        0: 0.333,
        1: 0.667,
        2: 0.667,
        3: 0.333,
    } or scores == pytest.approx({0: 1 / 3, 1: 2 / 3, 2: 2 / 3, 3: 1 / 3}), (
        f"chain degree scored wrong: {scores}"
    )


@requires_rust
def test_pinning_either_backend_yields_the_same_graph_answer():
    from core import accel

    count, edges = 6, [(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3), (1, 4)]

    def both(op, *extra):
        a = op(count, edges, *extra, prefer="rust").value
        b = op(count, edges, *extra, prefer="python").value
        return a, b

    native, fallback = both(accel.graph_degree_centrality)
    assert dict(native) == dict(fallback)

    native, fallback = both(accel.graph_betweenness)
    assert native == pytest.approx(fallback), f"{native} != {fallback}"

    native, fallback = both(accel.graph_components)
    assert sorted(map(sorted, native)) == sorted(map(sorted, fallback))

    for target in (0, 3, 5):
        native, fallback = both(accel.graph_shortest_path, 0, target)
        assert native == fallback, f"to {target}: {native} != {fallback}"


def test_the_c_core_is_registered_without_the_graph_capability():
    """It ships no graph code, and the table has to say so rather than omit it."""
    from core import accel

    assert "c" in accel.backend_infos_by_name()
    assert not (set(accel.GRAPH_CAPABILITIES) & accel._BACKENDS["c"]().capabilities)


def test_a_graph_call_records_which_engine_ran_it():
    g = build(["a", "b", "c"], [("a", "b"), ("b", "c")])
    g.degree_centrality()
    g.shortest_path("a", "c")
    report = g.graph_report()

    assert report["nodes"] == 3 and report["edges"] == 2
    assert set(report["engines"]) == {"degree", "shortest_path"}, (
        "each analysis records its own engine"
    )
    for operation in ("degree", "shortest_path"):
        assert report["engines"][operation]["engine"] in (
            "rust-native",
            "python-fallback",
            "none",
        ), f"{operation} reported {report['engines'][operation]}"


# ------------------------------------------------- reproducibility, for real
@pytest.mark.parametrize("seed", ["0", "1", "7", "12345", "random"])
def test_the_answers_do_not_move_with_the_hash_seed(seed):
    """The defect was invisible inside one process, so it is checked across
    processes: a fresh interpreter per seed, comparing full result dumps."""
    script = textwrap.dedent(
        f"""
        import os, random, sys
        sys.path.insert(0, {str(ROOT)!r})
        from engine.graph.core import AssetGraph

        rng = random.Random(4242)
        out = []
        for _ in range(60):
            n = rng.randint(2, 9)
            nodes = [f"n{{i:02d}}" for i in range(n)]
            edges = [
                (nodes[i], nodes[j])
                for i in range(n) for j in range(n)
                if i != j and rng.random() < 0.35
            ]
            g = AssetGraph()
            for x in nodes:
                g.add_node(x, "asset")
            for a, b in edges:
                g.add_edge(a, b)
            out.append(g._shortest_path_python(nodes[0], nodes[-1]))
            out.append(g._betweenness_python())
        print(repr(out))
        """
    )
    env = dict(os.environ, PYTHONHASHSEED=seed)
    runs = [
        subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            cwd=str(ROOT),
            check=True,
        ).stdout
        for _ in range(2)
    ]
    reference = runs[0]
    for other in runs[1:]:
        assert other == reference, (
            f"PYTHONHASHSEED={seed} changed the graph results between runs"
        )

    # And a fixed seed must reproduce the baseline computed without hashing
    # randomness, so the leak is caught even if every run is self-consistent.
    baseline = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(ROOT),
        check=True,
        env=dict(os.environ, PYTHONHASHSEED="4242"),
    ).stdout
    assert baseline == reference, (
        "the fallback engine is still sensitive to PYTHONHASHSEED"
    )
