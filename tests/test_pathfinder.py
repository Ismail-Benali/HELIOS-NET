"""Oracle tests for the least-resistance path engine.

Why an oracle instead of assertions on expected values
-----------------------------------------------------
A test hardcoding "the path must be A-B-C" only proves the code still does what
it did when the test was written. An oracle test states the property
independently and checks the implementation against it. When the two disagree,
one is wrong, and working out which is the point.

The reference is Bellman-Ford relaxed to a fixpoint, a deliberately naive
algorithm sharing no code with the heap-based Dijkstra under test. Because it
uses no priority queue and no ordering assumption, it is unlikely to mirror a
bug in the implementation.

Two further checks are made by independent means:

* every reported cost must equal the sum of edge weights along the path the
  function itself returned, which holds regardless of whether that path is the
  right one and so cannot be satisfied by a merely self-consistent cost;
* when two runs are compared, the engine must never report a higher cost than
  the alternative route it was shown, which is the "least resistance" claim
  stated directly.
"""

from __future__ import annotations

import random

import pytest

from engine.graph.core import AssetGraph
from engine.killchain.pathfinder import KillChainEngine

INF = float("inf")


def _weight_of(graph: AssetGraph, destination: str) -> float:
    """The cost the engine charges for entering `destination`.

    Mirrors the model in find_attack_path() so that only the search algorithm,
    not the cost model, is under test.
    """
    meta = graph.nodes[destination]
    if meta.get("kind") != "service":
        return 1.0
    name = str(meta.get("name", "unknown")).lower()
    return KillChainEngine.SERVICE_COSTS.get(name, 2.0)


def _matrix(graph: AssetGraph) -> dict[tuple[str, str], float]:
    """Directed weight matrix over real nodes. add_edge() creates both
    endpoints, so every neighbour is guaranteed to be in graph.nodes."""
    matrix: dict[tuple[str, str], float] = {}
    for node, neighbours in graph.adj.items():
        for neighbour in neighbours:
            if neighbour in graph.nodes:
                matrix[(node, neighbour)] = _weight_of(graph, neighbour)
    return matrix


def _reference_shortest(
    matrix: dict[tuple[str, str], float], src: str, dst: str
) -> float:
    """Shortest path by relaxing every edge until nothing changes.

    No heap, no visited set, no early exit, no reliance on pop ordering. Correct
    for any non-negative weight, and structurally unlike the implementation.
    """
    nodes = {n for edge in matrix for n in edge} | {src, dst}
    dist = {n: INF for n in nodes}
    dist[src] = 0.0
    for _ in range(len(nodes) + 1):
        changed = False
        for (u, v), weight in matrix.items():
            if dist[u] != INF and dist[u] + weight < dist[v]:
                dist[v] = dist[u] + weight
                changed = True
        if not changed:
            break
    return dist[dst]


def _random_graph(rng: random.Random, size: int, density: float = 0.25) -> AssetGraph:
    graph = AssetGraph()
    ids = [f"n{i}" for i in range(size)]
    services = ["http", "ssh", "mysql", "rdp", "unknown"]
    for node_id in ids:
        kind = "service" if rng.random() < 0.5 else "host"
        graph.add_node(node_id, kind, name=rng.choice(services))
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            if rng.random() < density:
                graph.add_edge(a, b)
    return graph


def _weight_sum(graph: AssetGraph, path: list[str]) -> float:
    total = 0.0
    for previous, current in zip(path, path[1:]):
        if current not in graph.nodes:
            return INF
        total += _weight_of(graph, current)
    return total


def test_matches_independent_reference_on_random_graphs():
    """The engine's cost must equal the reference on 300 random graphs.

    A violation here is a real defect in the search, not a disagreement about
    what was intended: both sides use the same weight model, so the cost model
    cannot account for the difference.
    """
    rng = random.Random(20260928)
    compared = 0

    for _ in range(300):
        size = rng.randint(2, 9)
        graph = _random_graph(rng, size)
        ids = sorted(graph.nodes)
        entry, target = rng.sample(ids, 2)

        path, cost = KillChainEngine(graph).find_attack_path(entry, target)
        expected = _reference_shortest(_matrix(graph), entry, target)

        assert cost == pytest.approx(expected), (
            f"{entry} -> {target}: engine {cost} != reference {expected}, path {path}"
        )
        compared += 1

    assert compared == 300


def test_reported_cost_equals_the_weight_of_the_returned_path():
    """Cost must describe the path that was actually returned.

    A path and a cost can be inconsistent while each looks plausible on its own,
    which would make the reported resistance untrustworthy.
    """
    rng = random.Random(11235)
    checked = 0

    for _ in range(200):
        graph = _random_graph(rng, rng.randint(2, 10), density=0.45)
        ids = sorted(graph.nodes)
        entry, target = rng.sample(ids, 2)

        path, cost = KillChainEngine(graph).find_attack_path(entry, target)
        if not path:
            assert cost == INF
            continue

        assert path[0] == entry, path
        assert path[-1] == target, path
        assert len(set(path)) == len(path), f"path revisits a node: {path}"
        for previous, current in zip(path, path[1:]):
            assert current in graph.adj.get(previous, ()), (
                f"{previous} -> {current} is not an edge in the graph"
            )
        assert cost == pytest.approx(_weight_sum(graph, path)), path
        checked += 1

    assert checked > 100, f"only {checked} random pairs were connected"


def test_never_reports_a_higher_cost_than_the_alternative_route():
    """The 'least resistance' claim, stated directly.

    Where an explicit cheap route is known, the engine must not return an
    expensive one even if the graph also contains a longer, costly path between
    the same nodes.
    """
    graph = AssetGraph()
    graph.add_node("entry", "host", name="unknown")
    for cheap in ("c0", "c1", "c2"):
        graph.add_node(cheap, "service", name="http")  # 2.0 each
    for pricey in ("p0", "p1"):
        graph.add_node(pricey, "service", name="ssh")  # 5.0 each
    graph.add_node("target", "host", name="unknown")

    graph.add_edge("entry", "c0")
    graph.add_edge("c0", "c1")
    graph.add_edge("c1", "c2")
    graph.add_edge("c2", "target")
    # A second, connected but far more expensive route.
    graph.add_edge("entry", "p0")
    graph.add_edge("p0", "p1")
    graph.add_edge("p1", "target")

    path, cost = KillChainEngine(graph).find_attack_path("entry", "target")

    assert path == ["entry", "c0", "c1", "c2", "target"], path
    # Three http services at 2.0 plus the final host hop at 1.0.
    assert cost == pytest.approx(7.0), cost
    assert cost == pytest.approx(_weight_sum(graph, path))


def test_unreachable_and_unknown_endpoints_report_no_path():
    graph = AssetGraph()
    graph.add_node("a", "host", name="unknown")
    graph.add_node("b", "host", name="unknown")
    graph.add_edge("a", "b")
    graph.add_node("island", "host", name="unknown")

    engine = KillChainEngine(graph)
    assert engine.find_attack_path("a", "island") == ([], INF)
    assert engine.find_attack_path("a", "missing") == ([], INF)
    assert engine.find_attack_path("missing", "a") == ([], INF)


def test_service_cost_ordering_actually_drives_the_route():
    """On equal-length routes the lower-cost service must be the one used.

    Asserting on the returned path rather than on a pair of costs: the engine
    already returns the cheaper route in every arrangement, so comparing its
    output to itself would not test anything.
    """
    graph = AssetGraph()
    graph.add_node("entry", "host", name="unknown")
    graph.add_node("via_http", "service", name="http")  # 2.0
    graph.add_node("via_ssh", "service", name="ssh")  # 5.0
    graph.add_node("target", "host", name="unknown")
    graph.add_edge("entry", "via_http")
    graph.add_edge("entry", "via_ssh")
    graph.add_edge("via_http", "target")
    graph.add_edge("via_ssh", "target")

    path, cost = KillChainEngine(graph).find_attack_path("entry", "target")

    assert path == ["entry", "via_http", "target"], path
    assert cost == pytest.approx(3.0), cost
    assert cost < 1.0 + KillChainEngine.SERVICE_COSTS["ssh"]

    # Raising the cheap service above the dear one must flip the choice.
    graph.nodes["via_http"]["name"] = "ssh"
    graph.nodes["via_ssh"]["name"] = "http"
    flipped, flipped_cost = KillChainEngine(graph).find_attack_path("entry", "target")
    assert flipped == ["entry", "via_ssh", "target"], flipped
    assert flipped_cost == pytest.approx(3.0), flipped_cost


def test_single_hop_and_identity_paths():
    graph = AssetGraph()
    graph.add_node("only", "host", name="unknown")
    engine = KillChainEngine(graph)

    path, cost = engine.find_attack_path("only", "only")
    assert path == ["only"]
    assert cost == 0.0

    graph.add_node("other", "host", name="unknown")
    graph.add_edge("only", "other")
    path, cost = engine.find_attack_path("only", "other")
    assert path == ["only", "other"]
    assert cost == pytest.approx(1.0)


def test_simulate_chaining_describes_each_real_hop():
    graph = AssetGraph()
    graph.add_node("entry", "host", name="unknown")
    graph.add_node("web", "service", name="http")
    graph.add_node("db", "database", name="mysql")
    graph.add_edge("entry", "web")
    graph.add_edge("web", "db")

    engine = KillChainEngine(graph)
    path, _ = engine.find_attack_path("entry", "db")
    chain = engine.simulate_chaining(path)

    assert [step["step"] for step in chain] == [1, 2]
    assert [step["from"] for step in chain] == ["entry", "web"]
    assert [step["to"] for step in chain] == ["web", "db"]
    assert "http" in chain[0]["action"]
    assert chain[0]["tactic"] == "Reconnaissance"
    assert "data store" in chain[1]["action"]


def test_plan_is_refused_when_no_route_exists():
    graph = AssetGraph()
    graph.add_node("a", "host", name="unknown")
    graph.add_node("b", "host", name="unknown")

    plan = KillChainEngine(graph).generate_kill_chain_plan("a", "b")
    assert "No reachable path found" in plan
    assert "a" in plan and "b" in plan
