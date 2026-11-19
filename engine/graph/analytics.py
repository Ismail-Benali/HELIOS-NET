"""HELIOS-NET :: engine/graph/analytics.py
Pure-Python reference for the directed, weighted graph analytics.

`rust-core/src/analytics.rs` is the native implementation; these functions let a
host without the Rust library answer the same questions and give the parity
tests something independent to compare against. The two must agree, because
whether the native core is present must never change a score or a route.

Representation rules mirror the CSR builder exactly:

* endpoints outside ``0..node_count`` and self-edges are dropped;
* duplicate ``(source, target)`` pairs keep the cheapest weight;
* an undirected graph stores both directions;
* routes break equal costs by lowest node index.

PageRank uses the same damping, iteration cap, tolerance, and dangling-node
redistribution as the native version, and every cost addition is capped at
``2**64 - 1`` so an overflowing route is unreachable on both sides.
"""

from __future__ import annotations

import heapq
from collections.abc import Sequence

Edge = tuple[int, int, int]

DAMPING = 0.85
PAGERANK_TOLERANCE = 1e-10
PAGERANK_MAX_ITERATIONS = 100
_U64_MAX = 2**64 - 1


def _rows(
    node_count: int, edges: Sequence[Edge], directed: bool
) -> list[dict[int, int]]:
    """Outgoing adjacency with the cheapest weight per unique target."""
    if node_count < 0:
        node_count = 0
    rows: list[dict[int, int]] = [{} for _ in range(node_count)]
    for source, target, weight in edges:
        if not (0 <= source < node_count and 0 <= target < node_count):
            continue
        if source == target:
            continue
        weight = max(0, int(weight))
        current = rows[source].get(target)
        if current is None or weight < current:
            rows[source][target] = weight
        if not directed:
            current = rows[target].get(source)
            if current is None or weight < current:
                rows[target][source] = weight
    return rows


def pagerank(
    node_count: int, edges: Sequence[Edge], directed: bool = False
) -> list[float]:
    """PageRank per node, summing to one, in ``[0, 1]``."""
    if node_count <= 0:
        return []
    rows = _rows(node_count, edges, directed)
    inv = 1.0 / node_count
    rank = [inv] * node_count

    for _ in range(PAGERANK_MAX_ITERATIONS):
        next_rank = [0.0] * node_count
        dangling = 0.0
        for node, targets in enumerate(rows):
            if not targets:
                dangling += rank[node]
                continue
            share = rank[node] / len(targets)
            for target in targets:
                next_rank[target] += share

        base = (1.0 - DAMPING) * inv + DAMPING * dangling * inv
        delta = 0.0
        for node, value in enumerate(next_rank):
            value = base + DAMPING * value
            next_rank[node] = value
            delta += abs(value - rank[node])
        rank = next_rank
        if delta < PAGERANK_TOLERANCE:
            break
    return rank


def weighted_shortest_path(
    node_count: int,
    edges: Sequence[Edge],
    directed: bool,
    source: int,
    goal: int,
) -> tuple[int, list[int]] | None:
    """Cheapest ``(cost, path)`` from ``source`` to ``goal``, or ``None``."""
    if not (0 <= source < node_count and 0 <= goal < node_count):
        return None
    if source == goal:
        return 0, [source]

    rows = _rows(node_count, edges, directed)
    dist: list[int] = [_U64_MAX] * node_count
    previous: list[int] = [-1] * node_count
    settled = [False] * node_count
    dist[source] = 0
    queue: list[tuple[int, int]] = [(0, source)]

    while queue:
        cost, node = heapq.heappop(queue)
        if settled[node]:
            continue
        settled[node] = True
        if node == goal:
            break
        for target, weight in rows[node].items():
            if settled[target]:
                continue
            candidate = cost + weight
            if candidate > _U64_MAX:
                continue
            if candidate < dist[target]:
                dist[target] = candidate
                previous[target] = node
                heapq.heappush(queue, (candidate, target))

    if dist[goal] == _U64_MAX:
        return None
    path = [goal]
    cursor = goal
    while cursor != source:
        parent = previous[cursor]
        if parent < 0:
            return None
        path.append(parent)
        cursor = parent
    path.reverse()
    return dist[goal], path


def articulation_and_bridges(
    node_count: int, edges: Sequence[Edge]
) -> tuple[list[int], list[tuple[int, int]]]:
    """Articulation points and bridges of the undirected view.

    Direction and weights are ignored: removing a node or an edge partitions the
    network the same way regardless of how the relationship was recorded.
    """
    if node_count <= 0:
        return [], []
    adjacency: list[set[int]] = [set() for _ in range(node_count)]
    for source, target, _weight in edges:
        if not (0 <= source < node_count and 0 <= target < node_count):
            continue
        if source == target:
            continue
        adjacency[source].add(target)
        adjacency[target].add(source)

    neighbours: list[list[int]] = [sorted(row) for row in adjacency]
    discovery = [-1] * node_count
    low = [0] * node_count
    parent = [-1] * node_count
    children = [0] * node_count
    articulation = [False] * node_count
    bridges: list[tuple[int, int]] = []
    clock = 0

    for root in range(node_count):
        if discovery[root] != -1:
            continue
        discovery[root] = low[root] = clock
        clock += 1
        stack: list[tuple[int, int]] = [(root, 0)]

        while stack:
            node, index = stack.pop()
            if index < len(neighbours[node]):
                neighbour = neighbours[node][index]
                stack.append((node, index + 1))
                if neighbour == parent[node]:
                    continue
                if discovery[neighbour] == -1:
                    parent[neighbour] = node
                    children[node] += 1
                    discovery[neighbour] = low[neighbour] = clock
                    clock += 1
                    stack.append((neighbour, 0))
                else:
                    low[node] = min(low[node], discovery[neighbour])
                continue

            ancestor = stack[-1][0] if stack else -1
            if ancestor < 0:
                continue
            low[ancestor] = min(low[ancestor], low[node])
            if low[node] > discovery[ancestor]:
                bridges.append((min(ancestor, node), max(ancestor, node)))
            if parent[ancestor] != -1 and low[node] >= discovery[ancestor]:
                articulation[ancestor] = True

        if children[root] > 1:
            articulation[root] = True

    points = [node for node, value in enumerate(articulation) if value]
    bridges.sort()
    return points, bridges
