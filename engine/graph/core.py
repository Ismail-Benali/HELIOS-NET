"""HELIOS-NET :: engine/graph/core.py
Asset graph architecture - the "bird's eye view" that turns findings into a network.

Responsibilities:
  - Convert raw findings (ports/services/domains/hosts) into a graph:
    nodes = assets, edges = relationships (a service runs on a host,
    subdomain -> domain).
  - Centrality analysis to rank assets by importance - so the commander knows
    who deserves focus, rather than touching everything at random.
  - Stays completely network-free: it only works on data sheets.

Remarks:
  - The pattern is free of external libraries - a dictionary-based graph.
  - Backend selection is delegated to `core.accel`. This module builds the
    integer form the cores expect, maps indices back to node ids, and records
    which engine answered - it no longer decides that for itself.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any


class AssetGraph:
    """A documented graph of assets and relationships."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}  # node_id -> meta
        self.adj: dict[str, set[str]] = defaultdict(set)  # node_id -> neighboring ids
        self._edges: set[tuple[str, str]] = set()
        # Which engine answered each analysis, and why. Written by `core.accel`
        # through `_last_engine`, read by `graph_report()` and the reporter.
        self.engines: dict[str, dict[str, str]] = {}

    # -- nodes and edges ------------------------------------------------------
    def add_node(self, node_id: str, kind: str, **meta: Any) -> str:
        self.nodes[node_id] = {"id": node_id, "kind": kind, **meta}
        return node_id

    def add_edge(self, a: str, b: str, rel: str = "related") -> None:
        # ensure both endpoints exist first.
        for n in (a, b):
            self.nodes.setdefault(n, {"id": n, "kind": "asset"})
            self.adj[n]  # initialize the set.
        self.adj[a].add(b)
        self.adj[b].add(a)
        self._edges.add((a, b))

    def _neighbours(self, node_id: str) -> list[str]:
        """Neighbours of `node_id` in the canonical order every analysis uses.

        Two rules, both copied from the Rust core's `Graph::from_edges`:

          1. Self-edges are dropped (`if a >= n || b >= n || a == b { continue }`).
             `adj` is a set, so `add_edge(a, a)` makes a node its own neighbour and
             would inflate its degree against every other asset.
          2. Neighbours come back sorted by node index, because Rust sorts every
             adjacency list (`list.sort_unstable(); list.dedup();`).

        Rule 2 is what makes the two implementations agree on equal-length
        shortest paths, and it is what makes the answers reproducible: `adj` is
        a `set`, so iterating it directly returned neighbours in an order that
        depends on `PYTHONHASHSEED`. The same graph then produced a different
        killchain route on every process start.
        """
        index = self._index()
        return sorted(
            (
                nb
                for nb in self.adj.get(node_id, ())
                if nb != node_id and nb in self.nodes
            ),
            key=lambda nb: index.get(nb, len(index)),
        )

    def _index(self) -> dict[str, int]:
        """Node id -> position in insertion order, the integer form Rust uses."""
        return {nid: i for i, nid in enumerate(self.nodes)}

    # -- feeding from findings -------------------------------------------------
    def ingest(self, findings: list[dict[str, Any]]) -> int:
        """Builds the graph from raw finding sheets.

        Reads known patterns:
          - port/service on a host -> host node + service node (edge).
          - subdomain -> subdomain node + edge to the parent domain node (if any).
        Unknown patterns are safely skipped (they do not stop the build).

        Returns:
          The number of edges added.
        """
        added = 0
        for f in findings:
            mid = f.get("module")
            if mid == "discovery" and f.get("host") and f.get("service"):
                host = f"host:{f['host']}"
                svc = f"svc:{f['host']}:{f.get('port', 0)}/{f['service']}"
                self.add_node(host, "host", ip=f["host"])
                self.add_node(svc, "service", port=f.get("port"), name=f["service"])
                self.add_edge(host, svc, "runs")
                added += 1
            elif mid == "dns_enum" and f.get("subdomain"):
                sub = f"sub:{f['subdomain']}"
                self.add_node(sub, "subdomain", fqdn=f["subdomain"])
                # only if a parent domain exists within the findings (not required; leave unlinked).
                added += 1
        return added

    # -- centrality analysis ------------------------------------------------------
    def _native_graph(self) -> tuple[int, list[tuple[int, int]], dict[str, int]]:
        """Returns `(node_count, edges, index_of)`.

        Maps the string-keyed graph onto the flat integer form the cores expect.
        Backend selection no longer happens here: `core.accel` decides which
        implementation serves each operation and records why, so this method only
        has to produce the input shape.
        """
        index_of = self._index()
        # Sorted so the edge list handed to the native core does not depend on
        # `set` iteration order. Rust sorts every adjacency list it builds, so this
        # is not strictly required today - but it makes the input reproducible
        # instead of accidentally reproducible, which is what the `_neighbours`
        # ordering in the Python path depends on.
        edges: list[tuple[int, int]] = []
        for a, b in sorted(
            self._edges, key=lambda e: (index_of.get(e[0], 0), index_of.get(e[1], 0))
        ):
            ia, ib = index_of.get(a), index_of.get(b)
            if ia is not None and ib is not None and ia != ib:
                edges.append((ia, ib))
        return len(self.nodes), edges, index_of

    def _last_engine(self, operation: str, engine: str, reason: str) -> None:
        """Records which engine answered an analysis, and why it was chosen.

        Kept per operation rather than as a single "last" value: selection is per
        operation, so a host whose Rust library answers centrality but not path
        finding has genuinely scored those two analyses with different engines,
        and a report claiming one engine for the lot would be wrong.
        """
        self.engines[operation] = {"engine": engine, "reason": reason}

    def graph_report(self) -> dict[str, Any]:
        """Which engine answered each analysis, for reporting and drift checks.

        `engine` is "rust-native", "python-fallback" or "none"; `reason` explains
        any degradation, e.g. that the Rust library was blocked by host policy.
        """
        return {
            "nodes": len(self.nodes),
            "edges": len(self._edges),
            "engines": {op: dict(info) for op, info in self.engines.items()},
        }

    def degree_centrality(self) -> list[tuple[str, float]]:
        """Ranking by importance: the number of direct relations (degree) per node.

        The simplest and fastest criterion: the asset with the most links is
        usually the most important (multiple services on one host, a domain
        hosting several others).
        """
        if not self.nodes:
            return []

        from core.accel import graph_degree_centrality

        count, edges, index_of = self._native_graph()
        outcome = graph_degree_centrality(count, edges)
        self._last_engine("degree", outcome.engine, outcome.reason)
        if (
            outcome.engine != "none"
            and isinstance(outcome.value, list)
            and len(outcome.value) == count
        ):
            reverse = {i: nid for nid, i in index_of.items()}
            # Re-sort by name rather than by integer index so that ties
            # resolve identically in both implementations.
            pairs = [
                (reverse[i], round(score, 3))
                for i, score in outcome.value
                if i in reverse
            ]
            pairs.sort(key=lambda x: (-x[1], x[0]))
            return pairs

        n = len(self.nodes)
        ranked = []
        # Iterate `self.nodes`, not `self.adj`: a node added without any edge has
        # no adjacency entry at all, and iterating the adjacency map silently
        # dropped isolated assets from the ranking (and therefore from
        # `top_targets`).
        #
        # `self._neighbours` drops self-edges and sorts by node index, so this
        # matches the Rust core on a graph that contains `add_edge(a, a)`. The
        # previous `len(self.adj[nid])` counted a node as its own neighbour and
        # scored it 2.0 where the native core scored it 1.0 - the ranking, and
        # therefore `top_targets`, depended on whether the Rust library was
        # installed.
        for nid in self.nodes:
            score = len(self._neighbours(nid)) / max(1, n - 1)
            ranked.append((nid, round(score, 3)))
        ranked.sort(key=lambda x: (-x[1], x[0]))
        return ranked

    def betweenness_centrality(self) -> list[tuple[str, float]]:
        """Ranking by how much traffic a node carries between other nodes.

        Unlike degree, a node can be important without being well connected, as
        the only bridge between two otherwise separate clusters.
        """
        if not self.nodes:
            return []

        from core.accel import graph_betweenness

        count, edges, index_of = self._native_graph()
        outcome = graph_betweenness(count, edges)
        self._last_engine("betweenness", outcome.engine, outcome.reason)
        if (
            outcome.engine != "none"
            and isinstance(outcome.value, list)
            and len(outcome.value) == count
        ):
            reverse = {i: nid for nid, i in index_of.items()}
            pairs = [(reverse[i], round(v, 6)) for i, v in enumerate(outcome.value)]
            pairs.sort(key=lambda x: (-x[1], x[0]))
            return pairs

        return self._betweenness_python()

    def _betweenness_python(self) -> list[tuple[str, float]]:
        """Reference Brandes implementation, used when Rust is unavailable."""
        # Built through `_neighbours` so the neighbour order - and therefore the
        # order of the `sigma` / `delta` accumulations below - is sorted by node
        # index. Reading the `set` directly made the last floating-point digits
        # depend on `PYTHONHASHSEED`, so the same graph scored differently on
        # different runs even though it was always rounded to 6 places.
        neighbours = {nid: self._neighbours(nid) for nid in self.nodes}
        centrality = {nid: 0.0 for nid in self.nodes}
        for source in self.nodes:
            stack: list[str] = []
            preds: dict[str, list[str]] = {nid: [] for nid in self.nodes}
            sigma = {nid: 0.0 for nid in self.nodes}
            dist = {nid: -1 for nid in self.nodes}
            sigma[source] = 1.0
            dist[source] = 0
            queue: deque[str] = deque([source])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in neighbours[v]:
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        preds[w].append(v)

            delta = {nid: 0.0 for nid in self.nodes}
            while stack:
                w = stack.pop()
                for v in preds[w]:
                    if sigma[w] > 0.0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != source:
                    centrality[w] += delta[w]

        pairs = [(nid, round(value / 2.0, 6)) for nid, value in centrality.items()]
        pairs.sort(key=lambda x: (-x[1], x[0]))
        return pairs

    def top_targets(self, limit: int = 10) -> list[str]:
        """The top-ranked assets - what the campaign should focus on."""
        return [nid for nid, _ in self.degree_centrality()[:limit]]

    def connected_components(self) -> list[list[str]]:
        """Separates connected components: surfaces independent groups of assets.

        Components are returned largest first, and members are sorted so the
        result does not depend on traversal order.
        """
        if not self.nodes:
            return []

        from core.accel import graph_components

        count, edges, index_of = self._native_graph()
        outcome = graph_components(count, edges)
        self._last_engine("components", outcome.engine, outcome.reason)
        if outcome.engine != "none" and outcome.value:
            reverse = {i: nid for nid, i in index_of.items()}
            comps = [
                sorted(reverse[i] for i in group if i in reverse)
                for group in outcome.value
            ]
            # Largest first; ties broken by first member so the order does
            # not depend on which implementation produced the grouping.
            comps.sort(key=lambda c: (-len(c), c[0]))
            return comps

        seen: set[str] = set()
        # Named distinctly from the native branch's list above: that one is
        # built and returned from inside `if native:`, so reusing the name here
        # read as a redefinition rather than two separate code paths.
        python_comps: list[list[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            comp, q = [], deque([start])
            seen.add(start)
            while q:
                cur = q.popleft()
                comp.append(cur)
                for nb in self._neighbours(cur):
                    if nb not in seen:
                        seen.add(nb)
                        q.append(nb)
            python_comps.append(sorted(comp))
        python_comps.sort(key=lambda c: (-len(c), c[0]))
        return python_comps

    def shortest_path(self, source: str, target: str) -> list[str] | None:
        """The fewest-hop route between two assets, or None when disconnected."""
        if source not in self.nodes or target not in self.nodes:
            return None

        from core.accel import graph_shortest_path

        count, edges, index_of = self._native_graph()
        outcome = graph_shortest_path(count, edges, index_of[source], index_of[target])
        self._last_engine("shortest_path", outcome.engine, outcome.reason)
        if outcome.engine != "none":
            if outcome.value is None:
                return None
            _, path = outcome.value
            reverse = {i: nid for nid, i in index_of.items()}
            return [reverse[i] for i in path if i in reverse]
        return self._shortest_path_python(source, target)

    def _shortest_path_python(self, source: str, target: str) -> list[str] | None:
        """Reference breadth-first search, used when Rust is unavailable.

        `_neighbours` makes this a byte-for-byte match for the Rust core on
        equal-length routes: both discover nodes in ascending node-index order,
        so both record the same predecessor. Reading the `set` instead returned
        whichever equal-length path the hash order happened to reach first, so
        the native and fallback engines disagreed on 25 of 400 random graphs and
        the fallback disagreed with itself between runs.
        """
        if source == target:
            return [source]
        prev: dict[str, str] = {}
        seen = {source}
        queue: deque[str] = deque([source])
        while queue:
            cur = queue.popleft()
            for nb in self._neighbours(cur):
                if nb in seen:
                    continue
                seen.add(nb)
                prev[nb] = cur
                if nb == target:
                    path = [target]
                    while path[-1] != source:
                        path.append(prev[path[-1]])
                    path.reverse()
                    return path
                queue.append(nb)
        return None

    # -- export ---------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": self.nodes,
            "adjacency": {k: sorted(v) for k, v in self.adj.items()},
            "edges": sorted(self._edges),
            # Travels with the graph so an exported report can be read later
            # without knowing which libraries the producing host happened to
            # have: "ranked by the Rust core" and "ranked by the Python fallback"
            # are different facts about the same numbers.
            "engines": {op: dict(info) for op, info in self.engines.items()},
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
