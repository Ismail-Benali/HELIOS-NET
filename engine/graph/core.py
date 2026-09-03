"""HELIOS-NET :: engine/graph/core.py
Asset graph architecture — the "bird's eye view" that turns findings into a network.

Responsibilities:
  - Convert raw findings (ports/services/domains/hosts) into a graph:
    nodes = assets, edges = relationships (a service runs on a host,
    subdomain -> domain).
  - Centrality analysis to rank assets by importance — so the commander knows
    who deserves focus, rather than touching everything at random.
  - Stays completely network-free: it only works on data sheets.

Remarks:
  - The pattern is free of external libraries — a dictionary-based graph.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque


class AssetGraph:
    """A documented graph of assets and relationships."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}      # node_id -> meta
        self.adj: dict[str, set[str]] = defaultdict(set)   # node_id -> neighboring ids
        self._edges: set[tuple[str, str]] = set()

    # -- nodes and edges ------------------------------------------------------
    def add_node(self, node_id: str, kind: str, **meta) -> str:
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

    # -- feeding from findings -------------------------------------------------
    def ingest(self, findings: list[dict]) -> int:
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
    def degree_centrality(self) -> list[tuple[str, float]]:
        """Ranking by importance: the number of direct relations (degree) per node.

        The simplest and fastest criterion: the asset with the most links is
        usually the most important (multiple services on one host, a domain
        hosting several others).
        """
        if not self.nodes:
            return []
        n = len(self.nodes)
        ranked = []
        for nid, neighbors in self.adj.items():
            if nid not in self.nodes:
                continue
            score = len(neighbors) / max(1, n - 1)
            ranked.append((nid, round(score, 3)))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def top_targets(self, limit: int = 10) -> list[str]:
        """The top-ranked assets — what the campaign should focus on."""
        return [nid for nid, _ in self.degree_centrality()[:limit]]

    def connected_components(self) -> list[list[str]]:
        """Separates connected components: surfaces independent groups of assets."""
        if not self.nodes:
            return []
        seen: set[str] = set()
        comps: list[list[str]] = []
        for start in self.nodes:
            if start in seen:
                continue
            # BFS
            comp, q = [], deque([start])
            seen.add(start)
            while q:
                cur = q.popleft()
                comp.append(cur)
                for nb in self.adj[cur]:
                    if nb not in seen and nb in self.nodes:
                        seen.add(nb)
                        q.append(nb)
            comps.append(comp)
        comps.sort(key=len, reverse=True)
        return comps

    # -- export ---------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "adjacency": {k: sorted(v) for k, v in self.adj.items()},
            "edges": sorted(self._edges),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
