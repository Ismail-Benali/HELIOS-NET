"""Versioned projection from the authoritative typed graph to native analytics.

The typed Python graph remains authoritative for direction, relationship types,
metadata, and evidence. Rust receives only a deterministic, undirected topology
projection for connectivity metrics; no typed semantics or provenance are
discarded from the source graph or returned report.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from engine.graph.model import Evidence, TypedAssetGraph


PROJECTION_SCHEMA = "helios.rust-graph-projection/1"


@dataclass(frozen=True)
class GraphProjection:
    schema: str
    node_ids: tuple[str, ...]
    edges: tuple[tuple[int, int], ...]
    relationships: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "nodes": [
                {"index": index, "asset_id": asset_id}
                for index, asset_id in enumerate(self.node_ids)
            ],
            "edges": [list(edge) for edge in self.edges],
            "relationships": [dict(row) for row in self.relationships],
            "semantics": (
                "undirected-topology-only; relationship direction, type and "
                "evidence remain authoritative in the typed source graph"
            ),
        }


def load_typed_graph(payload: Any) -> TypedAssetGraph:
    """Validate and load a schema-versioned TypedAssetGraph export."""
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise ValueError("unsupported or missing typed graph schema_version (expected 1.0)")
    raw_assets = payload.get("assets")
    raw_relationships = payload.get("relationships")
    if not isinstance(raw_assets, list) or not isinstance(raw_relationships, list):
        raise ValueError("graph assets and relationships must be arrays")

    graph = TypedAssetGraph()
    id_map: dict[str, str] = {}
    for row in raw_assets:
        if not isinstance(row, dict):
            raise ValueError("each asset must be an object")
        old_id = row.get("id")
        evidence_rows = row.get("evidence", [])
        metadata = row.get("metadata", {})
        if not isinstance(old_id, str) or not isinstance(evidence_rows, list):
            raise ValueError("asset id and evidence are malformed")
        if not isinstance(metadata, dict):
            raise ValueError("asset metadata must be an object")
        evidence_items = []
        for item in evidence_rows:
            if not isinstance(item, dict):
                raise ValueError("asset evidence entries must be objects")
            evidence = Evidence(
                source=item.get("source", ""),
                observed_at=item.get("observed_at", ""),
                reference=item.get("reference", ""),
                attributes=item.get("attributes", {}),
            )
            if item.get("id") != evidence.evidence_id:
                raise ValueError("asset evidence id does not match its content")
            evidence_items.append(evidence)
        if evidence_items:
            for evidence in evidence_items:
                new_id = graph.add_asset(row.get("type", ""), row.get("value", ""),
                                         metadata=metadata, evidence=evidence)
        else:
            new_id = graph.add_asset(row.get("type", ""), row.get("value", ""),
                                     metadata=metadata)
        if new_id != old_id:
            raise ValueError(f"asset identity mismatch for {old_id!r}")
        id_map[old_id] = new_id

    for row in raw_relationships:
        if not isinstance(row, dict):
            raise ValueError("each relationship must be an object")
        old_id = row.get("id")
        source_ref = row.get("source")
        target_ref = row.get("target")
        source = id_map.get(source_ref) if isinstance(source_ref, str) else None
        target = id_map.get(target_ref) if isinstance(target_ref, str) else None
        evidence_rows = row.get("evidence", [])
        metadata = row.get("metadata", {})
        if not isinstance(old_id, str) or source is None or target is None:
            raise ValueError("relationship has an unknown endpoint or missing id")
        if not isinstance(evidence_rows, list) or not isinstance(metadata, dict):
            raise ValueError("relationship evidence or metadata is malformed")
        evidence_items = []
        for item in evidence_rows:
            if not isinstance(item, dict):
                raise ValueError("relationship evidence entries must be objects")
            evidence = Evidence(
                source=item.get("source", ""),
                observed_at=item.get("observed_at", ""),
                reference=item.get("reference", ""),
                attributes=item.get("attributes", {}),
            )
            if item.get("id") != evidence.evidence_id:
                raise ValueError("relationship evidence id does not match its content")
            evidence_items.append(evidence)
        if evidence_items:
            for evidence in evidence_items:
                new_id = graph.add_relationship(
                    source, target, row.get("type", ""), metadata=metadata,
                    evidence=evidence,
                )
        else:
            new_id = graph.add_relationship(
                source, target, row.get("type", ""), metadata=metadata
            )
        if new_id != old_id:
            raise ValueError(f"relationship identity mismatch for {old_id!r}")
    return graph


def build_projection(graph: TypedAssetGraph) -> GraphProjection:
    """Create stable node indices and deduplicated undirected topology edges."""
    node_ids = tuple(sorted(graph.assets))
    indices = {asset_id: index for index, asset_id in enumerate(node_ids)}
    edge_set: set[tuple[int, int]] = set()
    relationship_rows: list[dict[str, Any]] = []
    for relationship in sorted(graph.relationships.values(), key=lambda item: item.id):
        source = indices[relationship.source]
        target = indices[relationship.target]
        relationship_rows.append({
            "relationship_id": relationship.id,
            "type": relationship.type.value,
            "source_index": source,
            "target_index": target,
            "directed": True,
        })
        if source != target:
            edge_set.add((min(source, target), max(source, target)))
    return GraphProjection(
        schema=PROJECTION_SCHEMA,
        node_ids=node_ids,
        edges=tuple(sorted(edge_set)),
        relationships=tuple(relationship_rows),
    )


def _valid_ranking(value: Any, count: int, *, bounded: bool) -> bool:
    if not isinstance(value, list) or len(value) != count:
        return False
    try:
        indices = [int(row[0]) for row in value]
        scores = [float(row[1]) for row in value]
    except (TypeError, ValueError, IndexError):
        return False
    return (
        sorted(indices) == list(range(count))
        and all(math.isfinite(score) and score >= 0 for score in scores)
        and (not bounded or all(score <= 1 for score in scores))
    )


def _validated(
    operation: str, call: Any, valid: Any, backend: str | None
) -> Any:
    """Reject malformed native results instead of presenting them as success."""
    from core.accel import GraphOutcome

    outcome = call(prefer=backend)
    if outcome.engine == "none":
        raise RuntimeError(outcome.reason or f"{operation} has no available backend")
    if valid(outcome.value):
        return outcome
    if outcome.engine == "rust-native" and backend != "rust":
        fallback = call(prefer="python")
        if fallback.engine != "none" and valid(fallback.value):
            return GraphOutcome(
                fallback.value,
                fallback.engine,
                f"Rust returned an invalid {operation} result; used Python fallback. "
                f"{fallback.reason}".strip(),
            )
    raise RuntimeError(f"{operation} returned an invalid result from {outcome.engine}")


def analyze_typed_graph(
    graph: TypedAssetGraph,
    *,
    source_asset: str | None = None,
    target_asset: str | None = None,
    backend: str | None = None,
) -> dict[str, Any]:
    """Run topology analytics and map every native index back to typed asset IDs."""
    from core import accel

    projection = build_projection(graph)
    count, edges = len(projection.node_ids), list(projection.edges)
    node_ids = projection.node_ids

    degree = _validated(
        "degree centrality",
        lambda prefer: accel.graph_degree_centrality(count, edges, prefer=prefer),
        lambda value: _valid_ranking(value, count, bounded=True),
        backend,
    )
    components = _validated(
        "connected components",
        lambda prefer: accel.graph_components(count, edges, prefer=prefer),
        lambda value: (
            isinstance(value, list)
            and all(isinstance(group, list) for group in value)
            and sorted(index for group in value for index in group) == list(range(count))
        ),
        backend,
    )
    betweenness = _validated(
        "betweenness",
        lambda prefer: accel.graph_betweenness(count, edges, prefer=prefer),
        lambda value: (
            isinstance(value, list) and len(value) == count
            and all(isinstance(score, (int, float)) and math.isfinite(score) and score >= 0
                    for score in value)
        ),
        backend,
    )

    def asset_record(asset_id: str) -> dict[str, str]:
        asset = graph.assets[asset_id]
        return {"id": asset.id, "type": asset.type.value, "value": asset.canonical_value}

    result: dict[str, Any] = {
        "schema_version": "1.0",
        "projection": projection.to_dict(),
        "summary": {
            "assets": count,
            "typed_relationships": len(graph.relationships),
            "topology_edges": len(edges),
            "components": len(components.value),
        },
        "degree_centrality": [
            {**asset_record(node_ids[index]), "score": round(float(score), 6)}
            for index, score in degree.value
        ],
        "betweenness_centrality": [
            {**asset_record(node_ids[index]), "score": round(float(score), 6)}
            for index, score in enumerate(betweenness.value)
        ],
        "connected_components": [
            [asset_record(node_ids[index]) for index in group]
            for group in components.value
        ],
        "engines": {
            "degree_centrality": {"engine": degree.engine, "reason": degree.reason},
            "betweenness_centrality": {"engine": betweenness.engine, "reason": betweenness.reason},
            "connected_components": {"engine": components.engine, "reason": components.reason},
        },
        "semantics": (
            "Connectivity metrics are computed on an undirected topology projection. "
            "They are not directed reachability, exploitability, or authorization results."
        ),
    }

    if (source_asset is None) != (target_asset is None):
        raise ValueError("source_asset and target_asset must be supplied together")
    if source_asset is not None and target_asset is not None:
        if source_asset not in graph.assets or target_asset not in graph.assets:
            raise ValueError("path endpoints must be existing typed asset IDs")
        source_index = node_ids.index(source_asset)
        target_index = node_ids.index(target_asset)
        path = _validated(
            "shortest path",
            lambda prefer: accel.graph_shortest_path(
                count, edges, source_index, target_index, prefer=prefer
            ),
            lambda value: (
                value is None or (
                    isinstance(value, tuple) and len(value) == 2
                    and isinstance(value[0], int) and isinstance(value[1], list)
                    and value[0] == len(value[1]) - 1
                    and len(value[1]) > 0
                    and value[1][0] == source_index and value[1][-1] == target_index
                    and all((min(a, b), max(a, b)) in set(edges)
                            for a, b in zip(value[1], value[1][1:]))
                )
            ),
            backend,
        )
        result["shortest_path"] = {
            "source": asset_record(source_asset),
            "target": asset_record(target_asset),
            "hops": path.value[0] if path.value is not None else None,
            "path": [asset_record(node_ids[index]) for index in path.value[1]]
            if path.value is not None else None,
            "engine": path.engine,
            "reason": path.reason,
        }
        result["engines"]["shortest_path"] = {
            "engine": path.engine, "reason": path.reason
        }
    return result
