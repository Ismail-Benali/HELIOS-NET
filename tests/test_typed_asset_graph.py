"""Tests for typed asset identity, edge validation, and provenance."""
from __future__ import annotations

import json

import pytest

from engine.graph.model import (
    AssetType,
    Evidence,
    RelationshipType,
    TypedAssetGraph,
)


def evidence(source: str = "dns", observed_at: str = "2026-11-10T12:00:00Z") -> Evidence:
    return Evidence(
        source=source,
        observed_at=observed_at,
        reference="campaign:demo",
        attributes={"record": "A"},
    )


def test_domain_identity_is_case_and_trailing_dot_insensitive() -> None:
    graph = TypedAssetGraph()
    first = graph.add_asset(AssetType.DOMAIN, "Example.COM.")
    second = graph.add_asset("domain", "example.com")
    assert first == second
    assert len(graph.assets) == 1


def test_ip_identity_uses_compressed_canonical_form() -> None:
    graph = TypedAssetGraph()
    first = graph.add_asset(AssetType.IP, "2001:0db8:0:0:0:0:0:1")
    second = graph.add_asset(AssetType.IP, "2001:db8::1")
    assert first == second


def test_same_asset_accumulates_distinct_evidence_without_duplicates() -> None:
    graph = TypedAssetGraph()
    asset_id = graph.add_asset("domain", "example.com", evidence=evidence())
    graph.add_asset("domain", "EXAMPLE.COM.", evidence=evidence())
    graph.add_asset(
        "domain",
        "example.com",
        evidence=evidence("certificate", "2026-11-10T13:00:00Z"),
    )
    assert len(graph.assets[asset_id].evidence) == 2


def test_relationship_is_directed_typed_and_deduplicated() -> None:
    graph = TypedAssetGraph()
    domain = graph.add_asset("domain", "example.com")
    address = graph.add_asset("ip", "192.0.2.10")
    first = graph.add_relationship(domain, address, RelationshipType.RESOLVES_TO)
    second = graph.add_relationship(domain, address, "resolves_to")
    assert first == second
    assert len(graph.relationships) == 1
    assert graph.relationships[first].source == domain
    assert graph.relationships[first].target == address


def test_relationship_rejects_invalid_endpoint_types() -> None:
    graph = TypedAssetGraph()
    domain = graph.add_asset("domain", "example.com")
    service = graph.add_asset("service", "tcp/443/https")
    with pytest.raises(ValueError, match="does not allow"):
        graph.add_relationship(domain, service, "resolves_to")


def test_relationship_requires_existing_endpoints() -> None:
    graph = TypedAssetGraph()
    domain = graph.add_asset("domain", "example.com")
    with pytest.raises(KeyError, match="endpoints"):
        graph.add_relationship(domain, "missing", "subdomain_of")


def test_evidence_requires_timezone_aware_iso_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone"):
        Evidence(source="dns", observed_at="2026-11-10T12:00:00")


def test_metadata_conflicts_are_preserved_not_overwritten() -> None:
    graph = TypedAssetGraph()
    asset_id = graph.add_asset("host", "app.example.com", metadata={"owner": "team-a"})
    graph.add_asset("host", "APP.EXAMPLE.COM", metadata={"owner": "team-b"})
    assert graph.assets[asset_id].metadata["owner"] == ["team-a", "team-b"]


def test_merge_preserves_provenance_and_deduplicates_identity() -> None:
    left = TypedAssetGraph()
    right = TypedAssetGraph()
    left_domain = left.add_asset("domain", "example.com", evidence=evidence())
    left_ip = left.add_asset("ip", "192.0.2.10")
    left.add_relationship(
        left_domain, left_ip, "resolves_to", evidence=evidence()
    )
    right_domain = right.add_asset(
        "domain",
        "EXAMPLE.COM.",
        evidence=evidence("certificate", "2026-11-10T13:00:00Z"),
    )
    right_ip = right.add_asset("ip", "192.0.2.10")
    right.add_relationship(right_domain, right_ip, "resolves_to")
    left.merge(right)
    assert len(left.assets) == 2
    assert len(left.relationships) == 1
    assert len(left.assets[left_domain].evidence) == 2
    assert len(left.relationships[next(iter(left.relationships))].evidence) == 1


def test_export_is_stable_and_json_serializable() -> None:
    graph = TypedAssetGraph()
    graph.add_asset("domain", "example.com", evidence=evidence())
    graph.add_asset("ip", "192.0.2.10")
    first = graph.to_json()
    second = graph.to_json()
    assert first == second
    assert json.loads(first)["schema_version"] == "1.0"


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_asset_identity_is_rejected(value: str) -> None:
    graph = TypedAssetGraph()
    with pytest.raises(ValueError, match="must not be empty"):
        graph.add_asset("domain", value)


def test_url_identity_drops_fragment_and_normalizes_authority() -> None:
    graph = TypedAssetGraph()
    first = graph.add_asset("url", "HTTPS://Example.COM:443/path#section")
    second = graph.add_asset("url", "https://example.com:443/path")
    assert first == second
