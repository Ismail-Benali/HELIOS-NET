"""Tests for discovery-to-typed-graph ingestion."""
from typing import Any


def ingest_discovery_summary(
    summary: dict[str, Any], *, observed_at: str, reference: str = ""
) -> tuple[Any, int]:
    from modules.discovery.graph_ingest import ingest_discovery_summary as ingest

    return ingest(summary, observed_at=observed_at, reference=reference)



OBSERVED_AT = "2026-11-10T20:30:00Z"


def finding(**overrides):
    result = {
        "module": "asset",
        "host": "app.example.test",
        "ip": "192.0.2.10",
        "port": 443,
        "open": True,
        "service": "https",
        "engine": "stdlib-http",
        "source": "asset-discovery",
        "status": 200,
        "title": "Example application",
        "technologies": ["nginx"],
        "redirects": [
            {
                "from": "http://app.example.test:80",
                "to": "https://app.example.test/login",
                "status": 200,
            }
        ],
    }
    result.update(overrides)
    return result


def test_ingestion_builds_assets_edges_and_provenance():
    graph, skipped = ingest_discovery_summary(
        {"source": "asset-discovery", "findings": [finding()]},
        observed_at=OBSERVED_AT,
        reference="campaign:test-01",
    )

    assert skipped == 0
    assert len(graph.assets) == 6
    relation_types = {edge.type.value for edge in graph.relationships.values()}
    assert relation_types == {"resolves_to", "hosts_service", "hosted_on", "redirects_to"}

    host = next(asset for asset in graph.assets.values() if asset.type.value == "host")
    assert host.canonical_value == "app.example.test"
    evidence = next(iter(host.evidence.values()))
    assert evidence.source == "asset-discovery"
    assert evidence.observed_at == OBSERVED_AT
    assert evidence.reference == "campaign:test-01"
    assert evidence.attributes["status"] == 200


def test_ingestion_deduplicates_same_host_and_ip_across_services():
    first = finding(port=443, service="https")
    second = finding(port=8443, service="https", title="Alternate listener")
    graph, skipped = ingest_discovery_summary(
        {"findings": [first, second]}, observed_at=OBSERVED_AT
    )

    assert skipped == 0
    assert sum(asset.type.value == "host" for asset in graph.assets.values()) == 1
    assert sum(asset.type.value == "ip" for asset in graph.assets.values()) == 1
    assert sum(asset.type.value == "service" for asset in graph.assets.values()) == 2


def test_blocked_candidates_are_never_ingested():
    graph, skipped = ingest_discovery_summary(
        {
            "blocked": [{"host": "outside.test", "reason": "name-outside-scope"}],
            "findings": [],
        },
        observed_at=OBSERVED_AT,
    )
    assert skipped == 0
    assert graph.assets == {}
    assert graph.relationships == {}


def test_malformed_findings_are_counted_and_skipped():
    graph, skipped = ingest_discovery_summary(
        {"findings": [None, {"host": "bad.example.test", "ip": "not-an-ip"}]},
        observed_at=OBSERVED_AT,
    )
    assert skipped == 2
    assert graph.assets == {}


def test_evidence_does_not_capture_arbitrary_body_fields():
    graph, _ = ingest_discovery_summary(
        {"findings": [finding(body_excerpt="must not be copied")]},
        observed_at=OBSERVED_AT,
    )
    host = next(asset for asset in graph.assets.values() if asset.type.value == "host")
    attributes = next(iter(host.evidence.values())).attributes
    assert "body_excerpt" not in attributes


def test_invalid_redirect_is_ignored_without_breaking_ingestion():
    graph, skipped = ingest_discovery_summary(
        {
            "findings": [
                finding(
                    redirects=[
                        {"from": "javascript:alert(1)", "to": "https://example.test/"}
                    ]
                )
            ]
        },
        observed_at=OBSERVED_AT,
    )
    assert skipped == 0
    assert any(asset.type.value == "host" for asset in graph.assets.values())
    assert not any(
        edge.type.value == "redirects_to" for edge in graph.relationships.values()
    )
