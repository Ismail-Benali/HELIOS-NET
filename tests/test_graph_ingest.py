"""Tests for discovery-to-typed-graph ingestion."""

from typing import Any


def ingest_discovery_summary(
    summary: dict[str, Any],
    *,
    observed_at: str,
    reference: str = "",
    scope: Any | None = None,
) -> tuple[Any, int]:
    from modules.discovery.graph_ingest import ingest_discovery_summary as ingest

    return ingest(summary, observed_at=observed_at, reference=reference, scope=scope)


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
    assert relation_types == {
        "resolves_to",
        "hosts_service",
        "hosted_on",
        "redirects_to",
    }

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


def test_ingestion_adds_certificate_identity_and_certificate_for_edge():
    fingerprint = "a" * 64
    graph, skipped = ingest_discovery_summary(
        {
            "findings": [
                finding(
                    service="https",
                    tls={
                        "sha256_fingerprint": fingerprint,
                        "subject": "app.example.test",
                        "issuer": "Example Test CA",
                        "not_before": "Nov 10 00:00:00 2026 GMT",
                        "not_after": "Nov 10 00:00:00 2027 GMT",
                    },
                )
            ]
        },
        observed_at=OBSERVED_AT,
        reference="campaign:tls-01",
    )

    assert skipped == 0
    certificate = next(
        asset for asset in graph.assets.values() if asset.type.value == "certificate"
    )
    host = next(asset for asset in graph.assets.values() if asset.type.value == "host")
    assert certificate.canonical_value == f"sha256:{fingerprint}"
    assert certificate.metadata["subject"] == "app.example.test"
    edge = next(
        edge
        for edge in graph.relationships.values()
        if edge.type.value == "certificate_for"
    )
    assert edge.source == certificate.id
    assert edge.target == host.id
    assert next(iter(edge.evidence.values())).reference == "campaign:tls-01"


def test_ingestion_ignores_malformed_certificate_fingerprints():
    graph, skipped = ingest_discovery_summary(
        {"findings": [finding(tls={"sha256_fingerprint": "not-a-fingerprint"})]},
        observed_at=OBSERVED_AT,
    )

    assert skipped == 0
    assert not any(asset.type.value == "certificate" for asset in graph.assets.values())


def scoped(domains=None, cidrs=None, ports=None):
    from core.scope import ScopeEnforcer
    return ScopeEnforcer(
        allowed_domains=domains or ["example.test"],
        allowed_cidrs=cidrs or ["192.0.2.0/24", "2001:db8::/32"],
        ports=ports or [443, 8443],
    )


def test_dns_a_and_aaaa_records_are_typed_and_scope_checked():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "app.example.test", "type": "A", "value": "192.0.2.10", "ttl": 300},
            {"name": "v6.example.test", "type": "AAAA", "value": "2001:db8::10", "ttl": 120},
        ]},
        observed_at=OBSERVED_AT, scope=scoped(),
    )
    assert skipped == 0
    assert {a.canonical_value for a in graph.assets.values() if a.type.value == "ip"} == {
        "192.0.2.10", "2001:db8::10"
    }
    edges = [e for e in graph.relationships.values() if e.type.value == "resolves_to"]
    assert len(edges) == 2
    assert all(next(iter(e.evidence.values())).attributes["dns_ttl"] in {120, 300} for e in edges)


def test_dns_cname_is_a_typed_edge_and_keeps_ttl():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "www.example.test", "type": "CNAME", "value": "app.example.test", "ttl": 600}
        ]},
        observed_at=OBSERVED_AT, scope=scoped(),
    )
    assert skipped == 0
    edge = next(iter(graph.relationships.values()))
    assert edge.type.value == "cname_to"
    assert edge.metadata["ttl"] == 600


def test_dns_out_of_scope_answers_are_rejected_before_graph_ingestion():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "app.example.test", "type": "A", "value": "203.0.113.8", "ttl": 60},
            {"name": "app.example.test", "type": "CNAME", "value": "outside.invalid", "ttl": 60},
        ]},
        observed_at=OBSERVED_AT, scope=scoped(),
    )
    assert skipped == 2
    assert graph.assets == {}
    assert graph.relationships == {}


def test_dns_and_service_records_fail_closed_without_scope():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "app.example.test", "type": "A", "value": "192.0.2.10", "ttl": 60}
        ]},
        observed_at=OBSERVED_AT,
    )
    assert skipped == 1
    assert graph.assets == {}


def test_srv_records_create_discovery_and_host_service_edges():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "_https._tcp.example.test", "type": "SRV",
             "value": {"target": "app.example.test", "port": 443, "protocol": "tcp", "service": "https"},
             "ttl": 180}
        ]},
        observed_at=OBSERVED_AT, scope=scoped(),
    )
    assert skipped == 0
    assert {e.type.value for e in graph.relationships.values()} == {
        "discovers_service", "hosts_service"
    }


def test_service_observations_are_scope_and_port_checked():
    graph, skipped = ingest_discovery_summary(
        {"service_observations": [
            {"host": "app.example.test", "port": 443, "protocol": "tcp", "service": "https"},
            {"host": "outside.invalid", "port": 443, "service": "https"},
            {"host": "app.example.test", "port": 22, "service": "ssh"},
        ]},
        observed_at=OBSERVED_AT, scope=scoped(),
    )
    assert skipped == 2
    assert sum(a.type.value == "service" for a in graph.assets.values()) == 1


def test_duplicate_dns_observations_merge_identity_but_preserve_distinct_evidence():
    graph, skipped = ingest_discovery_summary(
        {"dns_records": [
            {"name": "app.example.test", "type": "A", "value": "192.0.2.10", "ttl": 300},
            {"name": "APP.EXAMPLE.TEST.", "type": "A", "value": "192.0.2.10", "ttl": 120},
        ]},
        observed_at=OBSERVED_AT, reference="campaign:dns", scope=scoped(),
    )
    assert skipped == 0
    assert len([a for a in graph.assets.values() if a.type.value == "ip"]) == 1
    edge = next(iter(graph.relationships.values()))
    assert len(edge.evidence) == 2  # distinct TTL observations retain distinct evidence
    assert edge.metadata["ttl"] == [300, 120]
