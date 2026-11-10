"""Convert scope-authorized discovery findings into the canonical typed graph.

This adapter performs no network operations. It only translates completed
asset-discovery observations and deliberately ignores blocked candidates.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

_EVIDENCE_FIELDS = (
    "module",
    "host",
    "ip",
    "port",
    "service",
    "status",
    "server",
    "title",
    "technologies",
    "tls",
    "vhost",
    "content_type",
    "content_length",
    "security_headers",
    "security_headers_count",
    "cookies",
    "engine",
    "source",
)


def _observation_attributes(finding: dict[str, Any]) -> dict[str, Any]:
    """Keep bounded, relevant discovery facts; omit arbitrary response bodies."""
    attributes: dict[str, Any] = {}
    for key in _EVIDENCE_FIELDS:
        value = finding.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, str):
            attributes[key] = value[:1000]
        elif isinstance(value, (int, float, bool)):
            attributes[key] = value
        elif isinstance(value, list):
            attributes[key] = value[:50]
        elif isinstance(value, dict):
            # TLS/header metadata is small and structured; cap its field count.
            attributes[key] = {
                str(k)[:80]: str(v)[:500]
                for k, v in list(value.items())[:30]
            }
    return attributes


def _evidence(
    source: str,
    observed_at: str,
    reference: str,
    attributes: dict[str, Any],
) -> "Evidence":
    from engine.graph.model import Evidence

    return Evidence(
        source=source,
        observed_at=observed_at,
        reference=reference,
        attributes=attributes,
    )


def ingest_discovery_summary(
    summary: dict[str, Any],
    *,
    observed_at: str | None = None,
    reference: str = "",
) -> tuple["TypedAssetGraph", int]:
    """Build a typed graph from a discover_assets() summary.

    The summary's findings are treated as observations from already-authorized
    probes. The blocked list is never ingested. Invalid or incomplete findings
    are skipped and counted; no target is resolved or contacted here.
    """
    from engine.graph.model import AssetType, RelationshipType, TypedAssetGraph

    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    graph = TypedAssetGraph()
    skipped = 0

    findings = summary.get("findings", [])
    if not isinstance(findings, list):
        raise TypeError("summary.findings must be a list")

    for finding in findings:
        if not isinstance(finding, dict):
            skipped += 1
            continue
        host = finding.get("host")
        address = finding.get("ip")
        port = finding.get("port")
        service_name = finding.get("service")
        if not isinstance(host, str) or not isinstance(address, str):
            skipped += 1
            continue
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
        ):
            skipped += 1
            continue
        if not isinstance(service_name, str) or not service_name.strip():
            skipped += 1
            continue

        attrs = _observation_attributes(finding)
        evidence = _evidence(
            str(finding.get("source") or summary.get("source") or "discovery"),
            timestamp,
            reference,
            attrs,
        )
        finding_graph = TypedAssetGraph()
        try:
            host_id = finding_graph.add_asset(
                AssetType.HOST,
                host,
                metadata={"discovery_module": "asset"},
                evidence=evidence,
            )
            ip_id = finding_graph.add_asset(
                AssetType.IP, address, evidence=evidence
            )
            service_id = finding_graph.add_asset(
                AssetType.SERVICE,
                f"tcp/{port}/{service_name.strip().lower()}",
                metadata={"protocol": "tcp", "port": port, "name": service_name},
                evidence=evidence,
            )
            finding_graph.add_relationship(
                host_id, ip_id, RelationshipType.RESOLVES_TO, evidence=evidence
            )
            finding_graph.add_relationship(
                host_id, service_id, RelationshipType.HOSTS_SERVICE,
                metadata={"port": port}, evidence=evidence,
            )

            scheme = (
                "https"
                if service_name.lower() in {"https", "ssl", "tls"}
                or port in {443, 8443}
                else "http"
            )
            url_id = finding_graph.add_asset(
                AssetType.URL,
                f"{scheme}://{host}:{port}/",
                evidence=evidence,
            )
            finding_graph.add_relationship(
                url_id, host_id, RelationshipType.HOSTED_ON, evidence=evidence
            )

            redirects = finding.get("redirects", [])
            if isinstance(redirects, list):
                for redirect in redirects:
                    if not isinstance(redirect, dict):
                        continue
                    source_url = redirect.get("from")
                    target_url = redirect.get("to")
                    if not isinstance(source_url, str) or not isinstance(target_url, str):
                        continue
                    source_parts = urlsplit(source_url)
                    target_parts = urlsplit(target_url)
                    if (
                        source_parts.scheme not in {"http", "https"}
                        or not source_parts.hostname
                    ):
                        continue
                    if (
                        target_parts.scheme not in {"http", "https"}
                        or not target_parts.hostname
                    ):
                        continue
                    source_id = finding_graph.add_asset(
                        AssetType.URL, source_url, evidence=evidence
                    )
                    target_id = finding_graph.add_asset(
                        AssetType.URL, target_url, evidence=evidence
                    )
                    finding_graph.add_relationship(
                        source_id, target_id, RelationshipType.REDIRECTS_TO,
                        metadata={"status": redirect.get("status")},
                        evidence=evidence,
                    )
        except (TypeError, ValueError):
            skipped += 1
            continue
        graph.merge(finding_graph)

    return graph, skipped
