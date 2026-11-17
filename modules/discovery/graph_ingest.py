"""Convert scope-authorized discovery findings into the canonical typed graph.

This adapter performs no network operations. It only translates completed
asset-discovery observations and deliberately ignores blocked candidates.
"""

from __future__ import annotations

from datetime import UTC, datetime
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
    "dns_record_type",
    "dns_ttl",
    "dns_protocol",
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
                str(k)[:80]: str(v)[:500] for k, v in list(value.items())[:30]
            }
    return attributes


def _evidence(
    source: str,
    observed_at: str,
    reference: str,
    attributes: dict[str, Any],
) -> Any:
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
    scope: Any | None = None,
) -> tuple[Any, int]:
    """Build a typed graph from a discover_assets() summary.

    The summary's findings are treated as observations from already-authorized
    probes. The blocked list is never ingested. Invalid or incomplete findings
    are skipped and counted; no target is resolved or contacted here.
    """
    from engine.graph.model import AssetType, RelationshipType, TypedAssetGraph

    timestamp = observed_at or datetime.now(UTC).isoformat()
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
            ip_id = finding_graph.add_asset(AssetType.IP, address, evidence=evidence)
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
                host_id,
                service_id,
                RelationshipType.HOSTS_SERVICE,
                metadata={"port": port},
                evidence=evidence,
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

            tls = finding.get("tls", {})
            fingerprint = (
                tls.get("sha256_fingerprint") if isinstance(tls, dict) else None
            )
            if isinstance(fingerprint, str) and len(fingerprint) == 64:
                if all(char in "0123456789abcdef" for char in fingerprint.lower()):
                    certificate_id = finding_graph.add_asset(
                        AssetType.CERTIFICATE,
                        f"sha256:{fingerprint.lower()}",
                        metadata={
                            "subject": str(tls.get("subject", ""))[:500],
                            "issuer": str(tls.get("issuer", ""))[:500],
                            "not_before": str(tls.get("not_before", ""))[:100],
                            "not_after": str(tls.get("not_after", ""))[:100],
                        },
                        evidence=evidence,
                    )
                    finding_graph.add_relationship(
                        certificate_id,
                        host_id,
                        RelationshipType.CERTIFICATE_FOR,
                        evidence=evidence,
                    )

            redirects = finding.get("redirects", [])
            if isinstance(redirects, list):
                for redirect in redirects:
                    if not isinstance(redirect, dict):
                        continue
                    source_url = redirect.get("from")
                    target_url = redirect.get("to")
                    if not isinstance(source_url, str) or not isinstance(
                        target_url, str
                    ):
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
                        source_id,
                        target_id,
                        RelationshipType.REDIRECTS_TO,
                        metadata={"status": redirect.get("status")},
                        evidence=evidence,
                    )
        except (TypeError, ValueError):
            skipped += 1
            continue
        graph.merge(finding_graph)

    # DNS and service records are ingested only with an explicit scope object.
    # This adapter never resolves names or performs follow-up connections.
    dns_records = summary.get("dns_records", [])
    if not isinstance(dns_records, list):
        raise TypeError("summary.dns_records must be a list")
    for record in dns_records:
        if not isinstance(record, dict) or scope is None:
            skipped += 1
            continue
        owner = record.get("name") or record.get("owner")
        kind = str(record.get("type", "")).upper()
        value = record.get("value")
        ttl = record.get("ttl")
        if not isinstance(owner, str) or not scope.is_target_allowed(owner):
            skipped += 1
            continue
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0:
            skipped += 1
            continue
        try:
            evidence = _evidence(
                str(record.get("source") or "dns"),
                str(record.get("observed_at") or timestamp),
                str(record.get("reference") or reference),
                {"dns_record_type": kind, "dns_ttl": ttl},
            )
            record_graph = TypedAssetGraph()
            owner_id = record_graph.add_asset(
                AssetType.DOMAIN, owner, evidence=evidence
            )
            if kind in {"A", "AAAA"}:
                import ipaddress

                if not isinstance(value, str):
                    raise ValueError("DNS address value must be a string")
                address = ipaddress.ip_address(value)
                if (kind == "A" and address.version != 4) or (
                    kind == "AAAA" and address.version != 6
                ):
                    raise ValueError("DNS address family does not match record type")
                if not scope.is_target_allowed(str(address)):
                    raise ValueError("DNS address is outside authorized scope")
                address_id = record_graph.add_asset(
                    AssetType.IP, str(address), evidence=evidence
                )
                record_graph.add_relationship(
                    owner_id,
                    address_id,
                    RelationshipType.RESOLVES_TO,
                    metadata={"record_type": kind, "ttl": ttl},
                    evidence=evidence,
                )
            elif kind == "CNAME":
                if not isinstance(value, str) or not scope.is_target_allowed(value):
                    raise ValueError("CNAME target is outside authorized scope")
                target_id = record_graph.add_asset(
                    AssetType.DOMAIN, value, evidence=evidence
                )
                record_graph.add_relationship(
                    owner_id,
                    target_id,
                    RelationshipType.CNAME_TO,
                    metadata={"record_type": kind, "ttl": ttl},
                    evidence=evidence,
                )
            elif kind == "SRV":
                if not isinstance(value, dict):
                    raise ValueError("SRV value must be an object")
                target = value.get("target")
                port = value.get("port")
                protocol = str(value.get("protocol", "tcp")).lower()
                service_name = str(value.get("service", "unknown")).lower()
                if protocol not in {"tcp", "udp"}:
                    raise ValueError("unsupported SRV protocol")
                if not isinstance(target, str) or not scope.is_target_allowed(target):
                    raise ValueError("SRV target is outside authorized scope")
                if (
                    isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 1 <= port <= 65535
                ):
                    raise ValueError("invalid SRV port")
                scope.check_ports([port])
                service_id = record_graph.add_asset(
                    AssetType.SERVICE,
                    f"{protocol}/{port}/{service_name}",
                    metadata={
                        "protocol": protocol,
                        "port": port,
                        "name": service_name,
                        "target": target,
                    },
                    evidence=evidence,
                )
                record_graph.add_relationship(
                    owner_id,
                    service_id,
                    RelationshipType.DISCOVERS_SERVICE,
                    metadata={"record_type": kind, "ttl": ttl, "target": target},
                    evidence=evidence,
                )
                target_id = record_graph.add_asset(
                    AssetType.HOST, target, evidence=evidence
                )
                record_graph.add_relationship(
                    target_id,
                    service_id,
                    RelationshipType.HOSTS_SERVICE,
                    metadata={"port": port, "protocol": protocol},
                    evidence=evidence,
                )
            else:
                skipped += 1
                continue
        except (TypeError, ValueError):
            skipped += 1
            continue
        graph.merge(record_graph)

    service_observations = summary.get("service_observations", [])
    if not isinstance(service_observations, list):
        raise TypeError("summary.service_observations must be a list")
    for observation in service_observations:
        if not isinstance(observation, dict) or scope is None:
            skipped += 1
            continue
        host = observation.get("host")
        port = observation.get("port")
        protocol = str(observation.get("protocol", "tcp")).lower()
        service_name = observation.get("service")
        if (
            not isinstance(host, str)
            or not scope.is_target_allowed(host)
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            or protocol not in {"tcp", "udp"}
            or not isinstance(service_name, str)
            or not service_name.strip()
        ):
            skipped += 1
            continue
        try:
            scope.check_ports([port])
            evidence = _evidence(
                str(observation.get("source") or "service-discovery"),
                str(observation.get("observed_at") or timestamp),
                str(observation.get("reference") or reference),
                _observation_attributes(observation),
            )
            service_graph = TypedAssetGraph()
            host_id = service_graph.add_asset(AssetType.HOST, host, evidence=evidence)
            service_id = service_graph.add_asset(
                AssetType.SERVICE,
                f"{protocol}/{port}/{service_name.strip().lower()}",
                metadata={
                    "protocol": protocol,
                    "port": port,
                    "name": service_name.strip(),
                },
                evidence=evidence,
            )
            service_graph.add_relationship(
                host_id,
                service_id,
                RelationshipType.HOSTS_SERVICE,
                metadata={"port": port, "protocol": protocol},
                evidence=evidence,
            )
        except (TypeError, ValueError):
            skipped += 1
            continue
        graph.merge(service_graph)

    return graph, skipped
