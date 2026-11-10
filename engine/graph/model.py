"""Typed, deterministic asset graph with evidence provenance.

This model is deliberately network-free. It normalizes observations already
collected by scope-bound discovery; it never resolves names or opens sockets.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class AssetType(StrEnum):
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    SERVICE = "service"
    URL = "url"
    CERTIFICATE = "certificate"


class RelationshipType(StrEnum):
    SUBDOMAIN_OF = "subdomain_of"
    RESOLVES_TO = "resolves_to"
    HOSTS_SERVICE = "hosts_service"
    HOSTED_ON = "hosted_on"
    CERTIFICATE_FOR = "certificate_for"
    REDIRECTS_TO = "redirects_to"


_RELATION_ENDPOINTS: dict[RelationshipType, tuple[tuple[AssetType, AssetType], ...]] = {
    RelationshipType.SUBDOMAIN_OF: ((AssetType.DOMAIN, AssetType.DOMAIN),),
    RelationshipType.RESOLVES_TO: (
        (AssetType.DOMAIN, AssetType.IP),
        (AssetType.HOST, AssetType.IP),
    ),
    RelationshipType.HOSTS_SERVICE: ((AssetType.HOST, AssetType.SERVICE),),
    RelationshipType.HOSTED_ON: (
        (AssetType.URL, AssetType.HOST),
        (AssetType.URL, AssetType.IP),
    ),
    RelationshipType.CERTIFICATE_FOR: (
        (AssetType.CERTIFICATE, AssetType.DOMAIN),
        (AssetType.CERTIFICATE, AssetType.HOST),
    ),
    RelationshipType.REDIRECTS_TO: ((AssetType.URL, AssetType.URL),),
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def _normalize_value(kind: AssetType, value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("asset value must not be empty")
    if kind is AssetType.IP:
        return ipaddress.ip_address(raw).compressed
    if kind in (AssetType.DOMAIN, AssetType.HOST):
        candidate = raw.rstrip(".").lower()
        try:
            return candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid internationalized host name") from exc
    if kind is AssetType.URL:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("URL assets must be absolute HTTP(S) URLs")
        host = _normalize_value(AssetType.HOST, parts.hostname)
        port = parts.port
        authority = f"[{host}]" if ":" in host else host
        if port is not None:
            authority = f"{authority}:{port}"
        path = parts.path or "/"
        return urlunsplit((parts.scheme.lower(), authority, path, parts.query, ""))
    if kind is AssetType.SERVICE:
        return raw.lower()
    if kind is AssetType.CERTIFICATE:
        return raw.strip().lower()
    return raw


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{digest}"


@dataclass(frozen=True)
class Evidence:
    """A source observation; timestamps must be explicit and timezone-aware."""

    source: str
    observed_at: str
    reference: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("evidence source must not be empty")
        try:
            parsed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if not isinstance(self.attributes, dict):
            raise TypeError("evidence attributes must be a dictionary")

    @property
    def evidence_id(self) -> str:
        payload = {
            "source": self.source.strip(),
            "observed_at": self.observed_at,
            "reference": self.reference,
            "attributes": self.attributes,
        }
        return _stable_id("ev", _canonical_json(payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "source": self.source.strip(),
            "observed_at": self.observed_at,
            "reference": self.reference,
            "attributes": self.attributes,
        }


@dataclass
class Asset:
    id: str
    type: AssetType
    canonical_value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.canonical_value,
            "metadata": self.metadata,
            "evidence": [self.evidence[key].to_dict() for key in sorted(self.evidence)],
        }


@dataclass
class Relationship:
    id: str
    source: str
    target: str
    type: RelationshipType
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Evidence] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "metadata": self.metadata,
            "evidence": [
                self.evidence[key].to_dict() for key in sorted(self.evidence)
            ],
        }


class TypedAssetGraph:
    """Identity-aware directed graph with typed edges and auditable evidence."""

    schema_version = "1.0"

    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.relationships: dict[str, Relationship] = {}

    def add_asset(
        self,
        asset_type: AssetType | str,
        value: str,
        *,
        metadata: dict[str, Any] | None = None,
        evidence: Evidence | None = None,
    ) -> str:
        kind = AssetType(asset_type)
        canonical = _normalize_value(kind, value)
        identity = f"{kind.value}:{canonical}"
        asset_id = _stable_id(kind.value, identity)
        asset = self.assets.get(asset_id)
        if asset is None:
            asset = Asset(asset_id, kind, canonical)
            self.assets[asset_id] = asset
        elif asset.type is not kind or asset.canonical_value != canonical:
            raise ValueError("asset identity hash collision")
        if metadata:
            for key, item in metadata.items():
                if key not in asset.metadata:
                    asset.metadata[key] = item
                elif asset.metadata[key] != item:
                    # Preserve conflicting observations rather than overwrite.
                    existing = asset.metadata[key]
                    values = existing if isinstance(existing, list) else [existing]
                    if item not in values:
                        asset.metadata[key] = [*values, item]
        if evidence is not None:
            asset.evidence[evidence.evidence_id] = evidence
        return asset_id

    def add_relationship(
        self,
        source: str,
        target: str,
        relationship_type: RelationshipType | str,
        *,
        metadata: dict[str, Any] | None = None,
        evidence: Evidence | None = None,
    ) -> str:
        if source not in self.assets or target not in self.assets:
            raise KeyError("relationship endpoints must exist before the edge is added")
        rel_type = RelationshipType(relationship_type)
        endpoint_types = (self.assets[source].type, self.assets[target].type)
        if endpoint_types not in _RELATION_ENDPOINTS[rel_type]:
            expected = ", ".join(
                f"{left.value}->{right.value}"
                for left, right in _RELATION_ENDPOINTS[rel_type]
            )
            raise ValueError(
                f"{rel_type.value} does not allow {endpoint_types[0].value}->"
                f"{endpoint_types[1].value}; expected {expected}"
            )
        identity = f"{source}|{rel_type.value}|{target}"
        relationship_id = _stable_id("rel", identity)
        relationship = self.relationships.get(relationship_id)
        if relationship is None:
            relationship = Relationship(relationship_id, source, target, rel_type)
            self.relationships[relationship_id] = relationship
        if metadata:
            for key, item in metadata.items():
                if key not in relationship.metadata:
                    relationship.metadata[key] = item
                elif relationship.metadata[key] != item:
                    existing = relationship.metadata[key]
                    values = existing if isinstance(existing, list) else [existing]
                    if item not in values:
                        relationship.metadata[key] = [*values, item]
        if evidence is not None:
            relationship.evidence[evidence.evidence_id] = evidence
        return relationship_id

    def merge(self, other: TypedAssetGraph) -> None:
        """Merge another graph without losing duplicate-asset evidence."""
        for asset in other.assets.values():
            for evidence in asset.evidence.values():
                self.add_asset(
                    asset.type,
                    asset.canonical_value,
                    metadata=asset.metadata,
                    evidence=evidence,
                )
            if not asset.evidence:
                self.add_asset(
                    asset.type, asset.canonical_value, metadata=asset.metadata
                )
        for relationship in other.relationships.values():
            for evidence in relationship.evidence.values():
                self.add_relationship(
                    relationship.source,
                    relationship.target,
                    relationship.type,
                    metadata=relationship.metadata,
                    evidence=evidence,
                )
            if not relationship.evidence:
                self.add_relationship(
                    relationship.source,
                    relationship.target,
                    relationship.type,
                    metadata=relationship.metadata,
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "assets": [self.assets[key].to_dict() for key in sorted(self.assets)],
            "relationships": [
                self.relationships[key].to_dict() for key in sorted(self.relationships)
            ],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent
        )
