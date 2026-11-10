# Typed Asset Graph Contract

## Purpose and boundary

`engine.graph.model.TypedAssetGraph` is a network-free normalization layer for
observations already collected by HELIOS-NET. It does not resolve DNS, probe
hosts, follow redirects, or authorize targets. Discovery remains responsible
for enforcing the engagement scope before network activity.

The existing `engine.graph.core.AssetGraph` remains available for legacy
centrality and Rust/Python algorithm parity. The typed model is an additive
data contract; it does not silently change legacy graph payloads.

## Asset identity

An asset identity is the pair `(asset_type, canonical_value)`. Its public ID
is a deterministic SHA-256-derived identifier with a type prefix. Current
normalizers:

- Domain and host: lowercase IDNA ASCII, with a trailing dot removed.
- IP: canonical representation from Python's `ipaddress` module.
- URL: absolute HTTP(S), lowercase scheme/host, default path `/`, and fragment
  removed. Query strings remain part of identity.
- Service and certificate: trimmed lowercase opaque identifiers.

This deliberately avoids guessing that a domain and its resolved IP are the
same asset. They remain separate typed assets connected by evidence-backed
relationships.

## Typed relationships

Relationships are directed and have validated endpoint types:

| Relationship | Allowed endpoints |
| --- | --- |
| `subdomain_of` | domain → domain |
| `resolves_to` | domain/host → IP |
| `hosts_service` | host → service |
| `hosted_on` | URL → host/IP |
| `certificate_for` | certificate → domain/host |
| `redirects_to` | URL → URL |

Relationship identity is the ordered tuple `(source, type, target)`. Repeated
observations merge into the same edge rather than inflating graph counts.
Unknown relationships or invalid endpoint types are rejected.

## Provenance and conflict handling

Every `Evidence` record requires a source and an ISO-8601 timestamp with an
explicit timezone. Optional references can identify a campaign, response, or
source record. Attributes retain source-specific facts.

Evidence IDs are deterministic over their complete content. Repeated identical
evidence is stored once; distinct observations remain attached to the asset or
relationship. Conflicting metadata is preserved as a list rather than silently
overwritten.

## Merge and export

`TypedAssetGraph.merge()` merges assets by canonical identity and edges by
typed relationship identity, retaining evidence from both inputs. `to_dict()`
and `to_json()` sort assets, relationships, and evidence IDs for reproducible
exports. The export carries `schema_version: 1.0`.

## Native engine interoperability

This first increment intentionally keeps the typed domain model in Python.
The existing Rust graph API consumes integer-indexed undirected edges for
centrality and pathfinding; that API cannot represent relationship direction,
types, metadata, or provenance. Passing typed edges into it without a versioned
native contract would discard semantics. A later parity increment should define
a versioned flat projection and explicit Rust result mapping before changing
the ABI. C and Go currently do not own graph semantics and should emit
observations, not independent asset identities.

## Limitations

- IDs are stable for the same normalized type/value, not globally authoritative.
- DNS changes are represented as multiple timestamped observations on a
  domain→IP edge; the model does not infer historical validity windows.
- URL query strings are identity-bearing; fragment identifiers are not.
- Evidence attributes are caller-supplied JSON-compatible data and should not
  contain secrets or unbounded response bodies.
- The scope-bound HTTP asset discovery module is now adapted through
  `modules/discovery/graph_ingest.py`; other discovery modules still need
  dedicated adapters with explicit source contracts.
- Blocked candidates are intentionally excluded from the graph. The graph is
  not an authorization mechanism and cannot make an out-of-scope target safe.


## Discovery ingestion

`modules.discovery.assets.discover_assets()` now includes a versioned
`graph` export in its summary. The adapter in
`modules/discovery/graph_ingest.py` maps completed findings into:

- host → IP via `resolves_to`;
- host → TCP service via `hosts_service`;
- URL → host via `hosted_on`;
- redirect URL → destination URL via `redirects_to`.

Each node and edge carries source, observation timestamp, and a bounded set of
finding attributes. Arbitrary body excerpts are excluded. Invalid findings are
staged separately and skipped atomically, so a malformed record cannot leave
partial nodes or edges. The `blocked` list is never ingested.

The adapter does not perform DNS, HTTP, TLS, or socket operations. It consumes
only the already scope-checked findings emitted by asset discovery. Its
`graph_skipped` count makes incomplete input visible to callers.
