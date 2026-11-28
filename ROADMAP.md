# HELIOS-NET :: Engineering Roadmap

This roadmap prioritizes correctness, authorization, and interoperability
before operator-facing features. Work is ordered by dependency, not by
visibility.

## P0 — Engineering foundation

| Priority | Work | State | Completion evidence |
|---|---|---|---|
| P0 | Unify architecture and documentation | **Done** | README, Architecture, API, and contributor guidance aligned with the current Python / Go / C / Rust boundaries; obsolete process descriptions and empty-result fallback guidance corrected (PR #68) |
| P0 | Review scope enforcement | **Done — enforced runners** | Asset discovery enforces requested ports internally; redirects validate scheme, authority, host, address, and destination port before follow-up; denied/malformed cases have regression tests (PR #68). This does not certify arbitrary plugins or direct socket code outside enforced runners. |
| P0 | Stabilize IPC and NDJSON contracts | **Done for validated contracts** | Go persistent-worker responses require valid summaries and request correlation; missing/invalid replies fail closed. Existing UTF-8 framing, SEE, timeout, and fallback contracts remain documented and CI-tested (PR #68) |

**Exit gate: PASSED — PR #68 merged to `master`.** Python tests, native
contract/build tests, lint, Docker, and supported-platform CI completed
successfully on Ubuntu and Windows. Authorization guarantees remain scoped to
the enforced runners; arbitrary plugins and direct socket code are not
certified by this milestone.

## P1 — Intelligence and engine consistency

| Priority | Work | State | Completion evidence |
|---|---|---|---|
| P1 | Unify C/Rust/Go engine interfaces | Done | `core/native_contract.py` is authoritative; one closed outcome-state set; capability entrypoints are tested; degraded and failed dispatches carry a reason. Closed by PR #55 and covered by `tests/test_capability_contract.py`. |
| P1 | Develop Asset Graph | Done | Stable asset identities, typed relationships, provenance, deduplication, isolated nodes, and reproducible graph exports (PRs #34, #35, #45). |
| P1 | Develop Risk Scoring | Done | Explainable factors, evidence references, confidence, severity, and deterministic scoring with regression fixtures (PR #33). |
| P1 | Directed and weighted graph analytics | Done | Rust CSR paths for weighted routing, PageRank, articulation points and bridges (ABI v3) with a Python reference and parity tests; capability contract and benchmarks cover both backends. |

**Exit gate:** equivalent inputs produce consistent normalized findings;
engine selection and fallback are visible in reports; every risk score can be
explained from evidence.

## P2 — Operator experience

| Priority | Work | State | Completion evidence |
|---|---|---|---|
| P2 | Dashboard | Deferred | Campaign list/detail, live state, backend health, errors, and scope visibility. Deliberately postponed until the analytics and monitoring contracts settle. |
| P2 | Interactive reports | Done | `helios report` builds a single-file offline report from a typed graph with asset/relationship filters, degree and evidence counts, escaped embedded JSON, and no network requests. Hosted filtering of live campaigns remains part of the dashboard item. |

**Exit gate:** the UI consumes versioned internal APIs and does not duplicate
business logic or bypass scope enforcement.

## P3 — Continuous asset monitoring

| Priority | Work | Completion evidence |
|---|---|---|
| P3 | Continuous asset monitoring | Scheduled, scope-bound rechecks; baseline snapshots; change detection; deduplicated alerts and audit history |

**Exit gate:** monitoring reuses the same authorization policy, rate limits,
and evidence model as one-time campaigns.

## Current implementation notes

- Initial P0 scope and contract hardening was merged in PR #31. The follow-up P0 audit and remediation is now merged in PR #68; the current P0 exit gate passed Ubuntu and Windows CI.
- Graph analytics are available on both the Rust core and Python: the same
  directed/weighted inputs produce the same route, ranking and cut points, and
  only the reported engine changes. The native core is an accelerator, never a
  prerequisite.
- The Go scanner is a process/NDJSON component. The C core supports both a
  line-oriented JSON process interface and an in-process shared-library FFI
  path. Rust is exposed through a C ABI. These components do not share one
  transport protocol.
- Empty port allowlists currently retain backward-compatible any-port
  semantics for an otherwise authorized target. Explicit port lists are
  recommended for least-privilege engagements.
- Evasion, endpoint bypass, and stealth expansion are not roadmap priorities.
  The project should first demonstrate reliable, auditable, authorized
  discovery and analysis.
- Release status is pre-release (`v2.0.0-beta.1`). The earlier `v2.0.0` tag was
  withdrawn so no one reads a stable version number into a tree whose interfaces
  are still moving; no release is frozen and none is supported for production.

- The explainable risk-scoring increment is merged into `master` (PR #33).
- The typed Asset Graph model (PR #34) and scope-bound HTTP discovery ingestion
  (PR #35) are merged. The discovery summary emits the typed graph alongside
  legacy findings.
- The CLI can export the graph with `assets --graph-output` and analyze it with
  `graph analyze`. The versioned Rust topology projection maps native indices
  back to typed asset IDs while retaining the directed relationship ledger and
  evidence in Python.
- The Rust ABI and its legacy undirected analytics contract remain unchanged.
  This increment does not claim directed graph analytics or full polyglot
  graph parity.
- Dedicated DNS record and service-discovery graph adapters are merged (PR #45).
  They expand names only through Certificate Transparency and scoped
  resolution, drop every answer outside the authorized scope before a socket
  is opened, and record typed evidence (TTL, records, service endpoints).
  This closes the dedicated DNS/service adapter gap for the P1 asset graph.
- TLS observations now include a SHA-256 certificate fingerprint. The typed
  graph records certificate identity and a directed certificate_for edge to
  the observed host, with bounded certificate metadata and evidence provenance.
- Repository hygiene was tightened (PR #49): private security reporting, a
  documented threat model, issue templates, a 60-second local quickstart, and
  a ruff pre-commit hook aligned with the CI version.
- The capability contract is authoritative: `core/accel.py` derives each
  backend's advertised capabilities from `core/native_contract.py`, every
  capability names a tested entrypoint, `helios doctor` prints the matrix, and
  normalized outcomes use one closed state set. This closes the P1 engine
  interface item.
