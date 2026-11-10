# HELIOS-NET :: Engineering Roadmap

This roadmap prioritizes correctness, authorization, and interoperability
before operator-facing features. Work is ordered by dependency, not by
visibility.

## P0 — Engineering foundation

| Priority | Work | Completion evidence |
|---|---|---|
| P0 | Unify architecture and documentation | One current component map; obsolete module descriptions removed; README, Architecture, API, and contributor guidance agree |
| P0 | Review scope enforcement | Target and port checks happen before execution; DNS/redirect boundaries are tested; denied targets produce no connection |
| P0 | Stabilize IPC and NDJSON contracts | UTF-8, framing, request correlation, SEE errors, timeout and fallback semantics are documented and tested |

**Exit gate:** all P0 changes pass Python tests, native contract tests where
available, and CI on supported platforms. No claim of complete authorization
is made for arbitrary plugins or direct socket code outside the enforced
runners.

## P1 — Intelligence and engine consistency

| Priority | Work | Completion evidence |
|---|---|---|
| P1 | Unify C/Rust/Go engine interfaces | Capability registry is authoritative; common result/provenance shapes; backend parity and failure-state tests |
| P1 | Develop Asset Graph | Stable asset identities, typed relationships, provenance, deduplication, isolated nodes, and reproducible graph exports |
| P1 | Develop Risk Scoring | Explainable factors, evidence references, confidence, severity, and deterministic scoring with regression fixtures |

**Exit gate:** equivalent inputs produce consistent normalized findings;
engine selection and fallback are visible in reports; every risk score can be
explained from evidence.

## P2 — Operator experience

| Priority | Work | Completion evidence |
|---|---|---|
| P2 | Dashboard | Campaign list/detail, live state, backend health, errors, and scope visibility |
| P2 | Interactive reports | Filterable findings, asset relationships, risk explanations, export, and evidence provenance |

**Exit gate:** the UI consumes versioned internal APIs and does not duplicate
business logic or bypass scope enforcement.

## P3 — Continuous asset monitoring

| Priority | Work | Completion evidence |
|---|---|---|
| P3 | Continuous asset monitoring | Scheduled, scope-bound rechecks; baseline snapshots; change detection; deduplicated alerts and audit history |

**Exit gate:** monitoring reuses the same authorization policy, rate limits,
and evidence model as one-time campaigns.

## Current implementation notes

- P0 scope and contract hardening is merged into `master` (PR #31).
- The Go scanner is a process/NDJSON component, the C core is a process
  component, and Rust is currently exposed through a C ABI. They do not share
  one transport protocol.
- Empty port allowlists currently retain backward-compatible any-port
  semantics for an otherwise authorized target. Explicit port lists are
  recommended for least-privilege engagements.
- Evasion, endpoint bypass, and stealth expansion are not roadmap priorities.
  The project should first demonstrate reliable, auditable, authorized
  discovery and analysis.

- The explainable risk-scoring increment is merged into `master` (PR #33).
- The typed Asset Graph model and the first scope-bound HTTP discovery ingestion
  adapter are merged in PR #34 and are being extended in the current branch.
  Rust native projection and adapters for other discovery modules remain open.

- The asset discovery summary now emits a typed graph alongside legacy findings;
  the Rust ABI and legacy undirected analytics graph remain unchanged.
