# Changelog

Notable changes to HELIOS-NET. Entries describe what a checked-out revision
actually contains; `helios version` reports the revision with
`git describe --tags --always`, so a tagged checkout prints its tag.

## [Unreleased]

Nothing since `v2.0.0-beta.1`.

## [2.0.0-beta.1] - 2026-11-17

**Pre-release.** There is no stable release. A `v2.0.0` tag briefly existed and
was withdrawn: the tree is under active development, interfaces can change
without a deprecation cycle, and no part of it is supported for production use.

This release supersedes `v1.3.0`. HELIOS-NET is now an authorized attack
surface management and network-discovery project. The offensive transport,
loader, and evasion components that earlier releases advertised are not part of
this repository, and no payload, implant, C2 channel, credential-access code,
or evasion binary remains.

### Added

- Typed asset graph with stable asset identities, typed relationships,
  provenance, and evidence; export with `assets --graph-output` and analysis
  with `graph analyze` (PRs #34, #35, #36).
- Scope-bound DNS and service-discovery graph adapters: Certificate
  Transparency expansion, scoped resolution, and out-of-scope answers dropped
  before a socket is opened (PR #45).
- Explainable risk scoring with deterministic fixtures and evidence references
  (PR #33, `engine/risk.py`).
- Native capability contract and per-finding backend provenance across the Go,
  C, and Rust paths (PR #44, `core/native_contract.py`).
- CLI surface: `doctor`, `init`, `version`, `probe`, `export`, `graph`, and the
  `helios.cmd` Windows launcher with a Python 3.12 guard.
- Offline route ranking over a collected asset graph (`graph analyze
  --source-asset/--target-asset`) and request pacing helpers.
- Repository hardening: private security reporting and threat model
  (`SECURITY.md`), issue templates, a 60-second quickstart
  (`docs/QUICKSTART.md`), and a pre-commit hook pinned to the CI ruff version
  (PR #49).
- Documentation guards: `tests/test_docs_paths.py` fails on broken relative
  links, missing documented component paths, removed-component references, or a
  second architecture document (PR #52).
- Docker workflow (`docker.yml`): builds the image on pull requests and `master`
  pushes, smoke-tests `helios version` inside the container, and publishes
  `ghcr.io/<owner>/<repository>` on `v*` tags.
- The native capability contract is authoritative: `core/accel.py` derives each
  backend's advertised capabilities from `core/native_contract.py`, every
  capability names a tested entrypoint, `helios doctor` prints the matrix, and
  `tests/test_capability_contract.py` covers matrix agreement, the closed
  outcome-state set, and degraded/failed dispatch for scanning, matching and
  graph operations.

### Changed

- Fail-closed scope enforcement: an unreadable, malformed, or `*` scope is an
  error rather than a wildcard, and denied targets produce no connection
  (`core/scope.py`).
- `docs/Architecture.md` is the single maintained architecture document; the
  root `ARCHITECTURE.md` is a pointer to it.
- Discovery routes every port through `core.accel.scan_ports` (Go when built,
  socket probe otherwise) and records which engine answered.
- `build.yml` and `lint.yml` are the required merge gates on `master`; coverage,
  security, nightly fuzz, and release stay manually dispatched for now.
- Test suite: 907 tests with every native core built, on Ubuntu 24.04 and
  Windows. A skipped test now fails the run unless `--allow-skips` is passed:
  every skip meant a core had not been built, so a green run could claim C, Rust
  and Go parity, FFI and golden coverage it never executed.

### Fixed

- The runtime image now includes `cli/` and `config/`, which the entrypoint
  needs (`run.py` imports `cli.main`) and which the previous Dockerfile omitted.

### Removed

- `transport/rawsocket/`, `transport/tunnel/`, `transport/evasion/`,
  `transport/c_loader/`, `transport/harness/`, `transport/fingerprint/`, and
  `transport/c_matcher/` (matching now lives in `transport/c_core/`).
- `core/mutation_engine.py`, `core/pivot_proxy.py`, `core/error_envelope.py`
  (replaced by `core/envelope.py`), `strike.py`, `engine/pathfinder.py`, and
  `engine/c_matcher_bridge.py`.

## [1.3.0] - 2026-09-07

Historical snapshot. Its release notes describe transport and evasion
capabilities that are no longer present in this repository; use the 2.0.0 entry
above for the current component list. Earlier releases are available on the
GitHub releases page.
