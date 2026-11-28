# Contributing to HELIOS-NET

Thank you for your interest in contributing to **HELIOS-NET** — an enterprise-grade, autonomous polyglot orchestrator for **red teaming** and **attack surface management (ASM)**.

We welcome contributions from security researchers, red teamers, and engineers. This guide defines our contribution workflow and standards to keep the project cohesive, secure, and maintainable.

---

## 📜 Code of Conduct

By participating in this project you agree to abide by the following principles:

- **Authorized use only.** All features are intended for authorized testing (penetration testing, red teaming, and educational research) against assets you own or have explicit written permission to assess. Targeting third-party assets without consent is strictly prohibited.
- **Respectful engineering.** Collaborate constructively; no harassment, no gatekeeping, no personal attacks.
- **Dual-use responsibility.** Ship code that enables defenders and authorized testers, and document all capabilities honestly.

---

## 🛡️ Ethical & Legal Notice

HELIOS-NET is a **dual-use security framework**. Contributors are expected to ensure that any submitted code:

1. Does **not** hardcode targets owned by third parties.
2. Does **not** automate attacks against infrastructure without authorization.
3. Follows all applicable laws and regulations (e.g., Computer Fraud and Abuse Act, GDPR, regional equivalents).
4. Frames offensive primitives within the red-teaming / ASM context (authorized engagements), never generic "attack botnets".

Violations of these expectations are grounds for rejecting a contribution.

---

## 🧱 Architecture at a Glance

Understanding the layering helps you place your contribution correctly:

```
Python Orchestration Layer        core/  · engine/ · modules/ · cli/ · run.py
Go process worker                 transport/goscan/  (TCP discovery, NDJSON)
C process / FFI core              transport/c_core/  (matching, fingerprints)
Rust shared library               rust-core/  (graph analytics, matching, C ABI)
Documentation                     docs/ · README.md · ROADMAP.md
Automation                        build.py · .github/workflows/
```

| Layer | Purpose |
|-------|---------|
| `core/` | State, WAL, orchestration, planning, reporting, daemon |
| `engine/` | Graph, pathfinding, algorithms, verdicts, scanners, plugins |
| `modules/` | Discovery, asset metadata, recon, collection, registry, plugins |
| `transport/` | Go & C binaries that run natively via IPC/FFI |
| `rust-core/` | Pure-stdlib Rust primitives exposed via a `ctypes` FFI bridge |
| `cli/` + `run.py` | Command-line entry points and daemon control |

---

## Canonical technical references

- [Architecture and native-core map](docs/Architecture.md)
- [Internal API and module contracts](docs/API.md)
- [Scope enforcement and authorization boundary](docs/SCOPE-ENFORCEMENT.md)
- [Native IPC and NDJSON contract](docs/IPC-CONTRACT.md)
- [Engineering roadmap](ROADMAP.md)

These documents describe the current implementation. Do not copy an obsolete
module or transport description into a new feature.

---

## 🚀 Getting Started

### 1. Set up your environment
```bash
git clone https://github.com/Ismail-Benali/HELIOS-NET.git
cd HELIOS-NET

# Python stdlib only — no pip installs required for core logic.
python --version   # 3.12+ recommended
```

### 2. Install native toolchains (optional, for native modules)
- **Go** ≥ 1.22 — for `transport/` binaries
- **Rust / Cargo** — for `rust-core/` primitives
- **C compiler** (GCC/Clang) — for `transport/` C primitives

To compile all native binaries automatically:
```bash
python build.py
```

### 3. Build and verify the wheel
A checkout with built cores produces a platform wheel that carries them; a
checkout without cores produces the pure wheel that uses the Python fallback.
The version comes from `pyproject.toml` (`2.0.0b1` in this pre-release):

```bash
python build.py
python -m pip wheel . --no-deps -w dist
# dist/helios_net-2.0.0b1-py3-none-win_amd64.whl
# dist/helios_net-2.0.0b1-py3-none-linux_x86_64.whl
# dist/helios_net-2.0.0b1-py3-none-any.whl  (nothing built)
python tools/verify_wheel.py --wheel "dist/*.whl" --require c rust go
```

`verify_wheel.py` installs the artifact in a clean virtual environment outside
the checkout and fails unless the requested backends load. The `wheel` CI job
runs the same sequence on Ubuntu 24.04 and Windows, so a packaging change that
only works in a source checkout is caught before merge.

### 4. Run the verification suite
```bash
python tests/smoke.py
```
**All sets must pass** before you open a pull request.

---

## 🧩 How to Add a New Module

Modules are the primary extension point. They live under `modules/` (e.g. `modules/discovery/`).

### Example: a new in-process discovery module
1. Create `modules/discovery/my_discovery.py`.
2. Implement the in-process runner contract:
   ```python
   def runner(step: PlanStep, context: dict[str, Any]) -> dict[str, Any]:
       # Require the active campaign ScopeEnforcer from context.
       # Check the target and requested ports before any network operation.
       ...
   ```
   The example is a contract sketch: import the project types and use the
   existing scope/port helpers rather than creating a permissive enforcer.
3. Register the runner in `modules/registry.py` (or the relevant registry).
4. Add deterministic allowed/denied tests and a smoke test where appropriate.
5. Document the module and its evidence/output shape in `docs/`.

A Python discovery module is not a subprocess protocol. If a genuinely
independent native process is required, define its UTF-8 JSON/NDJSON wire
contract separately and update both producer and consumer tests.

### Module and native-process contracts
Python modules are in-process runners using
`runner(step: PlanStep, context: dict) -> dict`. They receive the active
campaign scope in the context and must enforce target and port authorization
before network access. Do not describe or implement a Python module as an
independent stdin/stdout process unless a separately reviewed process boundary
is explicitly introduced.

The Go scanner uses UTF-8 NDJSON over a process boundary. The C core has its
own line-oriented JSON process interface and an optional in-process FFI path.
Rust is loaded in-process through a C ABI; it is not an NDJSON worker. stdout is
protocol-only, while diagnostics and Standardized Error Envelopes (SEE) belong
on stderr. A missing response, malformed record, timeout, or non-zero process
exit must remain distinguishable from a genuine empty result. See
[API](docs/API.md), [scope policy](docs/SCOPE-ENFORCEMENT.md), and
[IPC contract](docs/IPC-CONTRACT.md).

> 💡 New modules must follow the same standards below: English-only, zero external pip dependencies, and unit tests.

---

## ✅ Contribution Checklist

Before submitting a pull request, confirm:

- [ ] **English only.** All code comments, docstrings, CLI help, and documentation are in English.
- [ ] **Zero external pip dependencies.** Core Python logic uses only the standard library. Native modules (Go/Rust/C) may use their respective toolchains' standards but must not require system-level package installation beyond the toolchain itself.
- [ ] **Tests pass.** Build native cores where supported, then run `python -m pytest -q` and `python tests/smoke.py`.
- [ ] **License.** Contributions are accepted under `AGPL-3.0-only`; do not submit code you cannot license on those terms.
- [ ] **Authorized-use framing.** No hardcoded third-party targets; offensive primitives framed within the red-teaming / ASM context.
- [ ] **Documentation updated.** README, relevant `docs/`, or module docs reflect your change.

---

## 🔀 Branching & Pull Request Workflow

1. Create a feature branch from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Implement your change following the checklist above.
3. Build the native cores and run the full suite:
   ```bash
   python build.py
   python -m pytest -q
   ```
   A skipped test fails the run unless you pass `--allow-skips`. Every skip
   means a core was not built, so do not use that flag to make the numbers look
   green; use it only for a deliberately platform-gated test.
4. Commit with a clear, conventional message:
   ```
   feat(modules): add MyDiscovery module
   fix(engine): correct Dijkstra tie-breaking
   docs(readme): document API export workflow
   ```
5. Push and open a pull request **against `master`**.
6. The GitHub Actions pipeline will validate the build and smoke tests on Ubuntu and Windows.

---

## 🐛 Reporting Bugs

- Search existing issues first to avoid duplicates.
- Include the HELIOS-NET version/commit, OS, Python version, and a minimal reproduction.
- Mention whether the bug affects the Python core, a native binary, or the build pipeline.

**Security vulnerabilities:** do **not** open a public issue. Follow the instructions in [`SECURITY.md`](SECURITY.md) to report privately.

---

## 📚 Documentation Standards

- Keep comments and docstrings concise, technical, and in English.
- Preserve the existing docstring style (`"""HELIOS-NET :: module/path :: one-line summary + features"""`).
- Update `ARCHITECTURE.md` when you change cross-cutting structure.
- Link new docs from `README.md` where appropriate.

---

## 🧪 Testing Guidelines

- Extend `tests/smoke.py` with a focused set for any new capability.
- Keep tests deterministic and independent of network availability.
- Native bridges may use a documented Python fallback when a core is absent, but must preserve backend status and failure reasons. Never use an empty result to disguise a missing binary, timeout, malformed response, or failed process.

---

## ❓ Questions & Feedback

- Open a Discussion or an Issue in the repository.
- Prefer async public discussion so others benefit from the context.

Thank you for helping keep HELIOS-NET **fast, safe, and frameworks-first** — secure by design, and responsibly built. ⚡
