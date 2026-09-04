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
Native Transport Layer (Go & C)   transport/  (goscan, rawsync, evasion, ...)
High-Performance Rust Core        rust-core/  (graph pathfinding, TTL analysis)
Documentation                      docs/ · README.md · ARCHITECTURE.md · ROADMAP.md
Automation                         build.py · .github/workflows/build.yml
```

| Layer | Purpose |
|-------|---------|
| `core/` | State, WAL, orchestration, planning, reporting, mutation, daemon |
| `engine/` | Graph, pathfinding, algorithms, verdicts, scanners, plugins |
| `modules/` | Discovery, recon, stealth, registry, plugins |
| `transport/` | Go & C binaries that run natively via IPC/FFI |
| `rust-core/` | Pure-stdlib Rust primitives exposed via a `ctypes` FFI bridge |
| `cli/` + `run.py` | Command-line entry points and daemon control |

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

### 3. Run the verification suite
```bash
python tests/smoke.py
```
**All sets must pass** before you open a pull request.

---

## 🧩 How to Add a New Module

Modules are the primary extension point. They live under `modules/` (e.g. `modules/discovery/`).

### Example: a new discovery module
1. Create `modules/discovery/my_discovery.py`.
2. It should accept input via **JSON on `stdin`** and emit results via **JSON on `stdout`**:
   ```
   {"host": "10.0.0.1", "ports": [80, 443]}
   ```
   ```
   [{"host": "10.0.0.1", "port": 443, "status": "open"}]
   ```
3. Register it in `modules/registry.py` (or the relevant registry) so the orchestrator can discover and load it.
4. Add a corresponding smoke test in `tests/smoke.py`.
5. Document the module in `docs/`.

### Module contract
- **stdin**: JSON input (target, scope, parameters).
- **stdout**: JSON output (findings, structured records).
- **stderr**: diagnostics only — never parse business data from stderr.
- **Exit codes**: `0` on success, non-zero on failure.

> 💡 New modules must follow the same standards below: English-only, zero external pip dependencies, and unit tests.

---

## ✅ Contribution Checklist

Before submitting a pull request, confirm:

- [ ] **English only.** All code comments, docstrings, CLI help, and documentation are in English.
- [ ] **Zero external pip dependencies.** Core Python logic uses only the standard library. Native modules (Go/Rust/C) may use their respective toolchains' standards but must not require system-level package installation beyond the toolchain itself.
- [ ] **Tests pass.** `python tests/smoke.py` completes with `ALL SETS PASSED`.
- [ ] **Authorized-use framing.** No hardcoded third-party targets; offensive primitives framed within the red-teaming / ASM context.
- [ ] **Documentation updated.** README, relevant `docs/`, or module docs reflect your change.

---

## 🔀 Branching & Pull Request Workflow

1. Create a feature branch from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Implement your change following the checklist above.
3. Run the full test suite and `python build.py` (if native code changed).
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
- Native modules should degrade gracefully (return `[]` / fallbacks) when their binaries are absent.

---

## ❓ Questions & Feedback

- Open a Discussion or an Issue in the repository.
- Prefer async public discussion so others benefit from the context.

Thank you for helping keep HELIOS-NET **fast, safe, and frameworks-first** — secure by design, and responsibly built. ⚡
