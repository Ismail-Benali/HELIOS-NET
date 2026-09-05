# HELIOS-NET :: Repository AI Agent Instructions (Copilot / Workspace)

Welcome, AI Agent or Copilot. You are assisting with the **HELIOS-NET** repository — an enterprise-grade autonomous polyglot orchestrator for **red teaming** and **attack surface management (ASM)**.

## Core Engineering Rules
1. **Zero External Pip Dependencies:** Python core logic must rely *exclusively* on the Python Standard Library (`stdlib`). Never introduce external `pip` packages.
2. **Polyglot Architecture:**
   - **Python (`core/`, `engine/`, `modules/`, `cli/`):** Control plane, state, graph analytics, and orchestration.
   - **Go (`transport/`):** High-performance concurrent networking and scanning (`goscan`, `covert`, `rawsync`) streaming via NDJSON.
   - **C (`transport/`):** Low-level user-mode evasion and signature matching primitives, compiled with size-optimization linker flags (`-Os -Wl,--gc-sections -s`).
   - **Rust (`rust-core/`):** High-performance graph pathfinding (Dijkstra) and TTL analysis exposed via a zero-dependency `ctypes` FFI bridge.
3. **Language Rule:** ALL code comments, docstrings, CLI help strings, and documentation MUST be in **English only**.
4. **Ethical & Safety Scope:** All code is strictly for authorized red teaming, penetration testing, and ASM. Never introduce hardcoded third-party public targets or unauthorized exploitation tools.
5. **Testing & Verification:** All code changes must pass the self-verification test suite (`python tests/smoke.py`) and compile cleanly via `python build.py`.
