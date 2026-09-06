# HELIOS-NET :: Internal API & Module Developer Guide

Welcome to the **HELIOS-NET Developer Guide**. This document details the internal API contracts, module specifications, and architectural guidelines for developers and contributors looking to extend the framework.

---

## 🏛️ Architectural Principles

1. **Zero External Pip Dependencies:** The Python core control plane must rely *exclusively* on the Python Standard Library (`stdlib`).
2. **Polyglot Isolation:** Heavy networking/recon is delegated to Go (`transport/`), memory-safe graph pathfinding to Rust (`rust-core/`), and low-level stealth primitives to C (`transport/`).
3. **Machine-Readable Contracts:** All inter-process communication (IPC) and error reporting use structured JSON / NDJSON or Standardized Error Envelopes (SEE).

---

## 🔌 Writing a New Module

Modules are isolated operational units placed under `modules/` (e.g., `modules/discovery/`, `modules/recon/`, `modules/exfil/`).

### Module Input / Output Contract
To maintain absolute decoupling and fault isolation, every extensible module must follow the **JSON Stdin/Stdout I/O Protocol**:
- **`stdin`**: Receives target parameters and scope configuration as a single-line JSON string.
- **`stdout`**: Outputs structured findings or discovery records as a JSON array or NDJSON stream.
- **`stderr`**: Reserved exclusively for diagnostics or **Standardized Error Envelopes (SEE)**.
- **Exit Code**: `0` on successful execution, non-zero on failure.

### Example Module Template (`modules/discovery/custom_scanner.py`)
```python
"""
HELIOS-NET :: modules/discovery/custom_scanner.py
Custom discovery module template following the JSON stdin/stdout contract.
"""

from __future__ import annotations

import sys
import json

def main() -> int:
    try:
        # Read input parameters from stdin
        raw_input = sys.stdin.read()
        payload = json.loads(raw_input) if raw_input.strip() else {}
        target = payload.get("target", "127.0.0.1")

        # Perform discovery logic (using stdlib only)
        findings = [
            {"host": target, "port": 80, "service": "http", "open": True}
        ]

        # Output results as JSON on stdout
        print(json.dumps(findings, ensure_ascii=True))
        return 0
    except Exception as exc:
        # Emit standardized error envelope on stderr
        err_env = {
            "status": "error",
            "code": "MODULE_ERROR",
            "message": str(exc),
            "component": "modules/discovery/custom_scanner"
        }
        print(json.dumps(err_env), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

---

## 🛠️ Registering Your Module

1. Place your module file inside the appropriate directory under `modules/`.
2. Register it with the module registry (`modules/registry.py`) so the orchestrator and CLI (`python run.py info`) discover it automatically.
3. Add verification test coverage in `tests/smoke.py`.

---

## 🛡️ Standardized Error Envelopes (SEE)

When a native or Python component encounters a security trap (WAF, EDR interception, timeout), it must emit an error envelope:
```json
{
    "status": "error",
    "code": "EDR_BLOCKED",
    "message": "Interception detected.",
    "component": "transport/evasion",
    "module": "direct_syscalls"
}
```
The `MutationEngine` (`core/mutation_engine.py`) consumes these envelopes to automatically pivot tactics (e.g., `direct_syscalls` -> `memory_loader`) without human intervention.
