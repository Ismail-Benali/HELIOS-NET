# 60-second quickstart (local lab only)

This walks through the whole loop without touching a third-party system.
No pip installs are needed for the Python control plane; Python 3.12+ is enough.

## 1. Initialize and verify the environment

```bash
python run.py init
python run.py doctor
```

`init` never overwrites an existing scope file. `doctor` is read-only and makes
no network connections. You should see `[OK] Scope configuration` plus the
optional native toolchains that were found.

## 2. Run a scoped campaign against your own machine

```bash
python run.py recon --target 127.0.0.1
```

Typical output (campaign ID and finding count vary by host):

```text
[HELIOS] campaign bcb5d23128c64f059781a99792b4526d -> done
[
  { "step_id": 1, "module": "discovery", "action": "scan",
    "target": "127.0.0.1", "status": "done" },
  ...
]
[HELIOS] findings collected: 1
```

The campaign plans discovery, asset expansion, and collection, then executes
them with fault isolation. Native Go/C/Rust cores are optional; without them
the Python reference paths answer and the report records which engine ran.

## 3. See fail-closed scope enforcement

```bash
python run.py recon --target 8.8.8.8
```

```text
[HELIOS] refused: target '8.8.8.8' is outside the authorized scope
(source: config/scope.yaml; cidrs=127.0.0.0/24; ...)
```

Exit code is `2` and **no socket is opened**. A missing, malformed, or `*`
scope is refused the same way — the default is deny, not allow.

## 4. Inspect results without a new scan

```bash
python run.py status
python run.py dashboard
python run.py export --help
```

`status` reads campaign state, `dashboard` renders a local briefing, and
`export` writes JSON/CSV/SARIF from stored findings.

## What to read next

- [Scope enforcement](SCOPE-ENFORCEMENT.md) — the authorization boundary
- [Architecture](Architecture.md) — component and native-core map
- [IPC contract](IPC-CONTRACT.md) — NDJSON/C ABI between layers
- [SECURITY policy](../SECURITY.md) — private vulnerability reporting

> Only add domains, CIDRs, and ports you are explicitly authorized to assess.
