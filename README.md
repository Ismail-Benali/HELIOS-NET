<div align="center">

# HELIOS-NET
### Autonomous Attack Surface Management & High-Performance Scanning Engine

[![Release](https://img.shields.io/github/v/release/Ismail-Benali/HELIOS-NET?style=for-the-badge&label=release&color=black)](https://github.com/Ismail-Benali/HELIOS-NET/releases)
[![Stars](https://img.shields.io/github/stars/Ismail-Benali/HELIOS-NET?style=for-the-badge&label=stars&color=black&logo=github)](https://github.com/Ismail-Benali/HELIOS-NET/stargazers)
[![License](https://img.shields.io/badge/license-non--commercial-black.svg?style=for-the-badge&color=black)](LICENSE)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/Ismail-Benali/HELIOS-NET/build.yml?style=for-the-badge&label=build&logo=githubactions&logoColor=green)](https://github.com/Ismail-Benali/HELIOS-NET/actions)

<br>

[![Python](https://img.shields.io/badge/python-3.12-black.svg?style=for-the-badge&logo=python&logoColor=green)](https://www.python.org/)
[![Go](https://img.shields.io/badge/go-1.22-black.svg?style=for-the-badge&logo=go&logoColor=green)](https://golang.org/)

</div>

---

**HELIOS-NET** is a focused, high-performance **Attack Surface Management (ASM)** and **network scanning orchestrator**. Designed around a **Closed-Loop Intelligence Cycle** (Reconnaissance ➔ Planning ➔ Execution ➔ Analysis ➔ Reporting), HELIOS-NET relies entirely on Python stdlib for control orchestration and high-performance Go binaries (`goscan`) for concurrent networking and NDJSON streaming.

> ⚠️ **Scope Notice:** HELIOS-NET is designed strictly for **authorized** penetration testing, network mapping, and educational research.

---

## 📑 Table of Contents

- [Core Capabilities](#-core-capabilities)
- [System Architecture](#-system-architecture)
- [Quick Start & CLI Usage](#-quick-start--cli-usage)
- [Automated Testing](#-automated-testing)
- [Honest Project Status](#-honest-project-status)

---

## ⚙️ Core Capabilities

1. **Closed-Loop Orchestration:** Manages campaign state, dependency planning, and parallel wave execution with absolute fault isolation.
2. **Encrypted Transactional WAL:** Crash recovery and secure transaction logging with PBKDF2 (100,000 iterations) stretched **once per log**, a per-record nonce, an HMAC-SHA256 counter-mode keystream, and separate encryption and MAC keys. Logs written by the earlier per-record-salt layout remain readable in place.
3. **Fail-Closed Scope Enforcement:** `core/scope.py` denies every target unless the scope file authorizes it. An unreadable, malformed, or `*` scope is an error, not a wildcard; the refusal names the reason.
4. **Scope-Bound Asset Discovery:** Expands seeds through Certificate Transparency, resolves each name, drops every address the scope does not authorize before a socket is opened, follows redirects only while every hop stays in scope, and records HTTP/TLS metadata, security headers, cookies, certificate expiry, and well-known documents (`--deep`).
5. **High-Performance Go Scanning:** Leverages thousands of lightweight Goroutines (`goscan`) streaming open ports via NDJSON through a long-lived `serve` worker, so repeated sweeps reuse the pool instead of paying process startup.
6. **Asset Graph & Risk Ranking:** Converts discoveries into an **Asset Graph**, computes Degree Centrality, and runs **Dijkstra's Algorithm** to calculate optimal inspection routes.
7. **Verdict & Rule Engine:** Classifies findings using built-in rules or dynamic JSON-driven rules (Dynamic DSL).
8. **Executive HTML Reporting:** Generates self-contained dark-mode HTML executive briefing reports with full HTML escaping for XSS protection.

---

## 🗺️ System Architecture

```text
+-------------------------------------------------------------------------+
|                         HELIOS-NET CLI & DAEMON                         |
|                       (Python Control Plane Core)                       |
+-------------------------------------------------------------------------+
       |                     |                     |              
       v                     v                     v              
+--------------+     +---------------+     +---------------+   
|  core/       |     |   engine/     |     |   modules/    |   
| - wal.py     |     | - graph/      |     | - discovery/  |   
| - state.py     |     | - killchain/  |     | - recon/      |   
| - orchestr.  |     | - algorithms/ |     | - stealth/    |   
+--------------+     +---------------+     +---------------+   
       |                     |                     |
       +---------------------+---------------------+
                             | (IPC / NDJSON Streams)
                             v
         +-------------------------------------+
         |          GO NETWORK ENGINE          |
         | - goscan (Goroutines Port Scanner)  |
         +-------------------------------------+
```

---

## 🚀 Quick Start & CLI Usage

HELIOS-NET requires **zero external pip dependencies** for its core control plane.

Every network command is scope-checked. Edit `config/scope.yaml` (or pass
`--scope path.json`) to list the domains, CIDRs, and ports you are authorized to
touch. The default file covers `example.test`, `lab.test`, and a loopback range;
anything outside it is refused with exit code `2` before a socket is opened.

### 1. Run a Full Reconnaissance Campaign
```bash
python run.py recon --target 127.0.0.1
```

### 2. Classify Open Ports via Verdict Engine
```bash
python run.py judge --target 127.0.0.1
```

### 3. Probe Banners Through the Adaptive Engine
```bash
python run.py probe --target 127.0.0.1 --ports 22,80,443
```

### 4. Map the Scoped Asset Surface
```bash
python run.py assets --target example.test --ct --depth 1
```

`assets` expands names through Certificate Transparency, refuses to probe any
name or address outside the scope, and reports virtual hosts separately from the
address-default response. Redirects are followed only while every hop resolves
inside the scope; leaving it is recorded as `redirect-outside-scope`.
`--max-hosts` and `--max-requests` bound the loop; `--seeds` adds names that are
still scope-checked. `--deep` also fetches `/.well-known/security.txt` and
`/robots.txt` for ownership signals. A campaign plans this step by default
(without CT); `recon --ct` opts into expansion.

DNS enumeration is scope-bound too: `dns_enum` refuses to run without an
enforcer, filters candidate names before any resolver call, and discards answers
outside a network scope.

Discovery routes every port through `core.accel.scan_ports` (Go when built,
socket probe otherwise), and recon matches the collected banners through the
C/Rust/Python signature core. Each finding records the engine that answered.

### 5. Run the End-to-End Simulation
```bash
python run_simulation.py
```

---

## Performance Measurement

The numeric claims live in `tools/bench_scan.py` rather than in this file:

```bash
python tools/bench_scan.py --host 127.0.0.1 --ports 1-1024 --repeat 3
```

It reports the median wall time, ports/second, which backend answered, and the
spread across runs. Numbers depend on the host, the open/closed mix, and whether
the Go binary was built (`python build.py`), so measure on the machine you care
about.

---

## ✅ Automated Testing

Install the pinned development toolchain, then run the suite:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

`tests/test_end_to_end.py` is the integration gate: it starts a real local TCP
server, runs a campaign through the CLI and the real cores, asserts the banner
is identified, and asserts an out-of-scope target is refused before any
connection is made. The C golden contract is checked separately:

```bash
python tools/gen_c_reference.py --check
```

## Continuous Integration

`master` requires two green workflows before a change is merged:

| Workflow | What it proves | What it does not prove |
| --- | --- | --- |
| `build.yml` | The project builds and its core suites pass on Ubuntu 24.04 and Windows: Python, Go, Rust, C, the C golden contract, and the ASan/UBSan plus differential-fuzz stages. | That no memory-safety bug exists. Sanitizers and fuzzing only cover the paths they execute. |
| `lint.yml` | Ruff, Clippy/rustfmt, cppcheck/clang-tidy and gofmt/golangci-lint agree with the tree. | Correctness. A clean lint is not a passing test. |

Coverage, Security (CodeQL, Trivy, Scorecards), Fuzz (nightly) and Release stay
in the repository but run manually (`workflow_dispatch`) while the pipeline is
being stabilized. They are not merge gates yet.

No automated check proves the project is free of vulnerabilities.

---

## 🛡️ Honest Project Status

**HELIOS-NET is a focused, research-grade Attack Surface Management and Scanning Framework.**
Following a major strategic refactoring, all unused polyglot bloat, disconnected evasion stubs, and malware tooling have been surgically removed to focus entirely on robust orchestration, fast network discovery, asset graphing, and executive reporting.
