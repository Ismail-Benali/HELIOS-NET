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
2. **Encrypted Transactional WAL:** Crash recovery and secure transaction logging secured by PBKDF2 (100,000 iterations) and Counter-Mode SHA-256 authenticated encryption.
3. **High-Performance Go Scanning:** Leverages thousands of lightweight Goroutines (`goscan`) streaming open ports via NDJSON.
4. **Asset Graph & Risk Ranking:** Converts discoveries into an **Asset Graph**, computes Degree Centrality, and runs **Dijkstra's Algorithm** to calculate optimal inspection routes.
5. **Verdict & Rule Engine:** Classifies findings using built-in rules or dynamic JSON-driven rules (Dynamic DSL).
6. **Executive HTML Reporting:** Generates self-contained dark-mode HTML executive briefing reports with full HTML escaping for XSS protection.

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

### 1. Run a Full Reconnaissance Campaign
```bash
python run.py recon --target 127.0.0.1
```

### 2. Classify Open Ports via Verdict Engine
```bash
python run.py judge --target 127.0.0.1
```

### 3. Run the End-to-End Simulation
```bash
python run_simulation.py
```

---

## ✅ Automated Testing

Execute the comprehensive self-verification test suite:
```bash
python tests/smoke.py
```

---

## 🛡️ Honest Project Status

**HELIOS-NET is a focused, research-grade Attack Surface Management and Scanning Framework.**
Following a major strategic refactoring, all unused polyglot bloat, disconnected evasion stubs, and malware tooling have been surgically removed to focus entirely on robust orchestration, fast network discovery, asset graphing, and executive reporting.
