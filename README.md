# HELIOS-NET — Autonomous Polyglot Cyber Warfare & Offensive Reconnaissance Orchestrator

[![GitHub Actions](https://img.shields.io/badge/github-actions-black.svg?style=for-the-badge&logo=githubactions&logoColor=green)](https://github.com/Ismail-Benali/HELIOS-NET)
[![Python](https://img.shields.io/badge/python-3.12-black.svg?style=for-the-badge&logo=python&logoColor=green)](https://www.python.org/)
[![Go](https://img.shields.io/badge/go-1.27-black.svg?style=for-the-badge&logo=go&logoColor=green)](https://golang.org/)
[![C](https://img.shields.io/badge/c-gcc-black.svg?style=for-the-badge&logo=c&logoColor=green)](https://gcc.gnu.org/)

**HELIOS-NET** is an enterprise-grade, autonomous polyglot cyber warfare and offensive reconnaissance orchestration framework. Designed around a **Closed-Loop Intelligence Cycle** (Reconnaissance ➔ Planning ➔ Execution ➔ Analysis ➔ Adaptation), HELIOS-NET eliminates external dependencies, relying entirely on Python stdlib for control orchestration, high-performance Go binaries for concurrent networking, and low-level C binaries for Evasion and memory execution.

---

## 🏛️ System Architecture Topology

```
+-------------------------------------------------------------------------+
|                         HELIOS-NET CLI & DAEMON                         |
|                       (Python Orchestration Core)                       |
+-------------------------------------------------------------------------+
       |                     |                     |              |
       v                     v                     v              v
+--------------+     +---------------+     +---------------+   +------------+
|  core/       |     |   engine/     |     |   modules/    |   |  core/     |
| - wal.py     |     | - graph/      |     | - discovery/  |   | - daemon.py|
| - state.py   |     | - killchain/  |     | - recon/      |   | - mutation |
| - orchestr.  |     | - algorithms/ |     | - stealth/    |   | - reporter |
+--------------+     +---------------+     +---------------+   +------------+
       |                     |                     |
       +---------------------+---------------------+
                             | (IPC / Subprocess / JSON Streams)
                             v
+-------------------------------------------------------------------------+
|                           TRANSPORT / NATIVE                            |
|                     (Go & C High-Performance Layer)                     |
+-------------------------------------------------------------------------+
       |                                           |
       +-------------------+-----------------------+
                           |
                           v
        +-------------------------------------+
        |          GO TRANSPORT (Go 1.27)     |
        | - goscan.exe (Goroutines Scanner)   |
        | - rawsync.exe (Raw TCP SYN/ACK)     |
        | - covert.go (Polymorphic DNS Tunnel)|
        | - raft.go (Distributed Consensus)   |
        +-------------------------------------+
        |          C SOVEREIGN (GCC -O3)      |
        | - c_matcher.exe (Memory Matcher)    |
        | - fingerprint.exe (TTL OS Engine)   |
        | - evasion.exe (Direct Syscalls)     |
        | - verifier.exe (Protocol Fuzzer)    |
        | - kernel_filter.c (Ring 0 Driver)   |
        +-------------------------------------+
```

---

## ⚙️ What HELIOS-NET Does (Core Capabilities)

1. **Closed-Loop Intelligence Orchestration:** Manages campaign state, dependency planning, and parallel wave execution with absolute fault isolation.
2. **High-Performance Go Networking:** Leverages thousands of lightweight Goroutines (`goscan.exe`, `rawsync.exe`) to conduct lightning-fast port scans and stealth raw-socket handshakes.
3. **Automated Kill-Chain Pathfinding:** Converts raw discoveries into an **Asset Graph**, computes Degree Centrality, and runs **Dijkstra's Algorithm** to calculate the Least Resistance Attack Path.
4. **Military-Grade Evasion & Syscalls:** Bypasses user-mode API hooking via direct NTDLL SSN resolution (`direct_syscalls.exe`) and executes runtime XOR memory decryption.
5. **Autonomous Self-Healing & Mutation:** Detects WAF/Honeypot traps, shreds local temporary footprints securely, mutates encryption keys, and shifts attack vectors automatically.
6. **Encrypted Transactional WAL:** Guarantees absolute crash recovery and zero data loss with at-record HMAC-SHA256 authenticated encryption.
7. **Continuous Autonomous Daemon:** Operates as a silent background agent (`daemon.py`) running continuous recon and self-preservation loops.

---

## 🚀 Quick Start & CLI Usage

HELIOS-NET requires zero external `pip` packages for its core logic.

### 1. Run a Full Reconnaissance Campaign
```bash
python run.py recon --target 127.0.0.1
```

### 2. Classify Open Ports via Verdict Engine
```bash
python run.py judge --target 127.0.0.1
```

### 3. Inspect Extensible Components (Algorithms, Modules, Rules)
```bash
python run.py info
```

### 4. Activate the Continuous Autonomous Daemon
```bash
python run.py daemon --target 127.0.0.1 --interval 15
```

### 5. Run the End-to-End Combat Simulation
```bash
python run_simulation.py
```

---

## 🗺️ Future Roadmap
Check our official [Project Roadmap](ROADMAP.md) for upcoming milestones, including P2P C2 Mesh networking and Ring 0 Kernel driver integration.

---

## 🧪 Automated Testing

Execute the comprehensive self-verification test suite:
```bash
python tests/smoke.py
```

---

## 🛡️ Security & Operational Notice

HELIOS-NET is an **dual-use offensive framework** designed strictly for authorized penetration testing, red teaming, and educational network research. Any unauthorized network targeting against third-party assets without explicit written consent is strictly prohibited and violates international computer fraud regulations.
