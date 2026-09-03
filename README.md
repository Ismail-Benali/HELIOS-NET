# HELIOS-NET — Autonomous Red Teaming & Attack Surface Management Orchestrator

<img width="1792" height="592" alt="Helios-Net" src="https://github.com/user-attachments/assets/eb7d5c73-ee03-4500-bc95-45269d7afec6" />

[![GitHub Actions](https://img.shields.io/badge/github-actions-black.svg?style=for-the-badge&logo=githubactions&logoColor=green)](https://github.com/Ismail-Benali/HELIOS-NET)
[![Python](https://img.shields.io/badge/python-3.12-black.svg?style=for-the-badge&logo=python&logoColor=green)](https://www.python.org/)
[![Go](https://img.shields.io/badge/go-1.27-black.svg?style=for-the-badge&logo=go&logoColor=green)](https://golang.org/)
[![C](https://img.shields.io/badge/c-gcc-black.svg?style=for-the-badge&logo=c&logoColor=green)](https://gcc.gnu.org/)

**HELIOS-NET** is an enterprise-grade, autonomous polyglot orchestrator for **red teaming** and **attack surface management (ASM)** engagements. Designed around a **Closed-Loop Intelligence Cycle** (Reconnaissance ➔ Planning ➔ Execution ➔ Analysis ➔ Adaptation), HELIOS-NET eliminates external dependencies, relying entirely on Python stdlib for control orchestration, high-performance Go binaries for concurrent networking, and low-level C binaries for user-mode evasion primitives and in-memory execution.


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
        |          C USER-MODE PRIMITIVES (GCC -O3) |
        | - c_matcher.exe (Memory Matcher)          |
        | - fingerprint.exe (TTL OS Engine)         |
        | - evasion.exe (Indirect Syscalls)         |
        | - memory_loader.exe (In-Memory Exec)      |
        | - verifier.exe (Protocol Fuzzer)          |
        +------------------------------------------+
```

## ⚙️ What HELIOS-NET Does (Core Capabilities)

1. **Closed-Loop Orchestration:** Manages engagement state, dependency planning, and parallel wave execution with absolute fault isolation.
2. **High-Performance Go Networking:** Leverages thousands of lightweight Goroutines (`goscan.exe`, `rawsync.exe`) to conduct high-speed port scans and raw-socket handshakes.
3. **Automated Pathfinding:** Converts raw discoveries into an **Asset Graph**, computes Degree Centrality, and runs **Dijkstra's Algorithm** to calculate the Least Resistance path.
4. **User-Mode Evasion & Syscalls:** Bypasses user-mode API hooking via indirect NTDLL SSN resolution (`direct_syscalls.exe`) and executes runtime in-memory decryption.
5. **Autonomous Self-Healing & Tuning:** Detects bogus/honeypot traps, shreds local temporary footprints securely, rotates encryption keys, and re-targets automatically.
6. **Encrypted Transactional WAL:** Guarantees crash recovery and zero data loss with at-record HMAC-SHA256 authenticated encryption.
7. **Continuous Autonomous Daemon:** Operates as a background agent (`daemon.py`) running continuous recon and self-monitoring loops.

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

### 5. Run the End-to-End Demonstration
```bash
python run_simulation.py
```

## 🗺️ Future Roadmap
Check our official [Project Roadmap](ROADMAP.md) for upcoming milestones, including P2P mesh networking and advanced user-mode evasion primitives.


## 🧪 Automated Testing

Execute the comprehensive self-verification test suite:
```bash
python tests/smoke.py
```

## 🛡️ Security & Operational Notice

HELIOS-NET is a **dual-use security framework** designed strictly for authorized penetration testing, red teaming, and educational network research. Any unauthorized network targeting against third-party assets without explicit written consent is strictly prohibited and violates international computer fraud regulations.
