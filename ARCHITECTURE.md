# HELIOS-NET :: Polyglot Cyber Warfare Architecture Blueprint

> **System Designation:** Autonomous Offensive Reconnaissance & Cyber Warfare Framework  
> **Architecture Style:** Polyglot Micro-Kernel & Sensor Mesh  
> **Core Languages:** Python 3.12 (Orchestration & AI), Go (High-Concurrency Networking & Transport), C (Low-Level Sovereignty, Evasion & Memory Execution)

---

## Architectural Topology

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

## Polyglot Component Breakdown

### 1. The Mind (Python Core Layer)
Responsible for state orchestration, intelligence planning, decision making, and AI/Graph analytics.
* **`core/orchestrator.py` & `planner.py`:** Manages closed-loop intelligence cycles, dividing campaigns into parallel dependency waves.
* **`core/wal.py`:** Encrypted Transactional Write-Ahead Log (WAL) with HMAC-SHA256 integrity and atomic `BEGIN/COMMIT` operations.
* **`engine/graph/core.py`:** Converts raw discoveries into an Asset Graph and calculates Degree Centrality to isolate high-value target assets.
* **`engine/killchain/pathfinder.py`:** Implements Dijkstra's algorithm to calculate the Least Resistance Attack Path and simulates automated multi-step Kill-Chain plans.
* **`core/mutation_engine.py`:** Autonomous self-healing engine that detects WAF/Honeypot traps, shreds local footprints, and triggers polymorphic mutation.
* **`core/daemon.py`:** Continuous background execution daemon enabling zero-touch autonomous missions.

### 2. The Muscle & Network (Go Transport Layer)
Handles high-concurrency packet generation, raw socket communications, and distributed consensus without Python GIL bottlenecks.
* **`transport/goscan/goscan.go`:** High-performance concurrent TCP port scanner powered by thousands of lightweight Goroutines.
* **`transport/rawsocket/rawsync.go`:** Low-level raw socket engine that dispatches raw TCP SYN packets and listens for SYN-ACK/RST responses.
* **`transport/tunnel/covert.go`:** Encrypts streams with AES-GCM and wraps data into polymorphic random-padded DNS queries to bypass DPI.
* **`core/consensus/raft.go`:** Raft-lite consensus state machine for decentralized node state synchronization.

### 3. The Sovereign Core (C Low-Level Layer)
Executes memory-speed pattern matching, anti-EDR evasion, system syscall manipulation, and kernel-level control.
* **`transport/c_matcher/c_matcher.c`:** Zero-allocation, pointer-level signature analyzer operating at SIMD/memory bandwidth speed.
* **`transport/evasion/evasion.c` & `direct_syscalls.c`:** Bypasses user-mode API hooking via direct NTDLL SSN resolution and runtime XOR decryption.
* **`transport/harness/protocol_fuzzer.c` & `verifier.c`:** Stateful protocol handshake verifier confirming service vulnerabilities with absolute precision.
* **`transport/rootkit/kernel_filter.c`:** Ring 0 Windows Filtering Platform (WFP) driver skeleton for kernel-level network interception.

---

## Inter-Process Communication (IPC) & Integration

Python orchestrates the Go and C binaries via secure, non-blocking `subprocess` execution pipes. Data is exchanged via structured JSON streams over standard input/output (`stdout`), ensuring absolute fault isolation: if a native binary crashes or hits an EDR wall, Python catches the exception, triggers the mutation engine, and routes around the failure without terminating the master orchestrator.
