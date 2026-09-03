# HELIOS-NET :: Polyglot Red Teaming & ASM Architecture Blueprint

> **System Designation:** Autonomous Attack Surface Management & Red Teaming Orchestrator  
> **Architecture Style:** Polyglot Micro-Kernel & Sensor Mesh  
> **Core Languages:** Python 3.12 (Orchestration & Planning), Go (High-Concurrency Networking & Transport), C (User-Mode Evasion Primitives & In-Memory Execution)

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
        |          C USER-MODE PRIMITIVES (GCC -O3) |
        | - c_matcher.exe (Memory Matcher)          |
        | - fingerprint.exe (TTL OS Engine)         |
        | - evasion.exe (Indirect Syscalls)         |
        | - memory_loader.exe (In-Memory Exec)      |
        | - verifier.exe (Protocol Fuzzer)          |
        +------------------------------------------+
```

---

## Polyglot Component Breakdown

### 1. The Mind (Python Core Layer)
Responsible for state orchestration, planning, decision making, and graph analytics.
* **`core/orchestrator.py` & `planner.py`:** Manages closed-loop intelligence cycles, dividing engagements into parallel dependency waves.
* **`core/wal.py`:** Encrypted Transactional Write-Ahead Log (WAL) with HMAC-SHA256 integrity and atomic `BEGIN/COMMIT` operations.
* **`engine/graph/core.py`:** Converts raw discoveries into an Asset Graph and calculates Degree Centrality to isolate high-priority assets.
* **`engine/killchain/pathfinder.py`:** Implements Dijkstra's algorithm to calculate the Least Resistance path and models multi-step engagement plans.
* **`core/mutation_engine.py`:** Autonomous self-healing engine that detects bogus/honeypot traps, shreds local footprints, and triggers re-targeting.
* **`core/daemon.py`:** Continuous background execution daemon enabling zero-touch autonomous monitoring.

### 2. The Network (Go Transport Layer)
Handles high-concurrency packet generation, raw socket communications, and distributed consensus without Python GIL bottlenecks.
* **`transport/goscan/goscan.go`:** High-performance concurrent TCP port scanner powered by thousands of lightweight Goroutines.
* **`transport/rawsocket/rawsync.go`:** Low-level raw socket engine that dispatches raw TCP SYN packets and listens for SYN-ACK/RST responses.
* **`transport/tunnel/covert.go`:** Encrypts streams with AES-GCM and wraps data into polymorphic random-padded DNS queries.
* **`core/consensus/raft.go`:** Raft-lite consensus state machine for decentralized node state synchronization.

### 3. The User-Mode Primitive Layer (C Low-Level)
Executes memory-speed pattern matching, anti-instrumentation evasion, direct syscall invocation, and in-memory execution.
* **`transport/c_matcher/c_matcher.c`:** Zero-allocation, pointer-level signature analyzer operating at memory bandwidth speed.
* **`transport/evasion/evasion.c` & `direct_syscalls.c`:** Indirect syscall resolution and runtime in-memory decryption that bypass user-mode hooking.
* **`transport/c_loader/memory_loader.c`:** Reflectively loads and executes encrypted blobs entirely in memory.
* **`transport/harness/protocol_fuzzer.c` & `verifier.c`:** Stateful protocol handshake verifier confirming service behavior for authorized testing.

---

## Inter-Process Communication (IPC) & Integration

Python orchestrates the Go and C binaries via secure, non-blocking `subprocess` execution pipes. Data is exchanged via structured JSON streams over standard input/output (`stdout`), ensuring absolute fault isolation: if a native binary crashes or hits an EDR wall, Python catches the exception, triggers the mutation engine, and routes around the failure without terminating the master orchestrator.
