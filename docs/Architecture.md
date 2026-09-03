# Polyglot Architecture & IPC

HELIOS-NET is engineered using a polyglot micro-kernel architecture, maximizing the strengths of Python, Go, and C:
- **Python:** Orchestration, state machines, closed-loop planning, and graph algorithms.
- **Go:** High-concurrency network operations, raw sockets, Goroutines port scanning, and polymorphic DNS tunneling.
- **C:** Memory-speed signature matching, direct system calls (Syscalls), API unhooking, and in-memory decryption.

IPC is handled via secure non-blocking `subprocess` execution pipes, exchanging structured JSON streams over stdin/stdout. Native binary failures are caught by Python, which triggers the mutation engine and routes around the failure without terminating the master orchestrator.
