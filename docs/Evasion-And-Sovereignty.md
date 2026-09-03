# User-Mode Evasion, Direct Syscalls & In-Memory Execution

Operating in instrumented enterprise environments requires careful user-mode priming to stay within authorized engagement bounds:
- **Indirect Syscalls:** Bypasses user-mode API hooking by resolving NTDLL System Service Numbers (SSN) dynamically in memory.
- **API Unhooking:** Restores original NTDLL / kernel32 stubs to counter user-mode instrumentation.
- **In-Memory Decryption:** Defeats static YARA/AV rules by decrypting blobs in RAM at execution time.
- **In-Memory Execution:** Reflectively loads and executes encrypted payloads without touching disk.
- **Encrypted WAL:** Protects engagement logs with HMAC-SHA256 authenticated encryption at rest.

> **Design note:** Evasion is intentionally confined to **user mode (Ring 3)**. No kernel-mode (Ring 0) drivers are included or planned — user-mode primitives above are sufficient for authorized red-teaming engagements and avoid the certification and patch-guard complexity of kernel drivers.
