# Evasion, Direct Syscalls & Sovereign Core

Operating in hostile enterprise environments requires military-grade evasion:
- **Direct Syscalls:** Bypasses user-mode API hooking by resolving NTDLL System Service Numbers (SSN) dynamically in memory.
- **Runtime XOR Decryption:** Defeats static YARA/AV rules by decrypting payloads in RAM at execution time.
- **Encrypted WAL:** Protects campaign logs with HMAC-SHA256 authenticated encryption at rest.
