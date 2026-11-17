# HELIOS-NET :: Architecture

The canonical, maintained architecture document is
[docs/Architecture.md](docs/Architecture.md). It is the single description of the
component boundaries, the IPC/NDJSON contracts, and the native backend matrix.

Earlier revisions of this file described transport components that are not part
of the repository: raw SYN scanning, DNS tunnelling, in-memory execution,
direct-syscall evasion, and distributed consensus. Those descriptions were
removed with the code. If a component is ever removed again, remove its
documentation in the same change.

- Scope boundary: [docs/SCOPE-ENFORCEMENT.md](docs/SCOPE-ENFORCEMENT.md)
- Native IPC and NDJSON contract: [docs/IPC-CONTRACT.md](docs/IPC-CONTRACT.md)
- Typed asset graph: [docs/ASSET-GRAPH.md](docs/ASSET-GRAPH.md)
- Engineering roadmap: [ROADMAP.md](ROADMAP.md)
