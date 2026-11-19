<div align="center">

# HELIOS-NET
### Autonomous Attack Surface Management & High-Performance Scanning Engine

[![Release](https://img.shields.io/github/v/release/Ismail-Benali/HELIOS-NET?style=for-the-badge&label=release&color=black)](https://github.com/Ismail-Benali/HELIOS-NET/releases)
[![Stars](https://img.shields.io/github/stars/Ismail-Benali/HELIOS-NET?style=for-the-badge&label=stars&color=black&logo=github)](https://github.com/Ismail-Benali/HELIOS-NET/stargazers)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=for-the-badge)](LICENSE)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/Ismail-Benali/HELIOS-NET/build.yml?style=for-the-badge&label=build&logo=githubactions&logoColor=green)](https://github.com/Ismail-Benali/HELIOS-NET/actions)

<br>

[![Python](https://img.shields.io/badge/python-3.12-black.svg?style=for-the-badge&logo=python&logoColor=green)](https://www.python.org/)
[![Go](https://img.shields.io/badge/go-1.22-black.svg?style=for-the-badge&logo=go&logoColor=green)](https://golang.org/)

</div>

---

**HELIOS-NET** is a polyglot **Attack Surface Management (ASM)** and network-discovery orchestrator. Its Python control plane manages the campaign lifecycle; Go performs concurrent TCP discovery, C provides signature/fingerprint primitives, and Rust provides native graph and matching operations through a C ABI. The system follows a closed-loop cycle: discovery ➔ planning ➔ execution ➔ analysis ➔ reporting. See the [architecture](docs/Architecture.md) for the actual component boundaries.

> ⚠️ **Scope Notice:** HELIOS-NET is designed strictly for **authorized** penetration testing, network mapping, and educational research.

---

## 📑 Table of Contents

- [Core Capabilities](#-core-capabilities)
- [System Architecture](#-system-architecture)
- [Quick Start & CLI Usage](#-quick-start--cli-usage)
- [Automated Testing](#-automated-testing)
- [Honest Project Status](#-honest-project-status)
- [Technical References](#technical-references)

---

## ⚙️ Core Capabilities

1. **Closed-Loop Orchestration:** Manages campaign state, dependency planning, and parallel wave execution with absolute fault isolation.
2. **Encrypted Transactional WAL:** Crash recovery and secure transaction logging with PBKDF2 (100,000 iterations) stretched **once per log**, a per-record nonce, an HMAC-SHA256 counter-mode keystream, and separate encryption and MAC keys. Logs written by the earlier per-record-salt layout remain readable in place.
3. **Fail-Closed Scope Enforcement:** `core/scope.py` denies every target unless the scope file authorizes it. An unreadable, malformed, or `*` scope is an error, not a wildcard; the refusal names the reason.
4. **Scope-Bound Asset Discovery:** Expands seeds through Certificate Transparency, resolves each name, drops every address the scope does not authorize before a socket is opened, follows redirects only while every hop stays in scope, and records HTTP/TLS metadata, security headers, cookies, certificate expiry, and well-known documents (`--deep`).
5. **High-Performance Go Scanning:** Leverages thousands of lightweight Goroutines (`goscan`) streaming open ports via NDJSON through a long-lived `serve` worker, so repeated sweeps reuse the pool instead of paying process startup. Each sweep can bound its dial timeout, retry timeouts, pace request starts, and reports why a port was closed (`refused`, `timeout`, `unreachable`, `error`) in a per-sweep summary.
6. **Asset Graph & Risk Ranking:** Converts discoveries into an **Asset Graph**, computes Degree Centrality and betweenness, runs **Dijkstra's Algorithm** over weighted relationships, ranks assets with PageRank, and identifies articulation points and bridges that would split the topology.
7. **Verdict & Rule Engine:** Classifies findings using built-in rules or dynamic JSON-driven rules (Dynamic DSL).
8. **Executive HTML Reporting:** Generates self-contained dark-mode HTML executive briefing reports with full HTML escaping for XSS protection.
9. **Native Capability Contract:** `core/native_contract.py` is the single backend/capability matrix. `core/accel.py` derives what each backend advertises from it, every capability names its callable, `python run.py doctor` prints the matrix, and degraded or failed dispatches report their reason instead of an empty success.
10. **Interoperable Ingest and Reports:** Nmap XML imports as JSON Lines (`ingest`) under the same scope gate, exports are available as JSON, JSONL, CSV, or SARIF, and `report` builds a single-file, offline, filterable HTML view of a typed asset graph.

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
         +------------------+------------------+------------------+
         |    GO / NETWORK  |    C / MATCHING   |  RUST / GRAPH    |
         |    goscan        | signatures + FP  | graph + matcher  |
         +------------------+------------------+------------------+
                              ^
                              | UTF-8 IPC / C ABI
                              +-----------------------------------+
```

---

## Technical References

- [60-second local quickstart](docs/QUICKSTART.md)
- [Polyglot architecture and native-core health](docs/Architecture.md)
- [Internal API and module contracts](docs/API.md)
- [Scope enforcement and authorization boundary](docs/SCOPE-ENFORCEMENT.md)
- [Native IPC and NDJSON contract](docs/IPC-CONTRACT.md)
- [Typed asset graph contract](docs/ASSET-GRAPH.md)
- [Reproducible benchmarks](docs/BENCHMARKS.md)
- [Engineering roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)

---

## 🚀 Quick Start & CLI Usage

HELIOS-NET requires **zero external pip dependencies** for its core control plane.

Install the CLI as a command (`pipx` is preferred so it lives in its own
environment):

```bash
python -m pipx install .
helios version
```

Or run the wrapper, which checks for Python 3.12, uses `pipx` when available,
and otherwise falls back to a user install:

```bash
sh install.sh          # Linux and macOS
.\install.ps1          # Windows PowerShell
```

An installed command keeps campaign state in `~/.helios-net`
(`%USERPROFILE%\.helios-net` on Windows); set `HELIOS_DATA` to put it elsewhere.
The `python run.py ...` form remains the way to run an uninstalled checkout.

Build the native cores before installing if you want them inside the wheel:

```bash
python build.py
python -m pipx install --force .
```

The wheel build picks up the cores it finds in the checkout and packs them into
`core/native/` inside the artifact, so the resulting wheel is platform-tagged
(`py3-none-win_amd64`, `py3-none-linux_x86_64`, ...) and ships the Go, C, and Rust
binaries alongside the Python control plane. Installing from a checkout where
nothing was built produces a pure wheel; `helios doctor` then reports the cores
as unavailable and uses the Python fallback. The `wheel` CI job builds and
installs the artifact on Ubuntu and Windows and fails if a core does not load,
so the two cases are both tested. `tools/bundle_cores.py` can be run explicitly
when a build pipeline wants that step to be visible.

The version in `pyproject.toml` is `2.0.0b1` for this pre-release, so the
artifact names carry the matching tag:

```bash
python -m pip wheel . --no-deps -w dist
# dist/helios_net-2.0.0b1-py3-none-win_amd64.whl    (Windows x86-64, cores inside)
# dist/helios_net-2.0.0b1-py3-none-linux_x86_64.whl (Linux x86-64, cores inside)
# dist/helios_net-2.0.0b1-py3-none-any.whl          (pure Python, no cores)
python tools/verify_wheel.py --wheel "dist/*.whl" --require c rust go
```

`verify_wheel.py` installs the artifact in a throwaway virtual environment
outside the checkout and fails unless the C, Rust, and Go backends load from the
installed package.

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

### 5. Export and Analyze the Typed Asset Graph (Terminal)

Export the graph produced by scope-bound asset discovery:

```bash
python run.py assets --target example.test --ct --depth 1 --graph-output data/graphs/example-test.json
```

Run the native-backed topology analysis (Python is selected automatically if
the Rust library is unavailable):

```bash
python run.py graph analyze --input data/graphs/example-test.json
```

Request a shortest topology path between two asset IDs and save the complete
analysis as JSON:

```bash
python run.py graph analyze --input data/graphs/example-test.json --source-asset "host:ASSET_ID" --target-asset "ip:ASSET_ID" --json-output data/reports/graph-analysis.json
```

The IDs above are placeholders; use the exact IDs printed in the graph export.
The command performs no network activity. Rust analytics use an undirected
connectivity projection; typed direction, relationship kinds, and evidence
remain in the original graph and report. Use `--backend python` to force the
reference implementation or `--backend rust` to prefer the native library.

On Windows CMD, the included launcher avoids typing `python run.py`:

```bat
helios.cmd info
helios.cmd assets --target example.test --graph-output data\\graphs\\example-test.json
helios.cmd graph analyze --input data\\graphs\\example-test.json
```

From PowerShell or Windows Terminal, invoke it as `.\helios.cmd`. The
same `python run.py ...` commands also work in both shells.

Initialize the local data directory and a scope template (existing scope files
are never overwritten), then run the read-only environment check:

```bat
helios.cmd init
helios.cmd doctor
helios.cmd version
```

The shared `--data` and `--scope` options work on either side of a command:

```bat
helios.cmd status --data data
helios.cmd doctor --scope config\scope.yaml
```

`doctor` does not contact targets or modify files. Optional Go, Rust, and C
toolchains are reported separately; the Python control plane and a valid scope
configuration are the required checks. Review `config/scope.yaml` and add only
assets and ports you are authorized to test.

### 6. Run the End-to-End Simulation
```bash
python run_simulation.py
```

### 7. Import an Existing Nmap Scan

Collection can stay in Nmap; HELIOS-NET imports the XML without opening a
socket. Hosts and ports outside the authorized scope are dropped, and the
default keeps open ports only:

```bash
python run.py ingest --nmap scan.xml --output data/imports/scan.jsonl
python run.py ingest --nmap scan.xml --include-closed
```

The JSON Lines format is the same one `export` produces, so results from
separate tools can be concatenated and processed a record at a time:

```bash
python run.py export CAMPAIGN_ID --format jsonl > findings.jsonl
```

### 8. Build an Offline Interactive Report

`report` turns a typed graph export into one HTML file with filters for asset
type, relationship type, and free-text search. It has no external assets, no
CDN, and no server; every value is rendered as text, and the graph is embedded
as escaped JSON:

```bash
python run.py assets --target example.test --graph-output data/graphs/example-test.json
python run.py report --input data/graphs/example-test.json --output data/reports/example-test.html
```

Open the file directly from disk. This is the offline alternative to the
`dashboard` command, which serves a live local view.

---

## Performance Measurement

The numeric claims live in scripts rather than in this file. Live network
throughput comes from `tools/bench_scan.py`:

```bash
python tools/bench_scan.py --host 127.0.0.1 --ports 1-1024 --repeat 3
```

It reports the median wall time, ports/second, which backend answered, and the
spread across runs. It measures real sockets, so numbers depend on the host, the
open/closed mix, and whether the Go binary was built (`python build.py`).

Deterministic component costs (Nmap parsing, signature matching, fingerprinting,
graph centrality, report generation) come from `tools/bench.py`, which uses the
same synthetic input for every backend:

```bash
python tools/bench.py --repeat 5 --markdown
python tools/bench.py --backend python --json
```

The recorded run and its interpretation are in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md). Measure on the machine you care about;
absolute milliseconds are not portable.

---

## ✅ Automated Testing

Install the pinned development toolchain, then run the suite:

```bash
python -m pip install -r requirements-dev.txt
python build.py
python -m pytest -q
```

`python build.py` is not optional if you want the real numbers. Every skip in
this suite means a native core was not built on the host, and a skipped test
now **fails** the run unless you pass `--allow-skips`: `799 passed, 108
skipped` and `907 passed` are not the same claim, and only the second one
exercised the C, Rust and Go parity, FFI and golden tests.

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

`docker.yml` builds the container image on every pull request and `master` push,
runs `helios version` inside it, and publishes `ghcr.io/<owner>/<repository>` on
`v*` tags. It is a build check and release publisher, not a merge gate yet.

### Container image

`v2.0.0-beta.1` publishes
`ghcr.io/ismail-benali/helios-net:2.0.0-beta.1`, alongside `latest` and a
`sha-<commit>` tag:

```bash
docker run --rm ghcr.io/ismail-benali/helios-net:2.0.0-beta.1 version
docker run --rm -v "$PWD/data:/app/data" ghcr.io/ismail-benali/helios-net:2.0.0-beta.1 doctor
```

The image carries the Python CLI and its native cores, so no toolchain is
needed. It tracks a prerelease: pin the `sha-` tag or the digest, and mount the
data directory explicitly if you want campaign state to survive the container.

Coverage, Security (CodeQL, Trivy, Scorecards), Fuzz (nightly) and Release stay
in the repository but run manually (`workflow_dispatch`) while the pipeline is
being stabilized. They are not merge gates yet.

No automated check proves the project is free of vulnerabilities.

---

## 🛡️ Honest Project Status

**HELIOS-NET is a focused, research-grade Attack Surface Management and scanning framework.**

**Status: pre-release (`v2.0.0-beta.1`).** There is no stable release. An earlier
`v2.0.0` tag was withdrawn because the tree is under active development:
interfaces can change without a deprecation cycle, and nothing here is
supported for production use. Pin an exact commit, run it only against assets
you are authorized to test, and treat every result as evidence to verify rather
than a verdict.

An earlier generation of this repository advertised raw SYN transport, DNS
tunnelling, in-memory execution, direct-syscall evasion, and distributed
consensus. None of that code is present today. The tree contains:

| Layer | Present in this repository |
| --- | --- |
| Python | `core/` (scope, WAL, state, orchestration, reporting), `engine/` (graph, verdicts, risk scoring), `modules/` (discovery, recon, registry) |
| Go | `transport/goscan/` — concurrent TCP discovery and the NDJSON `serve` worker |
| C | `transport/c_core/` — Aho–Corasick/Boyer–Moore matching, hashing, and batch primitives |
| Rust | `rust-core/` — string matching and graph analytics through a C ABI |

The remaining helpers whose names suggest offensive use are offline or pacing
logic, not execution: `engine/killchain/pathfinder.py` ranks inspection routes
over an already collected asset graph (exposed as `graph analyze` with
`--source-asset`/`--target-asset`), and `modules/stealth/pacer.py` paces
requests. There is no payload, implant, C2 channel, credential-access code, or
evasion binary in this repository.

No component here exploits a vulnerability, and no automated check proves the
project is free of vulnerabilities.

The `v1.3.0` release notes predate this scope and describe components that are
no longer in the tree; [CHANGELOG.md](CHANGELOG.md) records what changed.

---

## License

HELIOS-NET is licensed under the **GNU Affero General Public License v3.0
only** (`AGPL-3.0-only`); see [LICENSE](LICENSE) for the full text. There is no
non-commercial clause: commercial use is allowed on AGPL terms, which require
that anyone offering a modified version over a network also offers its complete
corresponding source.

Authorized use is a project policy, not an extra license restriction. Run the
tool only against assets you own or have written permission to test; that rule
is in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md), and the
license grants no exception to computer-misuse law.

Contributions are accepted under `AGPL-3.0-only`; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the contribution terms. The change from
the earlier custom text is recorded in [CHANGELOG.md](CHANGELOG.md).
