# Polyglot Architecture & IPC

HELIOS-NET is engineered as a polyglot architecture across four languages, each
selected for a specific strength:

- **Python — control plane.** Orchestration, campaign state, dependency planning,
  asset graphing (Dijkstra / Degree Centrality), verdict classification, and
  executive HTML reporting.
- **Go — network plane.** High-concurrency TCP port scanning and banner grabbing
  using bounded worker pools and NDJSON streaming (`transport/goscan`).
- **C — hot-path primitives.** A self-contained C11 signature & fingerprint
  core (`transport/c_core`): Boyer-Moore-Horspool single-pattern search with the
  Galil optimisation, a sparse Aho-Corasick multi-pattern automaton, FNV-1a
  32/64 and CRC-32 digests, and a streaming NDJSON CLI front end.
- **Rust — native acceleration.** Graph pathfinding plus native signature matching
  exposed as a C-ABI shared library (`rust-core`), consumed from Python through
  `core/rust_bridge.py` via `ctypes`.

## Native module map

| Module | Entry point | Role |
|---|---|---|
| `transport/goscan` | `goscan match <sigfile>` | Go port scanner, NDJSON stream |
| `transport/c_core` | `helios_core match\|fp\|selftest` | C signature & fingerprint core |
| `rust-core` | `helios_match_signatures` (C-ABI) | Rust signature matching, loaded by ctypes |

## IPC contracts

All native components communicate over `stdin`/`stdout` using structured JSON
(NDJSON for streaming components). Go components stream one result object per
line; the C core returns one JSON object per input line. Failures are reported
as a standardized **Error Envelope (SEE)** on stderr:

```json
{"status": "error", "code": "EDR_BLOCKED", "message": "...", "component": "transport/goscan"}
```

SEE lines are parsed by `core/envelope.py`.

**Encoding.** The native contract is UTF-8 on both directions. Python callers
must pin `encoding="utf-8"` on every subprocess pipe — relying on `text=True`
alone uses the host locale (cp1252 on Windows) and would hash non-ASCII banners
as different bytes than the pure-Python fallback. Banners containing newlines are
flattened to spaces before transmission, since NDJSON is line-delimited.

## Graceful degradation

No native core is a hard dependency. Each bridge detects a missing, unbuilt, or
host-blocked binary and falls back to a pure-Python path:

| Core | Bridge | Fallback |
|---|---|---|
| Go `goscan` | `modules/discovery/goscan_bridge.py` | records the reason in `LAST_ERROR`, raises in `strict=True` |
| C core | `core/c_core_bridge.py` | Python digests + Python substring match |
| Rust core | `core/rust_bridge.py` | `engine/pattern_matcher.py` uses its Aho-Corasick automaton |

A native fault therefore degrades that single module; it never terminates the
orchestrator or drops the campaign.

### An empty result is not a failure

A graceful fallback has a cost: a broken core becomes indistinguishable from a
healthy one. That is not hypothetical. The Go scanner shipped with an unseeded
worker semaphore, so every call deadlocked, and its bridge returned `[]` for the
deadlock exactly as it would for a host with nothing open.

Two rules keep the distinction observable:

1. A bridge never reports an empty result set for a core that did not run. The Go
   bridge records the cause in `goscan_bridge.LAST_ERROR` and raises
   `GoscanError` when called with `strict=True`. An empty list is trustworthy
   only when `LAST_ERROR is None`.
2. "Present" is never treated as "working". See the core health contract below.

## Core health contract

`core/cores.py` probes all four languages and is the single place that reports
their state. `build.py --test` and CI both run it, so a core cannot quietly stop
working.

Each core is asked three separate questions, and the answers are not collapsed:

| Question | Meaning |
|---|---|
| Present | a built artefact exists on disk |
| Loadable | the artefact can be initialised (library loaded, binary runnable) |
| Working | it self-tests successfully from Python |

States:

| State | Meaning | Pipeline result |
|---|---|---|
| `ok` | present, loadable, and self-tested | pass |
| `fallback` | never built or not present on this runner | pass, Python path covers it |
| `blocked` | present, but the host refused to execute it | pass, and flagged |
| `failed` | present and loadable, but the self test failed | **fail** |

`failed` is the state that matters. A core that is shipped and advertised but
cannot execute is a defect, and it fails the build. `blocked` is kept separate on
purpose: a host application-control policy refusing a freshly linked unsigned
binary is an environment condition, not a code defect, and folding it into
either pass or fail would be dishonest in both directions.

Every native core publishes the same self-test shape, so the three can be
compared directly:

```json
{"status": "ok", "checks": 19, "failures": 0, "version": "..."}
```

Current coverage: Go 30 unit tests plus 4 fuzz targets and a 19-check self test;
Rust 73 tests (31 in-library, 21 property, 21 C-ABI) plus an in-library self
test; C 297 native checks, 31,886 differential-fuzzer checks, and a 19-check
self test.

## Verification layers

`python build.py --test` is the gate, and it exits non-zero when any stage fails.
It runs, per language: `gofmt -l`, `go vet`, `go test`, `go test -race`, the Go
fuzz targets, `cargo clippy --all-targets`, `cargo test`, the C unit suite, and
the C differential fuzzer, then the unified health probe.

Two properties of that gate are worth stating because they were defects:

- **A failing stage must fail the process.** The pipeline used to print
  `Failing stages` and still exit 0, so CI reported green over a broken core.
- **`blocked` must survive the bridge.** Both native bridges used to catch
  `OSError` and return a "no report" value, which turned a WinError 4551
  application-control refusal into `failed` and failed the build for an
  environment condition. The `winerror` only reaches the classifier through the
  exception, so the bridges now let it propagate.

Fuzzing is opt-in via `--fuzz=<seconds>` because it is time-based; CI bounds it
to 20 seconds per target on Linux and skips it on Windows.

### Differential fuzzing and the absence of local sanitizers

The C core has no `libFuzzer`, and the MinGW toolchain in use has no `libasan`
(`cannot find -lasan`). Two substitutes are wired in:

- `transport/c_core/tests/fuzz_harness.c` compares every randomised Aho-Corasick
  and Boyer-Moore search against a naive oracle written independently in C, and
  runs every output call against a heap buffer padded with guard bytes. It is
  deterministic, so CI cannot flake and a failure reproduces exactly.
- The GitHub workflow additionally builds both the C unit suite and the fuzzer
  with `-fsanitize=address,undefined` on Linux. This is configured, not
  observed: see "Platform support" below for why that distinction matters and
  why no local run can stand in for it.

The guard-byte approach is not a substitute for a memory sanitizer; it catches
overruns of the specific buffers it wraps. That is still the class of defect that
mattered here, and it found three real bugs the hand-written suite missed,
including a one-byte overflow when a caller passed a zero-capacity output
buffer. GCC's `-fanalyzer` is a separate static pass and is not counted as
runtime checking.

### Strict C warnings

The C core is compiled with `-Werror` and 17 warning flags, not just
`-Wall -Wextra`. The extra flags cover the mistakes that actually matter in C:
`-Wcast-qual` and `-Wcast-align` for size truncation, `-Wshadow` for a length
variable being reused, `-Wwrite-strings` for a literal written through a mutable
pointer, `-Wformat=2` for mismatched format arguments. All five sources are
clean under the full set.

## Known divergences between engines

### Duplicate signature registration

A signature file line is `name<TAB>pattern`, and the two engines model that
differently, so "duplicate" means different things to each. The rule that was
adopted is that **de-duplication is on the (name, pattern) pair, not the
pattern alone**:

- Two *different* names sharing one pattern, such as `alpha<TAB>foo` and
  `beta<TAB>foo`, are two real signatures. Both are reported, and
  `match_count` is 2. Dropping `beta` would discard a signature the operator
  explicitly wrote, which is information loss rather than de-duplication.
- The *same* line repeated is a duplicated input and is stored once. Before this
  rule, a repeated line made a single detection emit the same name twice and
  report `match_count: 2`, inflating every aggregate computed from it. This is
  the same defect the Go port's `dedupePorts()` had, and it was equally
  untested on this side: the C fuzzer exercises the search primitives, not the
  signature-loading path.

The native core signals this with `HC_ERR_DUP` rather than `HC_OK`, because the
signature-file loader counts successful adds and would otherwise report the
duplicate as loaded. The Python fallback mirrors it in `_load_signatures`.

The Rust port de-duplicates by pattern alone, so it reports the first name and
drops the rest. That is **correct for its own contract**: `Aho::add` takes a
single label with no name/pattern split, and its only production caller,
`pattern_matcher.all_patterns()`, already de-duplicates before calling it. It
is therefore left unchanged. The two ports are not compared directly on this
input; the equivalence that matters is that the two C paths, native and
fallback, never diverge from each other.

A signature file containing a UTF-8 BOM, which is what PowerShell 5.1 and
Notepad produce by default, used to fold the BOM into the first signature name.
That is fixed now, on both paths: the native loader in
`transport/c_core/src/main.c` strips a leading `EF BB BF` from the first line
before any parsing, and `core/c_core_bridge.py` reads the same file with
`encoding="utf-8-sig"`. Both paths are covered by regression tests, so a
BOM-prefixed file now yields a clean first name instead of a corrupted one.

### ABI length arguments are a trust boundary

The Rust graph entry points take a `*const u32` plus a count. A raw pointer
carries no length, so a count larger than the caller's buffer is undefined
behaviour before any internal limit is reached. `MAX_NODES` is a genuine safety
bound because it guards this library's own allocation; `MAX_EDGES` is only a
resource bound. The caller, `core/rust_bridge.py`, passes the true length.

## Fallback equivalence

The C fallback is held to an equivalence standard by
`tests/test_c_core.py::test_native_digests_match_python_fallback`, which asserts
that native and Python paths produce byte-identical FNV-1a 32/64, CRC-32, and
match sets for the same input. A degraded campaign must never yield different
fingerprints than a healthy one.

The Rust and C parity tests are deliberately strict about *ordering* and about
isolated graph nodes, not just about set membership. Both defects were found
this way: the Rust Aho-Corasick automaton emitted matches in BFS order rather
than text order, silently dropping suffix matches from the Python-visible
result, and the Python `degree_centrality` reference omitted isolated nodes.

## Verifying the C contract on a host that cannot run the C core

A host application-control policy - Smart App Control, AppLocker, WDAC - may
refuse to execute a freshly built unsigned native image. This is not a defect to
work around and the code cannot decide its way out of it: the refusal is
`WinError 4551`, Code Integrity records `did not meet the Enterprise signing
level requirements`, and the verdict is permanent for that image. It is not
specific to one toolchain. A `cdylib` built by rustc seconds earlier is refused
exactly like a MinGW binary, while a Go binary and a Rust DLL that have been on
the machine for some time load normally, so what the policy weighs is the image's
standing, not its language or its exports. The supported answer is a valid code
signature, which `build.py` applies to every native artifact as it is built and
verifies afterwards; see `Signing.md`. The C core's *results* are made portable
independently, by carrying its contract as data.

That leaves one failure mode with no defence. The Python fallback is an
independent implementation of a byte-offset, ASCII-folded, overlap-preserving
matcher. If it ever diverges, a degraded campaign reports different detections
from a healthy one, and the only machine that could have noticed is the one
whose policy stopped it from asking. The C differential fuzzer does not cover
this: it compares the C core against an oracle written in C, so it cannot see a
disagreement between the C core and the code that stands in for it.

So the C core's answers are captured as data and travel with the repository:

- `tests/c_reference_corpus.py` - 17 matching cases (byte offsets across
  multi-byte text, ASCII-only folding, overlapping hits, suffix inheritance,
  significant whitespace, truncation boundaries) and 12 signature-parser cases.
- `tests/golden/c_reference.json` - the native core's recorded answers.
- `tools/gen_c_reference.py` - regenerates them; `--check` re-derives and fails
  on any difference.
- `tests/test_c_reference_golden.py` - replays the goldens against whatever this
  machine can run, and requires every native path that *does* run to reproduce
  them as well.

Two halves make the guarantee hold. Every machine, blocked or not, verifies its
own in-process path against the goldens, with no native execution at all. And CI
runs the real C core over the same corpus, so the goldens cannot quietly stop
describing the C core. The parser expectations are hand-written from
`main.c`'s documented behaviour rather than recorded from a run, because a golden
that only records what the code did today cannot tell a correct behaviour from an
incorrect one.

## Which engine produced a result

A result that does not say how it was produced cannot be audited. Two places
previously failed to say it:

- `AhoCorasickMatcher.match()` returned dicts of identical shape from the Rust
  and the Python path. A result produced while the Rust core was blocked by
  host policy was therefore indistinguishable from a native one, which meant a
  report could claim native performance it did not have. Every match now
  carries an `engine` key, `rust-native` or `python-fallback`, and the matcher
  records why it degraded in `last_engine_reason` instead of discarding the
  exception. This aligns the shared matcher with the C bridge, which already
  labelled its own fallback.
- The Go bridge used to fall back to `"service": "tcp-native"` when the core
  did not identify a service. That string reads like a detection the core made,
  but it was a label the bridge invented. An unidentified service is now an
  empty field, which is the falsy value the existing consumers already handle
  and which the service graph in `modules/core.py` already keys off.

## The in-process front end, and what it is worth

The C core is reached two ways, and they used to be the same way:

| Path | Mechanism | Cost per batch | Cost per banner |
|---|---|---|---|
| `process` | `subprocess` → `helios_core match` | one process, one signature-file read, **one automaton rebuild** | included in the batch |
| `ffi` | `ctypes` → `helios_core.dll` | **none after the first** | one call into C |

`hc_ac_build` is 484 lines of automaton construction and is the single most
expensive operation in the matcher. The process path paid it once per batch
because the front end read the signature file and built the automaton inside
each process. The in-process path builds it once and keeps it, keyed on the
signature file's mtime so an edited file is not matched against the previous
automaton.

### Why the logic moved out of `main.c`

`load_signatures`, `on_match` and the JSON encoder were `static` helpers in
`main.c`, so the reusable half of the front end was reachable only by running the
executable. They now live in `helios_batch.c` and both front ends call them.

This is the part that matters more than the speed. Two implementations of the
parser and the encoder would be two sets of answers to one contract, and a
divergence between them is indistinguishable from a bug in either. The same
reasoning applies to the consistency checks: an earlier draft of `helios_dll.c`
carried its own copy of the selftest suite and was **already weaker** than the
CLI's — missing the truncation, empty-pattern and scan-before-build cases. That
makes the narrower copy the in-process gate, and it would have passed while the
real suite failed. Both copies are gone; `hc_selftest_run` is the only definition.

### Honest reporting

`native_path()` returns `ffi`, `process` or `python`, and results carry it in
`reason`. `ffi_available()` requires the library to load **and** to pass that
shared selftest — loading alone is not health, and reporting availability from the
load alone would repeat the original defect at a new address: a
usable-looking handle answering with the wrong numbers.

A batch is served by one backend or not at all. If a single banner fails
in-process, the whole batch falls through to the next front end, because a list
mixing two implementations' entries is indistinguishable from a correct one.

### What is verified, and where

| Property | Enforced by | Runs on this host? |
|---|---|---|
| Python marshalling, handle reuse, buffer release, batch integrity | `tests/test_c_core_ffi.py` (16 tests, stand-in library) | **yes** |
| The C code compiles and runs, and the FFI serves real requests | `In-Process Core (FFI) Actually Serves Requests` in CI | **no** |
| C behaviour under ASan/UBSan | `C Sanitizers` stage | **no** |
| The C core still answers the recorded contract | `gen_c_reference.py --check` | via Rust re-derivation |

The C half is deliberately **not claimed** as verified locally. On a host whose
application-control policy blocks the compiler, it cannot be, and a summary that
implied otherwise would be the same error in a different costume.

## Known unverified state

Recorded so the next reader does not mistake these for regressions:

- `transport/c_core/build/*.exe` are **stale**: they predate `helios_batch.c`,
  `helios_dll.c` and `helios_batch.h`. They are correctly reported as unusable by
  the staleness check and refused rather than used. Rebuilding requires a working
  C toolchain.
- On such a host the C refactor has never been compiled. The JSON contract is
  preserved *textually* — the format strings in `helios_batch.c` are identical to
  the ones they replaced — but textual identity is not compilation.
- CI compiles and runs it before the FFI stage, so a compile error or a contract
  change fails the pipeline.

## Static analysis: what is enforced and what is not

Two CI steps previously ended in `|| true`, which discards the exit status. The
pipeline reported green regardless of the result, so a green build claimed a
type and security review that had not actually happened. Both are now
enforced, at different strengths, and neither is claimed to be stronger than it
is:

- **Bandit** runs as `bandit -r core/ modules/ engine/ -ll` with no
  suppression of the exit status. At medium severity and above the tree is
  clean today, so the check is genuinely green and can genuinely fail on a
  future finding. Only low-severity items exist and they are not gated.
- **mypy `--strict` is clean.** Zero errors across `core/`, `engine/`, `modules/`
  and `cli/`. This was not true when the check was first enforced, and the honest
  options at the time were to fix the errors or to baseline them. Baselining was
  the weaker promise, so the errors were fixed instead: 74 bare generics gained
  explicit parameters, 26 untyped definitions were annotated, and the resulting
  cascade of untyped calls disappeared with them.

  Fixing them surfaced two real defects that had been dormant, which is the main
  argument for doing the work rather than baselining it. `stealth_runner` called
  `Pacer(base_dwell=...)` while the constructor argument is `mean_dwell`, so the
  module raised `TypeError` on every execution and had therefore never run. And
  `verdict.py` and `async_engine.py` used `Path` and `List` in annotations before
  importing them; those survived only because `from __future__ import annotations`
  defers evaluation, and would have failed under `typing.get_type_hints`.

  One caveat stated plainly: `dict[str, Any]` was used for genuinely
  heterogeneous payloads such as findings and envelopes. That is a real
  annotation rather than a bare `dict`, but it records that those structures are
  not schema-checked, not that they are.

## Platform support: what has actually been executed

The CI matrix covers **Ubuntu and Windows only**. There is no macOS job. The
Linux-specific stages in `build.yml`, including the C `ASan`+`UBSan` stage and
the Go race detector, are configured but have not been observed passing, because
no local Linux environment has run them. Portability beyond the two matrix
entries is untested rather than supported, and nothing in this repository should
be read as a claim that it is.

The C sanitizer stage is also blocked locally on this machine: the available
GCC has no `libasan` or `libubsan`, so it fails at link time with
`cannot find -lasan`. The stage therefore uses clang when it is present and
falls back to GCC otherwise, and a Linux CI run remains the only way to prove
it.
