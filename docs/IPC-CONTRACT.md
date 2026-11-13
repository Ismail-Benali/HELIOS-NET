# Native IPC and NDJSON Contract

This document is the canonical process-boundary reference for HELIOS-NET.
The architecture overview lives in [Architecture](Architecture.md).

## Transport rules

- Encoding is UTF-8 on stdin, stdout, and stderr.
- stdout is reserved for protocol data only.
- stderr carries diagnostics and Standardized Error Envelopes (SEE).
- NDJSON means one complete JSON object per line; a line must not contain
  embedded raw newlines.
- A producer must flush each response line when the consumer expects streaming.
- A consumer must reject malformed JSON, unexpected top-level types, missing
  required fields, and mismatched request identifiers.
- Timeouts and process termination must become explicit failures, never a
  successful empty result.

## Go scanner

The Go scanner supports a long-lived `serve` worker. The Python bridge sends
one JSON request per line and expects one JSON object response per request.
The bridge correlates the response using the request `id` and reads its
`results` list. A missing line, malformed JSON, non-object response,
mismatched id, worker timeout, or explicit error is a scanner failure.

The request and response are intentionally treated as a request/reply contract,
not as an uncorrelated stream of findings. See
`modules/discovery/goscan_bridge.py` for the consumer implementation and the
Go worker source for the producer.

## C signature and fingerprint core

The C command-line front end consumes line-delimited JSON requests and returns
one JSON result object per input line on stdout. Error envelopes and diagnostics
belong on stderr. The process bridge is implemented in
`core/c_core_bridge.py`.

## Rust core

The Rust core is loaded as a shared library through a C ABI and
`ctypes` (`core/rust_bridge.py`). It is not a subprocess and must not be
documented as an NDJSON transport. ABI pointer/length pairs are trust
boundaries: callers must pass the actual buffer length, and native entry points
must validate their own allocation/resource limits.

## Standardized Error Envelope

The minimum parser contract is:

```json
{"status":"error","code":"CORE_UNAVAILABLE","message":"worker failed"}
```

The `component` field should be included by producers to identify the failing
component:

```json
{"status":"error","code":"CORE_UNAVAILABLE","message":"worker failed","component":"transport/goscan"}
```

The current Python parser requires `status`, `code`, and `message`, and
accepts only `status: error`. It does not require `component`. Consumers
must preserve the distinction between a genuine empty result and a failed or
unavailable backend.

## Versioned capability and result registry

`core/native_contract.py` publishes the additive capability registry
(`contract_version: 1.0.0`). It describes supported operations separately
from host availability and preserves each backend's actual boundary:

| Backend | Boundary | Capabilities |
| --- | --- | --- |
| Go | NDJSON process | `scan_ports` |
| C | NDJSON process or FFI | `match`, `fingerprint` |
| Rust | C ABI | `match`, `fnv1a32`, graph operations |
| Python | in-process | Reference/fallback implementations |

Registry states are `ready`, `fallback`, `blocked`, `failed`,
`unavailable`, and `unsupported`. An unsupported operation is not the same
as an unavailable backend; a host policy refusal is not the same as a missing
binary. Python is identified as a fallback rather than being presented as a
native backend.

`normalize_outcome(capability, outcome)` provides a stable reporting envelope
with `contract_version`, `capability`, `status`, `backend`, `reason`,
and `result`. Its statuses distinguish native success, degraded Python
fallback, failed execution, and unavailable execution. Existing typed outcome
classes and the Go/C/Rust transports remain unchanged; this is an additive
serialization contract.

## Compatibility and change policy

Any change to field names, framing, encoding, exit codes, or failure semantics
must update both producer and consumer in the same change. Add contract tests
for valid records, malformed records, missing fields, non-ASCII payloads,
multiple lines, worker restart, timeout, and request-id mismatch. Do not infer
a successful empty result from a non-zero exit code or missing response.
