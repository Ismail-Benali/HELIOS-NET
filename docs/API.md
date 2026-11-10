# HELIOS-NET :: Internal API and Module Contracts

This guide describes the contracts implemented by the current source tree. The
polyglot component map and native-core health model are documented in
[Architecture](Architecture.md). The scope boundary is specified in
[Scope Enforcement](SCOPE-ENFORCEMENT.md), and the byte-level process protocol
is specified in [IPC Contract](IPC-CONTRACT.md).

## Architectural boundaries

| Component | Responsibility | Boundary |
|---|---|---|
| `core/` | Campaign lifecycle, policy checks, planning, state, WAL, bridges | Owns orchestration and policy decisions |
| `engine/` | Asset graph, algorithms, verdicts, scanning utilities | Consumes findings; graph analysis itself is network-free |
| `modules/` | Discovery, asset metadata, recon, collection and extension runners | Must receive the campaign scope context before network work |
| `transport/goscan/` | Go TCP discovery worker | Process boundary; UTF-8 NDJSON |
| `transport/c_core/` | C signature/fingerprint core | Process boundary; line-oriented JSON |
| `rust-core/` | Native graph and signature operations | In-process C ABI via `ctypes`, not an NDJSON process |

Python core logic uses the standard library. Native components are optional at
runtime: bridges report backend availability and use documented Python
fallbacks where available. A fallback must not disguise a failed native
execution as a valid empty result.

## Campaign and module interface

The in-process module interface is:

```python
runner(step: PlanStep, context: dict[str, Any]) -> dict[str, Any]
```

A `PlanStep` carries `step_id`, `module`, `action`, `target`,
`priority`, `depends_on`, and a `params` mapping. The orchestrator passes a
shared campaign context containing findings, reports, the active
`ScopeEnforcer`, and the configured scope ports.

Rules for module authors:

1. Network-facing runners must use the supplied scope context and must not
   create a permissive scope when it is missing.
2. Target authorization is checked before the campaign executes its plan.
3. Requested `ports`, `web_ports`, and singular `port` parameters are checked
   against the campaign port allowlist before any planned step is run.
4. Asset expansion must independently verify each resolved address and each
   redirect destination; authorization of a DNS name does not authorize every
   address to which it resolves.
5. Keep findings and machine-readable results separate from diagnostics.
6. Add deterministic tests for both allowed and denied cases.

This in-process runner contract is not a claim that every Python module is an
independent stdin/stdout executable. Native process protocols are defined
separately below.

## Standardized Error Envelope (SEE)

A native component reports a machine-readable failure on stderr as one JSON
object per line:

```json
{"status":"error","code":"EDR_BLOCKED","message":"execution was blocked","component":"transport/goscan"}
```

The parser requires `status`, `code`, and `message`, and accepts only
objects whose status is `error`. The `component` field is recommended for
attribution. Human-readable diagnostics that are not SEE objects may coexist
on stderr and are ignored by the SEE parser.

Do not put findings, successful results, or protocol replies on stderr. Do not
emit diagnostics on stdout, because stdout is the machine protocol channel.

## Change control

A change to a shared contract must update its canonical document, bridge tests,
and every affected producer/consumer. Avoid introducing a second representation
of an existing field or silently changing fallback semantics.
