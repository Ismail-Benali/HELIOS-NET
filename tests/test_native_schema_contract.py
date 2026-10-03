"""Static contract between the Python consumers and the Go native core.

Every other test in this suite feeds the bridge JSON that a test author wrote.
That is circular: it proves the parser handles what we already believe the
producer emits, and proves nothing about the producer.

The failure this file exists to prevent is measured, not hypothetical. If the
`open` tag in goscan.go were renamed to `is_open`, `data.get("open")` returns
None, the filter drops every port, and the bridge reports:

    ([], None)

i.e. "the core ran successfully and found nothing open" while in fact the core
found everything. No exception, no LAST_ERROR. That is precisely the ambiguity
this module's own docstring says it was written to remove.

So these tests read the Go source and the Python source and check they agree,
in both directions:

  * a key the bridge reads must be one the Go core emits;
  * a key the bridge reads without a default must not be omitempty;
  * every key core/envelope.py requires must be in the Go error struct;
  * every key the health check reads must be in the Go selftest report;
  * the bridge may only invoke subcommands the Go main() dispatches.

The reverse direction matters as much: adding `data.get("proto")` to the bridge
without teaching goscan.go to emit `proto` also fails here, so the two sides
cannot drift apart silently in either direction.

No binary is executed, so these tests are immune to the host application-control
policy that intermittently blocks running the compiled core. That is deliberate:
the check must still run on a machine where the core cannot run, because a
schema drift is a source-level defect and is exactly what is invisible when the
core is blocked.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from core.envelope import REQUIRED_KEYS
from modules.discovery import goscan_bridge

ROOT = Path(__file__).resolve().parents[1]
GO_DIR = ROOT / "transport" / "goscan"
BRIDGE_SRC = ROOT / "modules" / "discovery" / "goscan_bridge.py"


def go_sources() -> str:
    return "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted(GO_DIR.glob("*.go"))
        if not p.name.endswith("_test.go")
    )


def go_source(name: str) -> str:
    """One file's source, so an assertion cannot be satisfied by a same-named
    local variable in an unrelated file."""
    return (GO_DIR / name).read_text(encoding="utf-8")


def go_struct(struct: str) -> dict[str, bool]:
    """Returns {json tag: is_omitempty} for a named Go struct.

    Parsed from source rather than hardcoded, so renaming a tag or dropping
    omitempty changes what this file sees.
    """
    match = re.search(
        rf"type\s+{re.escape(struct)}\s+struct\s*\{{(.*?)\n\}}", go_sources(), re.DOTALL
    )
    assert match, f"struct {struct} not found in {GO_DIR}"
    fields: dict[str, bool] = {}
    for tag in re.finditer(r'`json:"([^",]+)(,omitempty)?"`', match.group(1)):
        fields[tag.group(1)] = bool(tag.group(2))
    return fields


def bridge_reads() -> dict[str, bool]:
    """Every JSON key goscan_bridge.py reads, mapped to 'tolerates absence'.

    Tolerates absence is true when the read has a default (`.get("k", "")`) or
    is immediately guarded (`.get("k") or ""`). Those keys may be omitempty on
    the Go side; the rest must always be present.
    """
    source = BRIDGE_SRC.read_text(encoding="utf-8")
    reads: dict[str, bool] = {}
    for match in re.finditer(r'\.get\(\s*"([^"]+)"([^)]*)\)\s*(or\b)?', source):
        key, defaults, guarded = match.group(1), match.group(2), match.group(3)
        reads[key] = bool(defaults.strip()) or bool(guarded)
    return reads


def go_subcommands() -> set[str]:
    """Control subcommands goscan.go's main() dispatches on."""
    return set(re.findall(r'args\[0\]\s*==\s*"([a-z-]+)"', go_sources()))


# --------------------------------------------------------------------------- #
# port records
# --------------------------------------------------------------------------- #


def test_every_key_the_bridge_reads_is_produced_by_the_go_core():
    produced = go_struct("PortResult")
    read = bridge_reads()

    missing = {k for k in read if k not in produced and k not in REQUIRED_KEYS}
    assert not missing, (
        f"the bridge reads {sorted(missing)} but goscan.go's PortResult emits "
        f"only {sorted(produced)}"
    )


def test_a_key_read_without_a_default_is_never_omitted():
    """If the core can omit a key the bridge requires, the field is silently
    None in every result, with no error anywhere to notice."""
    produced = go_struct("PortResult")
    required = {k for k, tolerant in bridge_reads().items() if not tolerant}

    omittable = sorted(k for k in required if k in produced and produced[k])
    assert not omittable, (
        f"{omittable} are read without a default but are omitempty in Go, so "
        f"they vanish for closed services"
    )


def test_the_filter_key_is_guaranteed_to_arrive():
    """The single most important assertion in the file.

    `open` is the only key that decides whether a port is reported at all. If
    it is renamed or omitempty, every finding is dropped and the bridge reports
    a clean scan that found nothing.
    """
    produced = go_struct("PortResult")
    assert "open" in produced, "the bridge filters on `open`; it must exist"
    assert produced["open"] is False, (
        "`open` is omitempty in Go, so a false value would be omitted entirely "
        "and the bridge could not tell a closed port from a malformed record"
    )
    assert "open" in bridge_reads()


def test_the_go_core_filters_closed_ports_before_encoding():
    """Documents that the bridge's `open` check is defence in depth.

    goscan.go encodes a result only `if res.Open`, so the producer already drops
    closed ports. The bridge must still check, because it cannot assume the
    producer was the Go core, but the redundancy is deliberate rather than
    accidental.

    Scoped to goscan.go and anchored on the encoder: selftest.go has its own
    `if res.Open` over a different variable, and a whole-directory search is
    satisfied by that unrelated occurrence.
    """
    source = go_source("goscan.go")
    encoder = re.search(r"json\.NewEncoder\(os\.Stdout\)(.*?)\n\t\}", source, re.DOTALL)
    assert encoder, "could not find the stdout encoder loop in goscan.go"
    assert re.search(r"if\s+res\.Open\s*\{", encoder.group(1)), (
        "the encoder must be guarded by res.Open, or every closed port is "
        "reported to the bridge as a finding"
    )


# --------------------------------------------------------------------------- #
# error envelopes
# --------------------------------------------------------------------------- #


def test_the_error_envelope_carries_every_required_key():
    produced = go_struct("ErrorEnvelope")
    missing = [k for k in REQUIRED_KEYS if k not in produced]
    assert not missing, (
        f"core/envelope.py requires {list(REQUIRED_KEYS)} but the Go envelope "
        f"omits {missing}, so a real error would parse as None and be dropped"
    )


def test_the_envelope_is_written_to_stderr_as_a_single_line():
    """parse_envelope is called per line, so a pretty-printed envelope on one
    line with embedded newlines would never parse."""
    assert re.search(
        r"fmt\.Fprintln\(os\.Stderr,\s*string\(data\)\)", go_source("goscan.go")
    ), "the envelope must go to stderr through Fprintln, not a multi-line write"


# --------------------------------------------------------------------------- #
# the selftest report
# --------------------------------------------------------------------------- #


def test_the_selftest_report_carries_the_keys_the_health_check_reads():
    produced = go_struct("selftestReport")
    # core/cores.py: report.get("status") == "ok" and report.get("failures") == 0
    # test_cores.py:    report["checks"] > 0
    needed = {"status", "checks", "failures"}
    missing = sorted(needed - set(produced))
    assert not missing, (
        f"the health check reads {sorted(needed)} but the Go report omits {missing}"
    )


def test_the_failure_count_is_named_failures_not_failed():
    """The Go field is `Failed` but the wire name is `failures`; matching the
    field name instead of the tag is an easy and invisible mistake."""
    assert "failures" in go_struct("selftestReport")
    assert "failed" not in go_struct("selftestReport")


# --------------------------------------------------------------------------- #
# the invocation contract
# --------------------------------------------------------------------------- #


def test_the_bridge_only_invents_subcommands_that_exist():
    invoked = set(
        re.findall(
            r'str\(GOSCAN_BIN\),\s*"([a-z]+)"', BRIDGE_SRC.read_text(encoding="utf-8")
        )
    )
    known = go_subcommands()
    assert "version" in invoked and "selftest" in invoked
    assert invoked <= known, (
        f"the bridge invokes {sorted(invoked - known)} which main() does not "
        f"dispatch; known: {sorted(known)}"
    )


def test_the_scan_argv_shape_matches_the_go_usage():
    """The bridge spawns [bin, target, port_arg]; main() reads args[0] as the
    target and args[1] as the port spec. A reordered spawn would scan the wrong
    host with no error."""
    assert re.search(
        r"create_subprocess_exec\(\s*str\(GOSCAN_BIN\),\s*target,\s*port_arg",
        BRIDGE_SRC.read_text(encoding="utf-8"),
    )
    assert re.search(r"targetIP\s*:=\s*args\[0\]", go_source("goscan.go"))
    assert re.search(r"portArg\s*:=\s*args\[1\]", go_source("goscan.go"))


def test_the_port_specs_the_bridge_advertises_are_the_ones_go_parses():
    """`common` and `all` are special-cased in Go; the bridge's default must be
    one of them, or a default scan silently becomes an error envelope."""
    assert re.search(r'case\s+"common",\s*"default":', go_source("goscan.go"))
    assert re.search(r'case\s+"all",\s*"full",\s*"1-65535":', go_source("goscan.go"))
    signature = re.search(
        r"def run_go_scan\(.*?port_arg:\s*str\s*=\s*\"([^\"]+)\"",
        BRIDGE_SRC.read_text(encoding="utf-8"),
        re.DOTALL,
    )
    assert signature, "could not read run_go_scan's default port spec"
    assert signature.group(1) == "common", (
        f"the bridge defaults to {signature.group(1)!r}, which Go treats as a "
        f"port list and rejects with PARSE_ERROR"
    )


# --------------------------------------------------------------------------- #
# the guard has teeth
# --------------------------------------------------------------------------- #


def test_the_subset_check_rejects_a_key_the_core_cannot_produce():
    """Self-check on the extractor itself.

    Without this, a broken regex that matched nothing would make every subset
    assertion above vacuously true.
    """
    produced = go_struct("PortResult")
    read = dict(bridge_reads())
    read["is_open"] = False  # as if the tag had been renamed

    missing = {k for k in read if k not in produced and k not in REQUIRED_KEYS}
    assert missing == {"is_open"}, "the subset check failed to notice a drift"


def test_the_reader_detects_defaults_and_guards():
    """The 'tolerates absence' classification has to distinguish the three
    shapes the bridge actually uses, or the omitempty assertion is vacuous."""
    reads = bridge_reads()
    assert reads["banner"] is True, '`.get("banner", "")` has a default'
    assert reads["service"] is True, '`.get("service") or ""` is guarded'
    assert reads["port"] is False, '`.get("port")` has neither'
    assert reads["latency_ms"] is False, '`.get("latency_ms")` has neither'


# --------------------------------------------------------------------------- #
# behavioural proof that omitempty fields really are optional
# --------------------------------------------------------------------------- #


def test_a_minimal_go_record_still_produces_a_complete_result(monkeypatch):
    """Runs a record containing only the fields goscan.go always emits.

    goscan.go marks `banner` and `service` omitempty, so a closed-service port
    arrives without them. The bridge must still return a full row rather than
    raising or leaving the caller to guess.
    """

    class Stream:
        def __init__(self, lines):
            self.lines = list(lines)

        async def readline(self):
            return self.lines.pop(0) if self.lines else b""

    class Proc:
        def __init__(self, out):
            self.stdout = Stream(out)
            self.stderr = Stream([])

        async def wait(self):
            return 0

    # Exactly the fields with no omitempty in goscan.go's PortResult.
    minimal = {
        "port": 8080,
        "open": True,
        "latency_ms": 12,
        "time": "2026-09-28T00:00:00Z",
    }

    async def fake_exec(*args, **kwargs):
        return Proc([(json.dumps(minimal) + "\n").encode()])

    monkeypatch.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    assert len(results) == 1
    row = results[0]
    assert row["port"] == 8080
    assert row["service"] == "", "an omitted service must read as empty, not None"
    assert row["banner"] == "", "an omitted banner must read as empty, not None"
    assert row["latency_ms"] == 12
    assert goscan_bridge.LAST_ERROR is None


def test_a_record_missing_the_filter_key_is_a_provable_defect():
    """What the drift actually costs, pinned so the cost stays visible.

    This is the scenario the `open` assertion above rules out. It is written as
    a test of the *bridge's* honesty: it cannot detect the condition, and the
    only thing standing between that and a false clean report is the static
    contract check.
    """

    class Stream:
        def __init__(self, lines):
            self.lines = list(lines)

        async def readline(self):
            return self.lines.pop(0) if self.lines else b""

    class Proc:
        def __init__(self, out):
            self.stdout = Stream(out)
            self.stderr = Stream([])

        async def wait(self):
            return 0

    # A producer that renamed `open` but still found the port.
    drifted = {
        "port": 22,
        "is_open": True,
        "service": "ssh",
        "latency_ms": 1,
        "time": "t",
    }

    async def fake_exec(*args, **kwargs):
        return Proc([(json.dumps(drifted) + "\n").encode()])

    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(goscan_bridge.GOSCAN_BIN.__class__, "exists", lambda self: True)
        monkey.setattr(asyncio, "create_subprocess_exec", fake_exec)
        results = asyncio.run(goscan_bridge.run_go_scan_async("10.0.0.1"))
    finally:
        monkey.undo()

    assert results == []
    assert goscan_bridge.LAST_ERROR is None, (
        "the bridge cannot know, so it reports success. This is exactly why "
        "test_the_filter_key_is_guaranteed_to_arrive must exist."
    )
