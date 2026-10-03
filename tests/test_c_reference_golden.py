"""HELIOS-NET :: tests/test_c_reference_golden.py

Verifies the in-process signature path against the native C core's recorded
contract - on any host, with no native image executed.

The problem this solves
-----------------------
Smart App Control, AppLocker and WDAC refuse to execute newly built unsigned
native images. That is not a defect to work around and not something the code
can decide its way out of: on such a host the C core simply does not run, and
the shipped fallback answers in its place.

That leaves one failure mode with no defence. The fallback is an independent
implementation of a byte-offset, ASCII-folded, overlap-preserving matcher, and
if it ever diverges, a degraded campaign reports different detections from a
healthy one - and the only machine that could have noticed is the one whose
policy stopped it from asking. The C differential fuzzer does not help: it
compares the C core against an oracle written in C.

So the C core's answers are captured as data (`tests/golden/c_reference.json`)
and replayed here against whatever this machine can actually run. CI runs the
real C core over the same corpus, so the goldens cannot drift away from C
without failing a build. The guarantee is therefore: on every machine, on every
push, the shipped path is verified to agree with the C core.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from c_reference_corpus import MATCH_CASES, PARSE_CASES  # noqa: E402

from core import accel, c_core_bridge, rust_bridge  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "golden" / "c_reference.json"

#: `match_signatures` refuses an empty banner before consulting any core, the same
#: way `fingerprint` does: there is nothing to match and nothing to hash. These
#: cases pin that decision, so no engine is expected to answer them and asserting
#: otherwise would be asserting a core was consulted for a request that never
#: reaches one.
SHORT_CIRCUIT_CASES = {"empty_banner"}


@pytest.fixture(scope="module")
def goldens() -> dict:
    if not GOLDEN.exists():
        pytest.fail(f"{GOLDEN} is missing; generate it with tools/gen_c_reference.py")
    payload = json.loads(GOLDEN.read_text(encoding="utf-8"))
    # Indexed here rather than stored twice: the file stays the single record of
    # what the native core answered, with no derived copy to fall out of step.
    payload["match_cases_by_name"] = {
        case["name"]: case["matches"] for case in payload["match_cases"]
    }
    return payload


# ------------------------------------------------------- corpus completeness
def test_the_goldens_cover_every_corpus_case(goldens):
    """A corpus case with no golden is a case nobody is checking."""
    recorded = {c["name"] for c in goldens["match_cases"]}
    expected = {name for name, _, _ in MATCH_CASES}
    assert recorded == expected, (
        f"match corpus drift: missing={sorted(expected - recorded)} "
        f"unexpected={sorted(recorded - expected)}"
    )

    recorded_parse = {c["name"] for c in goldens["parse_cases"]}
    expected_parse = {name for name, _, _ in PARSE_CASES}
    assert recorded_parse == expected_parse, (
        f"parse corpus drift: missing={sorted(expected_parse - recorded_parse)} "
        f"unexpected={sorted(recorded_parse - expected_parse)}"
    )


def test_the_goldens_record_a_native_source(goldens):
    """A golden produced by the fallback proves only that the fallback is itself."""
    assert goldens["established_by"] in ("c-native", "rust-native"), (
        f"goldens claim to come from {goldens['established_by']!r}, which is not a "
        "native core"
    )


# ------------------------------------------------- the always-available path
@pytest.mark.parametrize("case", MATCH_CASES, ids=[c[0] for c in MATCH_CASES])
def test_python_path_reproduces_the_c_contract(goldens, case):
    name, banner, patterns = case
    expected = [tuple(m) for m in goldens["match_cases_by_name"][name]]
    outcome = accel.match_signatures(banner, patterns, prefer="python")
    if name in SHORT_CIRCUIT_CASES:
        assert outcome.engine == "none", (
            f"{name}: an empty banner must not reach a core, but {outcome.engine} answered"
        )
    produced = sorted((m.signature, m.position) for m in outcome.matches)
    assert produced == expected, (
        f"{name}: the in-process path disagrees with the C core.\n"
        f"  expected (C): {expected}\n"
        f"  produced:     {produced}"
    )


# --------------------------------------------------------- the native paths
@pytest.mark.skipif(
    not rust_bridge.rust_available(),
    reason="the Rust core is not available on this host",
)
@pytest.mark.parametrize("case", MATCH_CASES, ids=[c[0] for c in MATCH_CASES])
def test_rust_core_reproduces_the_c_contract(goldens, case):
    name, banner, patterns = case
    expected = [tuple(m) for m in goldens["match_cases_by_name"][name]]
    outcome = accel.match_signatures(banner, patterns, prefer="rust")
    if name in SHORT_CIRCUIT_CASES:
        assert outcome.engine == "none", (
            f"{name}: an empty banner must not reach a core, but {outcome.engine} answered"
        )
    else:
        assert outcome.engine == "rust-native", (
            f"{name}: the Rust core was requested but {outcome.engine} answered, so this "
            "test would silently re-check the fallback"
        )
    produced = sorted((m.signature, m.position) for m in outcome.matches)
    assert produced == expected


@pytest.mark.skipif(
    not c_core_bridge.core_available(),
    reason="the C core cannot be executed on this host",
)
@pytest.mark.parametrize("case", MATCH_CASES, ids=[c[0] for c in MATCH_CASES])
def test_c_core_still_reproduces_its_own_contract(goldens, case):
    """Runs wherever the C core is runnable - CI, and unblocked developer hosts.

    This is the half of the guarantee the goldens rest on: it is what stops them
    from slowly ceasing to describe the C core.
    """
    name, banner, patterns = case
    expected = [tuple(m) for m in goldens["match_cases_by_name"][name]]
    outcome = accel.match_signatures(banner, patterns, prefer="c")
    assert outcome.engine == "c-native", (
        f"{name}: the C core was requested but {outcome.engine} answered"
    )
    produced = sorted((m.signature, m.position) for m in outcome.matches)
    assert produced == expected, (
        f"{name}: the C core no longer reproduces its own recorded contract. "
        "If this change is intended, regenerate with tools/gen_c_reference.py."
    )


# ------------------------------------------------------------- the parser
@pytest.mark.parametrize("case", PARSE_CASES, ids=[c[0] for c in PARSE_CASES])
def test_signature_parser_matches_the_specified_contract(goldens, case, tmp_path):
    """The parser is pure, so it is pinned everywhere, including blocked hosts."""
    name, text, expected = case
    sig = tmp_path / "sigs.txt"
    sig.write_text(text, encoding="utf-8")
    produced = c_core_bridge._load_signatures(sig)
    assert produced == expected, (
        f"{name}: the signature parser disagrees with the specified contract.\n"
        f"  specified: {expected}\n"
        f"  produced:  {produced}"
    )
