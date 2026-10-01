"""HELIOS-NET :: tools/gen_c_reference.py

Regenerates `tests/golden/c_reference.json` from a native core.

The goldens are what makes the C core's contract verifiable on a host that
cannot execute the C core. They are produced from a core that is trusted to be
C-equivalent, cross-checked against the in-process path before being written so
a divergence fails here rather than being frozen into the repository:

  * if the C core runs, it is the source of truth (the normal CI case);
  * otherwise the Rust core is used, which the parity suite proves agrees with
    C byte for byte on byte offsets, folding and overlapping hits.

The matching answers are recorded, not asserted: they are the native core's
output for the corpus, and pinning them is what turns "the C core is blocked"
into a testable statement. The parser answers are different - those are
hand-written in the corpus and this tool only checks the code still agrees with
them, because a golden that records today's parser can never distinguish a
correct behaviour from an incorrect one.

Usage:  python tools/gen_c_reference.py [--check]

`--check` regenerates in memory and fails if the committed file differs, which
is what CI runs so a drift cannot be committed unnoticed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from c_reference_corpus import MATCH_CASES, PARSE_CASES  # type: ignore[import-not-found]  # noqa: E402

from core import accel, c_core_bridge, rust_bridge  # noqa: E402

GOLDEN = ROOT / "tests" / "golden" / "c_reference.json"


def _native_matches(case_name: str, banner: str, patterns: list[str]) -> tuple[list[tuple[str, int]], str]:
    """Matches for one case from the most trustworthy core available here."""
    if c_core_bridge.core_available():
        outcome = accel.match_signatures(banner, patterns, prefer="c")
        return sorted((m.signature, m.position) for m in outcome.matches), "c-native"
    if rust_bridge.rust_available():
        outcome = accel.match_signatures(banner, patterns, prefer="rust")
        return sorted((m.signature, m.position) for m in outcome.matches), "rust-native"
    raise SystemExit(
        "no native core is runnable here, so the goldens cannot be produced.\n"
        "Run this on CI (Linux) or on a host whose application-control policy "
        "permits a freshly built native image."
    )


def _python_matches(banner: str, patterns: list[str]) -> list[tuple[str, int]]:
    outcome = accel.match_signatures(banner, patterns, prefer="python")
    return sorted((m.signature, m.position) for m in outcome.matches)


def build() -> dict[str, Any]:
    """Computes the golden payload, refusing to record a disagreement."""
    source = ""
    matches: list[dict[str, Any]] = []
    for name, banner, patterns in MATCH_CASES:
        native, engine = _native_matches(name, banner, patterns)
        source = source or engine
        python_side = _python_matches(banner, patterns)
        if native != python_side:
            raise SystemExit(
                f"refusing to record a golden for {name!r}: the native core and the "
                f"in-process path disagree.\n  native: {native}\n  python: {python_side}"
            )
        matches.append({
            "name": name,
            "banner": banner,
            "patterns": patterns,
            "matches": [[sig, pos] for sig, pos in native],
        })

    parse: list[dict[str, Any]] = []
    for name, text, expected in PARSE_CASES:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            sig = Path(tmp) / "sigs.txt"
            sig.write_text(text, encoding="utf-8")
            produced = c_core_bridge._load_signatures(sig)
        if produced != expected:
            raise SystemExit(
                f"parser disagrees with the specified contract for {name!r}:\n"
                f"  specified: {expected}\n  produced:  {produced}"
            )
        parse.append({"name": name, "expected": [[n, p] for n, p in expected]})

    return {
        "_comment": (
            "The native C core's observable contract, captured as data so it can be "
            "verified on hosts that refuse to execute a native image. Regenerate with "
            "tools/gen_c_reference.py; CI re-runs the real C core over the same corpus."
        ),
        "established_by": source,
        "match_cases": matches,
        "parse_cases": parse,
    }


#: Sections that are the C core's actual answers. `established_by` is excluded on
#: purpose: it records which native core was run locally, so it necessarily differs
#: between a developer host (the C core is blocked, Rust establishes them) and CI
#: (the C core is runnable and re-derives them). Comparing it would fail the CI
#: check on every host for a reason that says nothing about correctness.
_GOLDEN_SECTIONS = ("match_cases", "parse_cases")


def _substance(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload[key] for key in _GOLDEN_SECTIONS}


def main() -> int:
    payload = build()
    blob = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"

    if "--check" in sys.argv:
        if not GOLDEN.exists():
            print(f"missing {GOLDEN}")
            return 1
        committed = json.loads(GOLDEN.read_text(encoding="utf-8"))
        if _substance(committed) != _substance(payload):
            print(
                f"{GOLDEN} is stale with respect to the {payload['established_by']} core.\n"
                "If the change is intended, regenerate with: "
                "python tools/gen_c_reference.py"
            )
            return 1
        print(
            f"the C core still reproduces every recorded answer "
            f"(re-derived via {payload['established_by']})"
        )
        return 0

    GOLDEN.write_text(blob, encoding="utf-8")
    print(f"wrote {GOLDEN} from {payload['established_by']}")
    print(f"  {len(payload['match_cases'])} match cases, {len(payload['parse_cases'])} parse cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
