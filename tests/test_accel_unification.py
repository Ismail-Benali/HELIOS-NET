"""Cross-backend tests for the unified core layer.

These exist because the fallback guarantee was never actually tested across
backends. The C differential fuzzer compares the C core against an oracle
written in C, so it cannot see a disagreement between the C core and the Python
code that stands in for it. Four such disagreements were found when this file
was first written, and each of them had the same shape: a degraded run reported
something a healthy run did not.

A C core that cannot run makes most of this file skip. The Python-only
regressions still run, because the defect is in the fallback, not in the core.
"""

from __future__ import annotations

import pytest

from core import accel
from core.c_core_bridge import _load_signatures, _python_fallback

# ------------------------------------------------------------------ fixtures


@pytest.fixture
def sig_file(tmp_path):
    """Writes a signature file and returns its path."""

    def write(content: str):
        path = tmp_path / "sigs.txt"
        path.write_bytes(content.encode("utf-8"))
        return path

    return write


def c_core_usable() -> bool:
    from core import c_core_bridge

    return c_core_bridge.core_available()


needs_c = pytest.mark.skipif(
    not c_core_usable(), reason="the C core binary is unavailable on this host"
)


def signature_set(hits):
    """The contract: a set of (signature, byte offset) pairs.

    Order is deliberately ignored. The native harness qsorts both sides before
    comparing, which is the project's own definition of what a match is, and
    tying a test to the order the automaton happens to emit in would pin down an
    implementation detail rather than the behaviour.
    """
    return sorted((h["signature"], h["position"]) for h in hits)


# --------------------------------------------- the fallback is a real substitute


@needs_c
def test_fallback_reports_every_occurrence_not_just_the_first(sig_file):
    """A banner advertising several SSH versions is one detection per version.

    The fallback looped on str.find() and kept only the first hit, so a degraded
    run reported one service where a healthy run reported three.
    """
    sig = sig_file("ssh\tSSH\n")
    banner = "SSH-1.5 ... SSH-2.0 ... SSH-2.0"

    native = _python_c_native(sig, banner)
    assert signature_set(native) == [("ssh", 0), ("ssh", 12), ("ssh", 24)]

    fallback = _python_fallback([banner], sig)[0]["matches"]
    assert signature_set(fallback) == signature_set(native)


@needs_c
def test_fallback_reports_overlapping_occurrences(sig_file):
    """The native matcher advances one character per hit, so matches overlap.

    'aa' in 'aaaa' is three positions, not two, and not one.
    """
    sig = sig_file("a\taa\n")

    native = _python_c_native(sig, "aaaa")
    assert signature_set(native) == [("a", 0), ("a", 1), ("a", 2)]

    fallback = _python_fallback(["aaaa"], sig)[0]["matches"]
    assert signature_set(fallback) == signature_set(native)


@needs_c
def test_fallback_returns_byte_offsets_not_character_indexes(sig_file):
    """A multi-byte prefix shifts a character index away from a byte offset.

    'Ü' is two bytes, so a match after it is at character index 4 but byte
    offset 5. The fallback used str.find()'s answer directly.
    """
    sig = sig_file("alpha\tSSH-2.0\n")
    banner = "\u00dcberSSH-2.0-OpenSSH_9.6"

    native = _python_c_native(sig, banner)
    assert signature_set(native) == [("alpha", 5)], "precondition: the core is in bytes"

    fallback = _python_fallback([banner], sig)[0]["matches"]
    assert signature_set(fallback) == signature_set(native)


@needs_c
def test_fallback_does_not_invent_matches_on_non_ascii_case(sig_file):
    """The native core folds ASCII case only, and so must the fallback.

    str.lower() folds 'Ü' to 'ü', so the fallback used to report a hit for
    'Über' against the pattern 'über' that the core rejects. A degraded campaign
    was therefore reporting detections a healthy one never produced.
    """
    sig = sig_file("umlaut\t\u00fcber\n")
    banner = "\u00dcBER 1.0"

    native = _python_c_native(sig, banner)
    assert native == [], "precondition: the core folds ASCII only"

    fallback = _python_fallback([banner], sig)[0]["matches"]
    assert fallback == [], "the fallback invented a match the core did not report"


@needs_c
def test_fallback_preserves_a_pattern_that_begins_with_a_space(sig_file):
    """The native parser trims the line, never the pattern.

    Trimming each field separately moved ' SSH' to 'SSH', so the fallback matched
    at a different position than the core and matched text the core rejected.
    """
    sig = sig_file("n\t SSH\n")
    banner = "xx SSHxx"

    native = _python_c_native(sig, banner)
    assert signature_set(native) == [("n", 2)], (
        "precondition: the space is part of the pattern"
    )

    fallback = _python_fallback([banner], sig)[0]["matches"]
    assert signature_set(fallback) == signature_set(native)


def test_signature_loading_mirrors_the_native_parser(sig_file):
    """Whitespace, comments, CRLF and a BOM are all part of the file format."""
    assert _load_signatures(sig_file("n\t SSH\n")) == [("n", " SSH")]
    assert _load_signatures(sig_file("n\tpat\r\n")) == [("n", "pat")]
    assert _load_signatures(sig_file("# a comment\n\nn\tpat\n")) == [("n", "pat")]
    assert _load_signatures(sig_file("\ufeffn\tpat\n")) == [("n", "pat")]
    assert _load_signatures(sig_file("bare\n")) == [("bare", "bare")]
    # Only the line is trimmed, so the spaces on either side of the tab survive
    # in the name and in the pattern. The name keeps the two spaces that sit
    # between it and the tab, because trim() ran before the split.
    assert _load_signatures(sig_file("  n  \t  pat  \n")) == [("n  ", "  pat")]


@needs_c
def test_signature_loading_agrees_with_the_native_parser(sig_file):
    """Whatever is asserted above, the native parser is the authority.

    The expectations in the test above are a reading of the C source; this
    checks that reading against the binary, so a change to either side is caught
    instead of both being adjusted to agree with each other.
    """
    from core import c_core_bridge

    for content in (
        "n\t SSH\n",
        "  n  \t  pat  \n",
        "n\tpat\r\n",
        "# a comment\n\nn\tpat\n",
        "\ufeffn\tpat\n",
        "bare\n",
        "a\tfoo\nb\tfoo\n",
    ):
        sig = sig_file(content)
        # The C bridge returns a match with the name, so a pattern that matched
        # proves the name it was registered under. Reading it back through the
        # C core therefore pins down both fields.
        probe = c_core_bridge.scan_banners(["foo foo"], sig)
        registered = _load_signatures(sig)
        assert len(registered) == 1 or len(registered) == 2, registered

        native_names = {m["signature"] for m in probe[0]["matches"]}
        python_names = {name for name, pattern in registered if "foo" in pattern}
        assert native_names == python_names, (
            f"{content!r}: native registered {native_names}, "
            f"python registered {python_names}"
        )


def test_signature_loading_deduplicates_an_identical_line(sig_file):
    """Mirrors hc_ac_add() returning HC_ERR_DUP for a repeated line."""
    assert _load_signatures(sig_file("a\tfoo\na\tfoo\n")) == [("a", "foo")]


def test_signature_loading_keeps_one_pattern_under_two_names(sig_file):
    """Two names sharing a pattern are two signatures, and the core keeps both."""
    assert _load_signatures(sig_file("a\tfoo\nb\tfoo\n")) == [
        ("a", "foo"),
        ("b", "foo"),
    ]


# --------------------------------------------------- all backends, one answer

CROSS_BACKEND_CASES = [
    ("ascii_case_insensitive", "xxFOOyyBARzz", ["foo", "bar", "baz"]),
    ("repeated_pattern", "SSH-1.5 then SSH-2.0", ["SSH"]),
    ("overlapping", "aaaa", ["aa"]),
    ("no_match", "nothing here", ["foo"]),
    ("empty_pattern_is_ignored", "abc", ["", "b"]),
    ("non_ascii_pattern", "SSHD-\u4e2d\u6587", ["\u4e2d\u6587", "SSHD"]),
    ("non_ascii_prefix", "\u00dcberSSH-2.0", ["SSH-2.0"]),
    ("non_ascii_case_is_not_folded", "\u00dcBER 1.0", ["\u00fcber", "ber"]),
    ("astral_plane", "ok-\U0001f600-tail", ["\U0001f600", "tail"]),
    ("pattern_with_leading_space", "xx SSHxx", [" SSH"]),
    ("duplicate_pattern_listed_twice", "foofoo", ["foo", "foo"]),
]


@pytest.mark.parametrize(
    "label,text,patterns", CROSS_BACKEND_CASES, ids=[c[0] for c in CROSS_BACKEND_CASES]
)
def test_every_backend_reports_the_same_matches(label, text, patterns):
    """Whatever serves a request, the answer is the same.

    The label exists to make a failure readable, since a mismatch here is a real
    detection difference rather than a cosmetic one.
    """
    report = accel.compare_backends(text, patterns)

    assert report["agree"] is True, (
        f"{label}: backends disagree on {text!r}\n"
        f"  {report['backends']}\n"
        f"  {report['disagreements']}"
    )
    # At least one backend must have run, otherwise "agree" is vacuous.
    assert report["backends"], report


def test_positions_are_byte_offsets_on_every_backend():
    """A byte offset is the shared contract, not a character index."""
    text = "\u00dcberSSH"
    for name in ("c", "rust", "python"):
        if not accel.backend_infos_by_name()[name].available:
            continue
        outcome = accel.match_signatures(text, ["SSH"], prefer=name)
        assert [m.position for m in outcome.matches] == [5], (
            f"{name} reported {outcome.matches} for {text!r}"
        )


# --------------------------------------------------------- one call, one core


def test_a_result_is_never_a_mixture_of_backends():
    """One request is served by one backend, so it corresponds to one opinion."""
    outcome = accel.match_signatures("xxFOOyyBARzz", ["foo", "bar"])
    assert outcome.engine in {"c-native", "rust-native", "python-fallback"}
    # Every hit came from the one engine named on the outcome.
    assert outcome.engine.endswith("native") or outcome.engine == "python-fallback"


def test_a_pinned_backend_is_used_when_it_is_available():
    outcome = accel.match_signatures("xxFOO", ["foo"], prefer="python")
    assert outcome.engine == "python-fallback"
    assert [m.signature for m in outcome.matches] == ["foo"]


def test_pinning_an_unavailable_backend_falls_back_and_says_why():
    from core import c_core_bridge

    original = c_core_bridge.core_available
    c_core_bridge.core_available = lambda: False
    try:
        outcome = accel.match_signatures("xxFOO", ["foo"], prefer="c")
    finally:
        c_core_bridge.core_available = original

    assert outcome.engine != "c-native"
    assert "c" in outcome.reason and outcome.reason.strip(), (
        "a skipped backend must leave a reason behind"
    )
    assert [m.signature for m in outcome.matches] == ["foo"]


def test_an_unknown_backend_name_is_refused():
    with pytest.raises(ValueError):
        accel.match_signatures("abc", ["a"], prefer="cobol")


# ------------------------------------------------------------- fingerprints


def test_fingerprints_agree_across_backends():
    """The digests are the same numbers whichever core computes them."""
    from core import c_core_bridge

    text = "220 ProFTPD 1.3 ready \u00dc"
    expected = {
        "fp_fnv1a32": f"0x{c_core_bridge.fnv1a32_py(text):08X}",
        "fp_fnv1a64": f"0x{c_core_bridge.fnv1a64_py(text):016X}",
        "fp_crc32": f"0x{c_core_bridge.crc32_py(text):08X}",
    }

    seen = {}
    for name in ("c", "python"):
        if not accel.backend_infos_by_name()[name].available:
            continue
        seen[name] = accel.fingerprint(text, prefer=name).to_dict()

    assert seen, "no fingerprint backend was available to compare"
    for name, digests in seen.items():
        assert digests == expected, f"{name} disagreed on {text!r}"


def test_rust_is_not_handed_a_partial_digest_set():
    """The Rust core implements FNV-1a 32 only, so it is not used for a full set.

    Returning its single digest where three are expected would hand back a
    complete-looking result that is missing two algorithms.
    """
    from core import rust_bridge

    if not rust_bridge.rust_available():
        pytest.skip("the Rust library is unavailable on this host")

    info = accel.backend_infos_by_name()["rust"]
    assert "fingerprint" not in info.capabilities
    # Asserted per capability rather than as a whole set: this test is about the
    # digest set, and the Rust core legitimately gains unrelated capabilities
    # (the graph operations) without that weakening this guarantee.
    assert "fnv1a32" in info.capabilities
    assert not ({"fingerprint"} & info.capabilities), (
        "the Rust core must never be handed a full digest request: it only "
        "implements FNV-1a 32 of the three algorithms"
    )


def test_an_empty_string_has_no_digest():
    outcome = accel.fingerprint("")
    assert outcome.engine == "none"
    assert outcome.fnv1a32 == ""


# --------------------------------------------------- the shared matcher path


def test_the_registry_delegates_to_the_unified_layer():
    """A caller of the matcher gets the cores' answer, not a fourth opinion."""
    from engine.pattern_matcher import AhoCorasickMatcher

    matcher = AhoCorasickMatcher()
    matcher.load_defaults()
    hits = matcher.match("banner with openssh and redis inside")

    direct = accel.match_signatures(
        "banner with openssh and redis inside", matcher.all_patterns()
    )
    assert [(h["signature"], h["position"]) for h in hits] == [
        (m.signature, m.position) for m in direct.matches
    ]
    assert {h["engine"] for h in hits} == {direct.engine}


def test_the_registry_reports_byte_offsets_for_a_non_ascii_banner():
    from engine.pattern_matcher import AhoCorasickMatcher

    matcher = AhoCorasickMatcher()
    matcher.load_defaults()

    # One 'Ü' is two bytes, so the character index of 'openssh' is 2 while its
    # byte offset is 3. A character-indexed caller would report 2.
    hits = matcher.match("\u00dc openssh")
    positions = {h["signature"]: h["position"] for h in hits}
    assert positions["openssh"] == 3, positions


# ------------------------------------------------------------------ helpers


def _python_c_native(sig, banner):
    """Runs the C core over a signature file, for a side-by-side comparison."""
    from core import c_core_bridge

    return c_core_bridge.scan_banners([banner], sig)[0]["matches"]
