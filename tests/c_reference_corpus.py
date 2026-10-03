"""HELIOS-NET :: tests/c_reference_corpus.py

The corpus that pins the native C core's observable contract.

Why this exists
---------------
The C core is a native image, and a host application-control policy - Smart
App Control, AppLocker, WDAC - may refuse to execute it. On such a host the C
core cannot be run, so the only thing standing between the shipped fallback and
a silent behavioural drift is this corpus plus the golden file it is replayed
against. Without it, "the C core is blocked" and "the fallback is wrong" are
indistinguishable, and nothing catches the second until a real engagement
reports the wrong positions.

So the C core's answers are captured once, as data, and travel with the
repository. Every machine - any Windows policy, any compiler, no compiler - can
then verify its own in-process path against what the C core actually produced,
with no native execution at all. `tools/gen_c_reference.py` regenerates the
goldens; the CI job runs the real C core over this same corpus so a divergence
between C and the goldens fails the build instead of being discovered later.

`PARSE_CASES` expectations are hand-written from `main.c`'s documented parser
behaviour rather than recorded from a run, because they are small enough to be
specified exactly, and a golden that merely records whatever the code did today
cannot tell a correct behaviour from a wrong one.
"""

from __future__ import annotations

#: (name, banner, patterns) for the matching contract.
MATCH_CASES: list[tuple[str, str, list[str]]] = [
    ("empty_banner", "", ["ssh"]),
    # ASCII-only case-insensitivity. "openssh" must match inside "OpenSSH".
    ("ascii_case_folding", "SSH-2.0-OpenSSH_9.6p1", ["SSH", "openssh", "OPEN"]),
    # The contract folds ASCII A-Z and nothing else. "Über" contains "über"
    # under str.lower() but not under the native rule, and reporting it would
    # invent a detection the C core never produced.
    ("ascii_only_folding", "Über Server", ["über", "Server"]),
    # Positions are UTF-8 byte offsets, not character indices: three CJK
    # characters occupy nine bytes, so "SSH" starts at byte 9.
    ("multibyte_byte_offset", "日本語SSH", ["SSH"]),
    # The native matcher advances one character past each hit, so a pattern
    # matches inside its own previous match: 0, 1, 2.
    ("overlapping_hits", "aaaa", ["aa"]),
    ("pattern_longer_than_text", "ab", ["abcd"]),
    # A prefix family: every pattern of one another, all at the same offset.
    ("prefix_family", "abc", ["abc", "ab", "a", "b", "c"]),
    ("repeated_pattern", "abcabc", ["abc"]),
    ("single_char_pattern", "aaa", ["a"]),
    # Taken from the C core's own selftest, which registers he/she/hers/his
    # and scans "ushers". Suffix inheritance is the part of Aho-Corasick most
    # likely to be reimplemented differently by a fallback.
    ("adjacent_suffix_family", "ushers", ["he", "she", "hers", "his"]),
    # Whitespace inside a pattern is significant; only the whole line is
    # trimmed by the file parser.
    ("space_is_significant", "x SSH y", [" SSH", "SSH "]),
    ("utf8_pattern_and_prefix", "café", ["café", "caf"]),
    # A non-ASCII byte before the hit still counts as one *byte* per char in
    # this position, and must not be counted as one character.
    ("leading_high_byte", "\u00ffSSH", ["SSH"]),
    ("control_characters", "a\x01b", ["a\x01b", "b"]),
    ("no_match", "plain text", ["absent"]),
    # Long lines cross the CLI's MAX_LINE/MATCH_BUFFER truncation boundaries.
    ("long_line", "a" * 5000 + "needle", ["needle"]),
    (
        "many_patterns",
        "alpha beta gamma delta",
        ["alpha", "beta", "gamma", "delta", "alp", "hha", "zzz"],
    ),
]


#: (name, signature-file text, expected (name, pattern) pairs after parsing).
#:
#: Expectations are transcribed from `main.c: load_signatures()`: `read_line()`
#: splits on '\n' and drops one trailing '\r', `trim()` then removes leading and
#: trailing spaces and tabs from the *whole line*, a leading UTF-8 BOM is
#: stripped from the first line, and only afterwards is the line split at its
#: first tab. The pattern is never trimmed on its own.
PARSE_CASES: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("comments_and_blanks", "# a comment\n\n   \nssh\n", [("ssh", "ssh")]),
    # A '#' only starts a comment at the start of a line; inside a pattern it
    # is ordinary text.
    ("hash_inside_pattern", "n\t#hash\n", [("n", "#hash")]),
    ("tab_form", "ssh\tSSH-2.0\n", [("ssh", "SSH-2.0")]),
    # The whole line is trimmed, so the surrounding spaces of the *line* go.
    ("whole_line_trim", "  spaced name\tpattern  \n", [("spaced name", "pattern")]),
    # ...but the pattern's own leading space survives, because trim() ran
    # before the split. Trimming each field separately moves the match.
    ("pattern_space_preserved", "name\t SSH\n", [("name", " SSH")]),
    # hc_ac_add() rejects an identical (name, pattern) as HC_ERR_DUP, so the
    # signature must appear once, not twice in one detection.
    ("duplicate_line", "a\tx\na\tx\n", [("a", "x")]),
    # Two names over one pattern are two real signatures and both survive.
    (
        "two_names_one_pattern",
        "first\tp\nsecond\tp\n",
        [("first", "p"), ("second", "p")],
    ),
    # PowerShell 5.1, Notepad and several Windows editors write a BOM; without
    # stripping it the first signature name silently becomes "﻿first".
    ("bom_prefix", "\ufefffirst\tp\n", [("first", "p")]),
    # A whitespace-only line trims to nothing and is skipped.
    ("whitespace_only_rejected", "   \n\t\n", []),
    # "name\t" trims its trailing tab *as part of the line*, leaving no tab to
    # split on, so it registers as the pattern "name" rather than as an empty
    # pattern. The C core behaves the same way, which is why it is pinned.
    ("trailing_tab_is_trimmed", "name\t\n", [("name", "name")]),
    # No trailing newline on the final line still parses.
    ("no_trailing_newline", "a\tone\nb\ttwo", [("a", "one"), ("b", "two")]),
    # CRLF: read_line() drops the '\r' before trim().
    ("crlf_line_endings", "a\tone\r\nb\ttwo\r\n", [("a", "one"), ("b", "two")]),
]
