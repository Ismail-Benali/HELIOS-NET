"""Boundary tests for the untrusted-banner sanitiser.

`core.input_guard` is the only place raw socket text is allowed to become a
banner. These tests pin the two properties the cores rely on: nothing
non-printable survives, and the UTF-8 encoding of the result never exceeds the
cap regardless of how the input is composed.
"""

from __future__ import annotations

from core.input_guard import MAX_BANNER_BYTES, sanitize_banner


def test_empty_input_is_returned_as_empty() -> None:
    assert sanitize_banner("") == ""


def test_printable_text_is_unchanged() -> None:
    banner = "SSH-2.0-OpenSSH_9.8p1 Ubuntu-24.04"
    assert sanitize_banner(banner) == banner


def test_control_characters_are_removed() -> None:
    assert sanitize_banner("a\x01b\x00c\x1bd") == "abcd"


def test_whitespace_that_is_printable_is_kept() -> None:
    assert sanitize_banner("HTTP/1.1 200 OK") == "HTTP/1.1 200 OK"


def test_ascii_input_is_capped_at_the_byte_limit() -> None:
    assert sanitize_banner("A" * (MAX_BANNER_BYTES + 100)) == "A" * MAX_BANNER_BYTES


def test_exact_limit_is_not_truncated() -> None:
    banner = "B" * MAX_BANNER_BYTES
    assert sanitize_banner(banner) == banner


def test_multibyte_input_cannot_exceed_the_byte_limit() -> None:
    result = sanitize_banner("\u20ac" * MAX_BANNER_BYTES)
    assert len(result.encode("utf-8")) <= MAX_BANNER_BYTES
    assert result == "\u20ac" * (MAX_BANNER_BYTES // 3)


def test_custom_limit_is_respected() -> None:
    assert sanitize_banner("abcdef", max_bytes=3) == "abc"
