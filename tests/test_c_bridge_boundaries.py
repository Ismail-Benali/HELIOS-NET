"""Boundary behaviour of the C-core bridge.

The core contract is byte-faithful: it reports matches at UTF-8 byte offsets and
it does not rewrite its input. Text sanitisation belongs to the network boundary
(`core.input_guard`), so these tests drive the bridge with the inputs a hostile
or broken service can produce and pin two things: it answers instead of raising,
and it keeps reporting offsets in bytes. They pin the Python fallback because it
must be able to stand in for the native core at any moment, and because the
native path is skipped on hosts whose application-control policy blocks freshly
linked binaries.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest

from core import c_core_bridge as bridge


@pytest.fixture
def fallback(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Pins `scan_banners` to the in-process path on every host."""
    monkeypatch.setattr(bridge, "_BINARY", None)
    monkeypatch.setattr(bridge, "_open_signatures", lambda _path: None)
    return bridge


def _signatures(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "signatures.txt"
    path.write_text(text, encoding="utf-8")
    return path


def _names(result: dict) -> list[str]:
    return sorted(match["signature"] for match in result["matches"])


def test_an_oversized_banner_is_answered_not_rejected(fallback, tmp_path):
    banner = "x" * 65_536 + "needle"
    result = fallback.scan_banners([banner], _signatures(tmp_path, "sig\tneedle"))

    assert len(result) == 1
    assert _names(result[0]) == ["sig"]
    assert result[0]["matches"][0]["position"] == 65_536


def test_an_embedded_newline_stays_one_banner(fallback, tmp_path):
    result = fallback.scan_banners(["a\nneedle"], _signatures(tmp_path, "sig\tneedle"))

    assert len(result) == 1, "newlines are data, not record separators"
    assert result[0]["matches"][0]["position"] == 2


def test_multibyte_text_is_reported_at_byte_offsets(fallback, tmp_path):
    result = fallback.scan_banners(
        ["\u00e9needle"], _signatures(tmp_path, "sig\tneedle")
    )

    assert result[0]["matches"][0]["position"] == 2, "one char, two UTF-8 bytes"


def test_a_nul_byte_is_preserved_by_the_bridge(fallback, tmp_path):
    result = fallback.scan_banners(
        ["a\x00needle"], _signatures(tmp_path, "sig\tneedle")
    )

    assert result[0]["matches"][0]["position"] == 2
    assert result[0]["banner"] == "a\x00needle", "sanitisation is not the bridge's job"


def test_invalid_utf8_signature_bytes_do_not_raise(fallback, tmp_path):
    path = tmp_path / "garbage.txt"
    path.write_bytes(b"\xff\xfe needle\nsig\tneedle\n")
    result = fallback.scan_banners(["needle"], path)

    assert len(result) == 1
    assert "sig" in _names(result[0])


def test_a_pattern_longer_than_the_banner_cannot_match(fallback, tmp_path):
    result = fallback.scan_banners(
        ["short"], _signatures(tmp_path, "sig\tshort-pattern")
    )

    assert result[0]["matches"] == []
    assert result[0]["match_count"] == 0


def test_crlf_signature_files_keep_the_pattern_intact(fallback, tmp_path):
    path = tmp_path / "crlf.txt"
    path.write_bytes(b"sig\tneedle\r\n")
    result = fallback.scan_banners(["a needle b"], path)

    assert _names(result[0]) == ["sig"]


def test_an_empty_banner_is_a_valid_question(fallback, tmp_path):
    result = fallback.scan_banners([""], _signatures(tmp_path, "sig\tneedle"))

    assert len(result) == 1
    assert result[0]["status"] == "ok"
    assert result[0]["matches"] == []
