"""HELIOS-NET :: tests/test_c_core.py
Integration tests for the native C signature & fingerprint core.

These tests verify the process contract, the NDJSON framing, and - critically -
that the pure-Python fallback produces byte-identical digests and matches to the
native core. That equivalence is what makes graceful degradation safe.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from core.c_core_bridge import (
    core_available,
    core_version,
    crc32_py,
    fnv1a32_py,
    fnv1a64_py,
    fingerprint,
    scan_banners,
    selftest,
)

ROOT = Path(__file__).resolve().parent.parent
SIGS = ROOT / "config" / "scope.yaml"


def _native_c_runnable() -> tuple[bool, str]:
    """True when the C core is built AND the host will actually execute it.

    Existence on disk is not enough. A host application-control policy refuses a
    freshly linked unsigned binary, and every test below that shells out to it
    then raises WinError 4551. Reporting that as a test failure would blame the
    code for an environment decision, and would turn the whole suite red on any
    locked-down host while proving nothing about the C core. The health probe
    already separates BLOCKED from FAILED, so the tests defer to it.
    """
    if not core_available():
        return False, "C core binary not built; run `python build.py`"
    from core.cores import BLOCKED, check_c

    status = check_c()
    if status.state == BLOCKED:
        return False, "host application-control policy refuses to execute the C core"
    return True, ""


_C_RUNNABLE, _C_SKIP_REASON = _native_c_runnable()

requires_core = pytest.mark.skipif(not _C_RUNNABLE, reason=_C_SKIP_REASON)


@pytest.fixture(scope="module")
def signature_file(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("sigs") / "signatures.txt"
    path.write_text(
        "\n".join([
            "# comment line is ignored",
            "",
            "openssh\topenssh",
            "nginx",
            "microsoft-iis",
            "mariadb",
        ]),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------- discovery

@requires_core
def test_core_binary_is_located():
    assert core_available()
    assert core_version() not in ("unavailable", "unknown")


@requires_core
def test_native_selftest_reports_zero_failures():
    result = selftest()
    assert result.get("failures") == 0, result
    assert result.get("status") == "ok"


# ------------------------------------------------------------ hash vectors

def test_hash_vectors_match_published_values():
    assert fnv1a32_py("a") == 0xE40C292C
    assert fnv1a32_py("foobar") == 0xBF9CF968
    assert fnv1a64_py("a") == 0xAF63DC4C8601EC8C
    assert fnv1a64_py("foobar") == 0x85944171F73967E8
    assert crc32_py("123456789") == 0xCBF43926
    assert crc32_py("") == 0


# ------------------------------------------------- native / fallback parity

@requires_core
def test_native_digests_match_python_fallback(signature_file):
    """The native core and the Python fallback must agree byte-for-byte.

    If they ever diverge, a degraded campaign would silently produce different
    fingerprints than a healthy one.
    """
    banners = [
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu",
        "HTTP/1.1 200 OK Server: nginx/1.24.0",
        "unicode banner: \u00e9\u00e8\u00ea",
        "",
        "a" * 300,
    ]

    native = scan_banners(banners, signature_file)

    # Force the fallback by pointing the loader at a non-existent binary.
    import core.c_core_bridge as bridge

    original = bridge._BINARY
    try:
        bridge._BINARY = None
        fallback = scan_banners(banners, signature_file)
    finally:
        bridge._BINARY = original

    assert len(native) == len(banners)
    assert len(fallback) == len(banners)

    for n, f in zip(native, fallback):
        assert n["fp_fnv1a32"] == f["fp_fnv1a32"]
        assert n["fp_fnv1a64"] == f["fp_fnv1a64"]
        assert n["fp_crc32"] == f["fp_crc32"]
        assert [m["signature"] for m in n["matches"]] == \
               [m["signature"] for m in f["matches"]]


# ------------------------------------------------------------------ matching

@requires_core
def test_scan_reports_expected_signatures(signature_file):
    results = scan_banners([
        "SSH-2.0-OpenSSH_9.6p1",
        "Server: nginx/1.24",
        "Server: Microsoft-IIS/10.0",
        "completely unrelated text",
    ], signature_file)

    assert [r["match_count"] for r in results] == [1, 1, 1, 0]
    assert results[0]["matches"][0]["signature"] == "openssh"
    assert results[0]["matches"][0]["position"] == 8
    assert results[2]["matches"][0]["signature"] == "microsoft-iis"
    assert results[3]["matches"] == []


@requires_core
def test_matching_is_case_insensitive(signature_file):
    results = scan_banners(["SERVER: NGINX/1.24"], signature_file)
    assert results[0]["match_count"] == 1


@requires_core
def test_each_banner_yields_one_result_object(signature_file):
    """NDJSON framing: one output line per input line, order preserved."""
    banners = [f"banner number {i}" for i in range(25)]
    results = scan_banners(banners, signature_file)
    assert len(results) == 25
    assert [r["banner"] for r in results] == banners


@requires_core
def test_fingerprint_returns_all_three_digests():
    digests = fingerprint("HTTP/1.1 200 OK")
    assert set(digests) == {"fp_fnv1a32", "fp_fnv1a64", "fp_crc32"}
    for value in digests.values():
        assert value.startswith("0x")
        assert len(value) in (10, 18)


def test_fingerprint_falls_back_when_binary_absent(monkeypatch):
    import core.c_core_bridge as bridge

    monkeypatch.setattr(bridge, "_BINARY", None)
    digests = bridge.fingerprint("HTTP/1.1 200 OK")
    assert digests["fp_fnv1a32"] == f"0x{fnv1a32_py('HTTP/1.1 200 OK'):08X}"


# ------------------------------------------------------------- edge cases

def test_empty_banner_list_returns_empty(signature_file):
    assert scan_banners([], signature_file) == []


@requires_core
def test_hostile_signature_name_cannot_forge_json(tmp_path):
    """A signature name is attacker-controlled text, so it must be data.

    The NDJSON emitter used to interpolate the name into a format string via
    snprintf with a %s for a size the caller did not control, which let a name
    containing a quote close the string and append a sibling key. That produced
    well-formed JSON with an extra field the Python side would then trust. This
    asserts on the parsed object rather than the raw line, so a passing test
    cannot be satisfied by output that happens to look right.

    tests/verify_c_ndjson.py covers the same class through the CLI, but it is a
    side-effecting script that pytest's default discovery does not collect, so
    the guarantee was only checked when someone remembered to run it by hand.
    """
    sig = tmp_path / "hostile.txt"
    hostile_name = 'evil","injected":"yes'
    sig.write_text(hostile_name + "\tpatternZZZ", encoding="utf-8")

    raw = _run_match(sig, ["patternZZZ"])
    line = raw.strip().splitlines()[-1]
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:  # pragma: no cover - failure path
        pytest.fail(f"core emitted invalid JSON: {exc}\n{line!r}")

    assert parsed.get("status") == "ok", parsed
    matches = parsed.get("matches") or []
    assert matches, "the pattern should still match; a silent miss is also a bug"
    for match in matches:
        # The name round-trips as data, character for character, and the object
        # carries no field beyond the two the contract defines.
        assert set(match) == {"signature", "position"}, match
        assert match["signature"] == hostile_name, match
        assert "injected" not in match, f"injected key survived: {match}"

    # The same input through the bridge must return the name unchanged rather
    # than raising or fabricating a truncated version of it.
    for row in scan_banners(["patternZZZ"], sig):
        for match in row.get("matches", []):
            assert set(match) == {"signature", "position"}, match
            assert match["signature"] == hostile_name, match


def _run_match(sig: Path, banners) -> str:
    from core.c_core_bridge import _BINARY

    proc = subprocess.run(
        [str(_BINARY), "match", str(sig)],
        input="\n".join(banners),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60.0,
    )
    assert proc.stdout.strip(), f"no output; stderr={proc.stderr!r}"
    return proc.stdout


def test_missing_signature_file_returns_empty():
    assert scan_banners(["anything"], ROOT / "does-not-exist.txt") == []


@requires_core
def test_bom_prefixed_signature_file_does_not_corrupt_the_first_name(tmp_path):
    """A BOM must not become part of the first signature name.

    PowerShell 5.1 and Notepad write a UTF-8 BOM by default, so this is the
    common case, not an exotic one. Both paths must strip it: the native core
    and the Python fallback, because a BOM handled in one and not the other
    means a degraded campaign scores differently from a healthy one.
    """
    import core.c_core_bridge as bridge

    bom = tmp_path / "bom.txt"
    bom.write_bytes(b"\xef\xbb\xbfalpha\tfoo\nbeta\tfoo\n")

    def native_and_fallback(sig):
        native = bridge.scan_banners(["a foo b"], sig)
        original = bridge._BINARY
        try:
            bridge._BINARY = None
            fallback = bridge.scan_banners(["a foo b"], sig)
        finally:
            bridge._BINARY = original
        return native, fallback

    nat, fb = native_and_fallback(bom)
    assert [m["signature"] for m in nat[0]["matches"]] == ["alpha", "beta"], (
        f"native kept the BOM: {[m['signature'] for m in nat[0]['matches']]!r}"
    )
    assert [m["signature"] for m in fb[0]["matches"]] == ["alpha", "beta"], (
        f"fallback kept the BOM: {[m['signature'] for m in fb[0]['matches']]!r}"
    )

    # A BOM on a line with no name column must not corrupt the pattern either,
    # or the signature silently stops matching anything.
    bare = tmp_path / "bare.txt"
    bare.write_bytes(b"\xef\xbb\xbffoo\n")
    nat, fb = native_and_fallback(bare)
    assert [m["signature"] for m in nat[0]["matches"]] == ["foo"], nat[0]["matches"]
    assert [m["signature"] for m in fb[0]["matches"]] == ["foo"], fb[0]["matches"]


@requires_core
def test_duplicate_registration_counts_once_but_shared_pattern_keeps_both(tmp_path):
    """Native and fallback must agree on duplicate handling.

    Two names sharing one pattern are two real signatures and both are reported.
    An identical line repeated is a duplicated input and counts once, because
    storing it twice made one detection emit the same name twice and inflate
    match_count. The Rust port has no name/pattern split, so it drops a repeated
    label; that is correct for its pattern-only contract and is not compared
    here. The property that matters is that the two C paths never diverge.
    """
    import core.c_core_bridge as bridge

    shared = tmp_path / "shared.txt"
    shared.write_text("alpha\tfoo\nbeta\tfoo\n", encoding="utf-8")
    repeated = tmp_path / "repeated.txt"
    repeated.write_text("alpha\tfoo\nalpha\tfoo\n", encoding="utf-8")

    def native_and_fallback(sig):
        native = bridge.scan_banners(["a foo b"], sig)
        original = bridge._BINARY
        try:
            bridge._BINARY = None
            fallback = bridge.scan_banners(["a foo b"], sig)
        finally:
            bridge._BINARY = original
        return native, fallback

    nat, fb = native_and_fallback(shared)
    assert [m["signature"] for m in nat[0]["matches"]] == ["alpha", "beta"]
    assert [m["signature"] for m in fb[0]["matches"]] == ["alpha", "beta"]
    assert nat[0]["match_count"] == fb[0]["match_count"] == 2

    nat, fb = native_and_fallback(repeated)
    assert [m["signature"] for m in nat[0]["matches"]] == ["alpha"]
    assert [m["signature"] for m in fb[0]["matches"]] == ["alpha"]
    assert nat[0]["match_count"] == fb[0]["match_count"] == 1


def test_fallback_handles_comments_and_blank_lines(tmp_path):
    import core.c_core_bridge as bridge

    sig = tmp_path / "s.txt"
    sig.write_text("# comment\n\nalpha\talpha\nbeta\n", encoding="utf-8")

    monkey = None
    original = bridge._BINARY
    try:
        bridge._BINARY = None
        results = bridge.scan_banners(["xx alpha xx beta xx"], sig)
    finally:
        bridge._BINARY = original

    names = sorted(m["signature"] for m in results[0]["matches"])
    assert names == ["alpha", "beta"]


# ----------------------------------------------------------- CLI contract

@requires_core
def test_cli_version_subcommand_emits_json():
    from core.c_core_bridge import _BINARY

    proc = subprocess.run([str(_BINARY), "version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["component"] == "c_core"


@requires_core
def test_cli_rejects_unknown_subcommand():
    from core.c_core_bridge import _BINARY

    proc = subprocess.run([str(_BINARY), "nonsense"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert proc.returncode == 2
    assert "Usage" in proc.stderr


@requires_core
def test_cli_reports_missing_signature_file():
    from core.c_core_bridge import _BINARY

    proc = subprocess.run(
        [str(_BINARY), "match", str(ROOT / "no-such-sigs.txt")],
        input="banner\n", capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 3
    assert json.loads(proc.stderr.strip())["code"] == "SIG_LOAD_FAILED"
