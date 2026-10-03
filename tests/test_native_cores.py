"""HELIOS-NET :: tests/test_native_cores.py
Integration tests for the native cores: Rust (ctypes) and C (subprocess).
"""

from __future__ import annotations

from core.envelope import parse_envelope
from core.rust_bridge import match_signatures_rust, rust_available, rust_version
from engine.pattern_matcher import AhoCorasickMatcher
from transport import banner_fingerprint, match_banner


def test_rust_library_is_loaded():
    assert rust_available(), "rust-core library not built; run `python build.py`"
    assert "Rust Core" in rust_version()


def test_rust_signature_matching():
    hits = match_signatures_rust(
        "SSH-2.0-OpenSSH_9.6 on ubuntu", ["openssh", "apache", "nginx"]
    )
    assert "openssh" in hits
    assert "apache" not in hits


def test_rust_matcher_empty_inputs():
    assert match_signatures_rust("", ["openssh"]) == []
    assert match_signatures_rust("anything", []) == []


def test_pattern_matcher_still_returns_hits():
    matcher = AhoCorasickMatcher()
    matcher.load_defaults()
    hits = matcher.match("HTTP/1.1 200 OK Server: nginx/1.24.0")
    assert any(h["signature"] == "nginx" for h in hits)


def test_pattern_matcher_all_patterns_is_populated():
    matcher = AhoCorasickMatcher()
    matcher.load_defaults()
    assert "openssh" in matcher.all_patterns()


def test_c_matcher_bridge_handles_missing_binary():
    offset = match_banner("SSH-2.0-OpenSSH_9.6", "OpenSSH")
    assert offset == -1 or offset >= 0


def test_c_fingerprint_bridge_handles_missing_binary():
    digest = banner_fingerprint("HTTP/1.1 200 OK")
    assert digest == "" or digest.startswith("0x")


def test_pattern_matcher_labels_the_engine_that_produced_each_match(monkeypatch):
    """Every match must say which engine produced it.

    This was the one place in the project that could misreport its own results.
    The native path and the Python path returned dicts of identical shape, so a
    result produced while a core was blocked by host policy was
    indistinguishable from a native one. The test asserts the two are now
    distinguishable, and that a degraded run also explains itself.
    """
    from engine.pattern_matcher import AhoCorasickMatcher

    banner = "HTTP/1.1 200 OK Server: nginx/1.24.0"

    matcher = AhoCorasickMatcher()
    matcher.load_defaults()
    native = matcher.match(banner)
    assert native, "expected the default signatures to match"
    assert {m["engine"] for m in native} <= {
        "c-native",
        "rust-native",
        "python-fallback",
    }
    assert all("engine" in m for m in native)

    # Withdrawing every native core is what forces the floor. Nulling the Rust
    # library alone no longer does, because the matcher now asks the C core
    # first and that one is present on this host.
    monkeypatch.setattr("core.c_core_bridge.core_available", lambda: False)
    monkeypatch.setattr("core.rust_bridge.rust_available", lambda: False)

    degraded = AhoCorasickMatcher()
    degraded.load_defaults()
    fallback = degraded.match(banner)

    assert fallback, "the python fallback must still match"
    assert {m["engine"] for m in fallback} == {"python-fallback"}, fallback
    reason = degraded.last_engine_reason.lower()
    assert "c" in reason and "rust" in reason, (
        f"a degraded run must explain which cores it skipped, got {reason!r}"
    )

    # Same matches, different provenance: the label is the whole difference.
    assert [m["signature"] for m in native] == [m["signature"] for m in fallback]
    assert native != fallback or {m["engine"] for m in native} == {"python-fallback"}


def test_pattern_matcher_does_not_dress_python_results_as_native(monkeypatch):
    """A core that errors must not yield matches labelled as that core."""
    from engine import pattern_matcher as pm

    def boom(text, patterns):
        raise RuntimeError("simulated native failure")

    # The unified layer calls match_json_rust, not match_signatures_rust, so the
    # failure is injected where the layer actually reaches the core. C is
    # withdrawn as well, because it is asked first and is present on this host.
    monkeypatch.setattr("core.rust_bridge.match_json_rust", boom, raising=False)
    monkeypatch.setattr("core.rust_bridge.rust_available", lambda: True, raising=False)
    monkeypatch.setattr("core.c_core_bridge.core_available", lambda: False)

    matcher = pm.AhoCorasickMatcher()
    matcher.load_defaults()
    hits = matcher.match("banner with openssh inside")
    assert hits, "the fallback must still work when the native call raises"
    assert {h["engine"] for h in hits} == {"python-fallback"}, hits
    assert "runtimeerror" in matcher.last_engine_reason.lower(), (
        matcher.last_engine_reason
    )


def test_error_envelope_parser():
    valid = '{"status": "error", "code": "EDR_BLOCKED", "message": "blocked"}'
    assert parse_envelope(valid)["code"] == "EDR_BLOCKED"

    assert parse_envelope("not json") is None
    assert parse_envelope('{"status": "ok"}') is None
    assert parse_envelope(None) is None
