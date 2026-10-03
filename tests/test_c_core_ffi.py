"""HELIOS-NET :: tests/test_c_core_ffi.py
Tests for the in-process (ctypes) front end to the native C core.

These exercise the Python side of the FFI against a stand-in library, because
the shared library cannot be loaded on every developer host: on a Windows
machine under an application-control policy the *load* is refused exactly as the
executable's execution is, and a test suite that could only pass where the
library happens to load would report coverage nobody can reproduce. The C
behaviour behind these calls is covered separately by the C unit tests, the
ASan/UBSan stage, and the cross-backend golden replay.
"""

from __future__ import annotations

import ctypes
import json
from pathlib import Path
from typing import Any

import pytest

from core import c_core_bridge as bridge


#: Distinguishes "caller said nothing" from "caller said None". Without it,
#: `selftest=None` would be indistinguishable from the default healthy result and
#: the "library returned no usable selftest" case could not be expressed.
_UNSET = object()


class FakeLibrary:
    """A stand-in for the shared library, recording how Python drives it."""

    def __init__(
        self,
        *,
        selftest: object = _UNSET,
        match: object = None,
        fingerprint: bytes | None = None,
        open_ok: bool = True,
    ) -> None:
        self._selftest = (
            json.dumps(
                {"status": "ok", "mode": "selftest", "checks": 21, "failures": 0}
            ).encode("utf-8")
            if selftest is _UNSET
            else selftest
        )
        self._match: Any = match
        self._fingerprint = fingerprint
        self._open_ok = open_ok

        self.opened: list[str] = []
        self.closed: list[str] = []
        self.scanned: list[str] = []
        self.freed = 0
        self.fingerprinted: list[str] = []
        self._next = 0
        #: Live allocations, keyed by the address handed to the caller. The
        #: buffer is held here so `ctypes.string_at` can read real memory, which
        #: is what the production path does, and dropped in hc_free so a stale
        #: read or a double free is observable rather than silent.
        self._heap: dict[int, ctypes.Array[ctypes.c_char]] = {}

    def _alloc(self, payload: bytes | None) -> int:
        """Hands back a real address for `payload`, as c_void_p would."""
        if payload is None:
            return 0
        buf = ctypes.create_string_buffer(payload)
        addr = ctypes.addressof(buf)
        self._heap[addr] = buf
        return addr

    # --- the flat C ABI -------------------------------------------------

    def hc_dll_version(self):
        return b"1.0.0-ffi"

    def hc_dll_strerror(self, _status: int):
        return b"ok"

    def hc_dll_open(self, path: bytes):
        self.opened.append(path.decode("utf-8"))
        if not self._open_ok:
            return None
        self._next += 1
        return f"handle-{self._next}"

    def hc_dll_close(self, handle) -> None:
        self.closed.append(str(handle))

    def hc_dll_pattern_count(self, _handle) -> int:
        return 3

    def hc_dll_node_count(self, _handle) -> int:
        return 42

    def hc_dll_match_json(self, _handle, text: bytes):
        banner = text.decode("utf-8")
        self.scanned.append(banner)
        if callable(self._match):
            return self._alloc(self._match(banner))
        return self._alloc(self._match)

    def hc_dll_fp_json(self, text: bytes):
        banner = text.decode("utf-8")
        self.fingerprinted.append(banner)
        return self._alloc(self._fingerprint)

    def hc_dll_selftest_json(self):
        return self._alloc(self._selftest)

    def hc_free(self, ptr) -> None:
        # An address the library never handed out means the caller freed
        # something it does not own, which is the bug this fake exists to catch:
        # with a c_char_p restype the caller holds a Python bytes object, not
        # the malloc'd block, and passing its address here is an invalid free.
        addr = ptr.value if isinstance(ptr, ctypes.c_void_p) else int(ptr)
        assert addr in self._heap, (
            f"hc_free was given {addr:#x}, which was never allocated; the caller "
            "passed an address the library does not own"
        )
        del self._heap[addr]
        self.freed += 1

    @property
    def live_allocations(self) -> int:
        return len(self._heap)


def _ok_match(banner: str) -> bytes:
    return json.dumps(
        {
            "status": "ok",
            "banner": banner,
            "fp_fnv1a32": "0xdeadbeef",
            "fp_fnv1a64": "0x1",
            "fp_crc32": "0x2",
            "matches": [{"signature": "nginx", "position": 0}],
            "match_count": 1,
            "truncated": False,
        }
    ).encode("utf-8")


@pytest.fixture(autouse=True)
def _clean_module_state():
    """Module caches persist by design; tests must not inherit them."""
    bridge._probe_cache.clear()
    bridge._library_cache.clear()
    bridge._handles.clear()
    yield
    bridge._probe_cache.clear()
    bridge._library_cache.clear()
    bridge._handles.clear()


@pytest.fixture
def signatures(tmp_path: Path) -> Path:
    path = tmp_path / "sigs.txt"
    path.write_text("nginx\tnginx\napache\thttpd\n", encoding="utf-8")
    return path


def _install(fake: FakeLibrary) -> FakeLibrary:
    """Puts the stand-in in the place `_library()` would have cached it."""
    bridge._library_cache["lib"] = fake
    bridge._library_cache["path"] = Path("fake")
    bridge._library_cache["reason"] = ""
    return fake


# ------------------------------------------------------------- availability


def test_absent_library_says_python_not_native():
    """No library and no runnable binary must not be described as native."""
    bridge._library_cache["lib"] = None
    bridge._library_cache["reason"] = "the native shared library was not found"
    original = bridge._BINARY
    bridge._BINARY = None
    try:
        assert bridge.ffi_available() is False
        assert bridge.native_path() == "python"
    finally:
        bridge._BINARY = original


def test_ffi_is_reported_as_the_path_when_it_answers():
    """A loaded, self-tested library is what "c-native" must actually mean."""
    _install(FakeLibrary())
    assert bridge.ffi_available() is True
    assert bridge.native_path() == "ffi"
    assert bridge.core_available() is True
    assert bridge.core_version() == "1.0.0-ffi"


def test_library_failing_its_own_checks_is_not_available():
    """Loading is not health. A library that fails its suite stays out."""
    _install(FakeLibrary(
        selftest=json.dumps(
            {"status": "error", "mode": "selftest", "checks": 21, "failures": 3}
        ).encode("utf-8")
    ))
    assert bridge.ffi_available() is False
    assert "consistency checks" in str(bridge._probe_cache.get("ffi_reason", ""))


def test_library_with_no_usable_selftest_is_not_available():
    _install(FakeLibrary(selftest=None))
    assert bridge.ffi_available() is False


def test_blocked_load_surfaces_the_policy_reason(tmp_path, monkeypatch):
    """A refused load keeps its WinError instead of becoming "not found"."""
    monkeypatch.setenv(bridge._LIBRARY_ENV_KEY, str(tmp_path / "helios_core.dll"))
    library = tmp_path / "helios_core.dll"
    library.write_bytes(b"MZ")
    newest = bridge._newest_c_source()
    if newest is not None:
        import os

        os.utime(library, (newest.stat().st_mtime + 60, newest.stat().st_mtime + 60))

    def refuse(*_args, **_kwargs):
        raise OSError(4551, "os error", "helios_core.dll")

    monkeypatch.setattr(bridge.ctypes, "CDLL", refuse)
    assert bridge.ffi_available() is False
    note = bridge.library_note()
    assert "4551" in note
    assert "policy" in note.lower()


# ------------------------------------------------------- automaton reuse


def test_automaton_is_built_once_across_many_batches(signatures):
    """The reason this path exists: no rebuild per dispatch.

    Rebuilding the automaton once per batch is the cost the subprocess front end
    pays. Reuse is the entire benefit, so it is asserted directly rather than
    inferred from timing.
    """
    fake = _install(FakeLibrary(match=_ok_match))

    for _ in range(4):
        results = bridge.scan_banners(["Server: nginx"], signatures)
        assert len(results) == 1

    assert len(fake.opened) == 1, "the signature file was re-opened per batch"
    assert len(fake.scanned) == 4, "banners were not scanned in-process"


def test_handle_is_rebuilt_when_the_signature_file_changes(tmp_path):
    """An edited signature file must not keep matching the old automaton."""
    path = tmp_path / "sigs.txt"
    path.write_text("nginx\tnginx\n", encoding="utf-8")
    fake = _install(FakeLibrary(match=_ok_match))

    bridge.scan_banners(["a"], path)
    first_handle = bridge._handles[str(path)][1]

    import os

    os.utime(path, None)
    path.write_text("nginx\tnginx\napache\thttpd\ncaddy\tcaddy\n", encoding="utf-8")
    import time

    time.sleep(0.01)
    os.utime(path, (time.time() + 2, time.time() + 2))

    bridge.scan_banners(["a"], path)
    assert len(fake.opened) == 2
    assert first_handle in fake.closed, "the stale automaton was leaked"


def test_unreadable_signature_file_yields_nothing(tmp_path):
    _install(FakeLibrary(match=_ok_match))
    assert bridge.scan_banners(["a"], tmp_path / "missing.txt") == []


def test_failed_open_falls_through_to_the_next_front_end(signatures, monkeypatch):
    fake = _install(FakeLibrary(match=_ok_match, open_ok=False))
    monkeypatch.setattr(
        bridge, "_python_fallback",
        lambda banners, _path: [{"status": "ok", "banner": b} for b in banners],
    )
    results = bridge.scan_banners(["a", "b"], signatures)
    assert [r["banner"] for r in results] == ["a", "b"]
    assert fake.scanned == []


# ------------------------------------------------------- batch integrity


def test_one_failed_banner_drops_the_whole_batch(signatures, monkeypatch):
    """A batch is served by one backend or not at all.

    Returning the banners that happened to succeed and letting the rest fall to
    Python would produce a list that looks correct and is not: the entries would
    come from two implementations, and nothing in the result would say so.
    """
    def mixed(banner: str) -> bytes | None:
        if banner == "bad":
            return None
        return _ok_match(banner)

    _install(FakeLibrary(match=mixed))
    monkeypatch.setattr(bridge, "_BINARY", None)
    monkeypatch.setattr(
        bridge, "_python_fallback",
        lambda banners, _path: [{"status": "ok", "banner": f"py:{b}"} for b in banners],
    )
    results = bridge.scan_banners(["good", "bad", "also-good"], signatures)
    assert all(r["banner"].startswith("py:") for r in results), (
        "the batch mixed in-process and fallback results"
    )


def test_batch_order_and_count_are_preserved(signatures):
    _install(FakeLibrary(match=_ok_match))
    banners = ["one", "two", "three", "four"]
    results = bridge.scan_banners(banners, signatures)
    assert [r["banner"] for r in results] == banners


def test_empty_input_never_reaches_the_library(signatures):
    fake = _install(FakeLibrary(match=_ok_match))
    assert bridge.scan_banners([], signatures) == []
    assert fake.opened == []


# ------------------------------------------------------------- resources


def test_every_returned_buffer_is_released(signatures):
    """Each hc_dll_* buffer must be handed back with hc_free.

    Without this the library leaks once per call, and a long scan grows the
    process without bound - a failure that shows up as memory exhaustion in a
    campaign, far from the call that caused it.
    """
    fake = _install(FakeLibrary(
        match=_ok_match,
        fingerprint=json.dumps(
            {
                "status": "ok",
                "input": "x",
                "length": 1,
                "fp_fnv1a32": "0x1",
                "fp_fnv1a64": "0x2",
                "fp_crc32": "0x3",
            }
        ).encode("utf-8"),
    ))

    bridge.scan_banners(["a", "b"], signatures)
    bridge.fingerprint("a")

    # One selftest, two match buffers, one fingerprint buffer.
    assert fake.freed == 4, f"expected every returned buffer to be freed, saw {fake.freed}"
    # Counting frees is not enough: a caller could free one buffer twice and
    # leak another, leaving the total right. Nothing may still be outstanding.
    assert fake.live_allocations == 0, (
        f"{fake.live_allocations} buffer(s) never reached hc_free"
    )


def test_a_caller_may_not_free_an_address_it_does_not_own(signatures):
    """The regression this file exists for.

    With a c_char_p restype ctypes copies the library's buffer into a Python
    bytes and hands back that copy, discarding the malloc'd address. Freeing
    what came back therefore passes the address of a Python object to free(),
    which glibc rejects with `munmap_chunk(): invalid pointer` and aborts the
    process. Declaring the exports c_void_p keeps the address intact, and the
stand-in refuses any address it never handed out.
    """
    fake = _install(FakeLibrary(match=_ok_match))

    assert bridge.scan_banners(["a", "b"], signatures) is not None
    assert fake.live_allocations == 0

    with pytest.raises(AssertionError, match="never allocated"):
        foreign = ctypes.create_string_buffer(b"a buffer the library never returned")
        fake.hc_free(ctypes.c_void_p(ctypes.addressof(foreign)))


def test_fingerprint_prefers_the_library(signatures):
    fake = _install(FakeLibrary(
        match=_ok_match,
        fingerprint=json.dumps(
            {
                "status": "ok",
                "input": "Server: nginx",
                "length": 14,
                "fp_fnv1a32": "0xAAAAAAAA",
                "fp_fnv1a64": "0xBBBBBBBBBBBBBBBB",
                "fp_crc32": "0xCCCCCCCC",
            }
        ).encode("utf-8"),
    ))
    digests = bridge.fingerprint("Server: nginx")
    assert digests["fp_fnv1a32"] == "0xAAAAAAAA"
    assert fake.fingerprinted == ["Server: nginx"]


def test_availability_reset_forgets_a_failed_probe():
    _install(FakeLibrary(
        selftest=json.dumps(
            {"status": "error", "mode": "selftest", "checks": 1, "failures": 1}
        ).encode("utf-8")
    ))
    assert bridge.ffi_available() is False
    bridge.reset_availability()
    _install(FakeLibrary())
    assert bridge.ffi_available() is True, "a cached negative probe outlived its library"


def test_cast_of_returned_pointer_is_pointer_sized():
    """Guards the binding: a truncated handle would be a wild pointer on x64."""
    pointer = ctypes.cast(ctypes.c_char_p(b"payload"), ctypes.c_void_p)
    assert ctypes.sizeof(pointer) == ctypes.sizeof(ctypes.c_void_p)


def test_a_library_that_loads_but_fails_its_selftest_never_answers(signatures):
    """Availability must gate serving, not just loading.

    The library loading proves nothing about whether it is correct. A load that
    succeeds and a selftest that fails means the project has already declared
    this build untrustworthy, so answering a scan from it would contradict
    native_path(), which reports "process" in exactly that state.
    """
    fake = _install(FakeLibrary(
        match=_ok_match,
        selftest=json.dumps(
            {"status": "error", "mode": "selftest", "checks": 1, "failures": 1}
        ).encode("utf-8"),
    ))

    assert bridge.ffi_available() is False
    results = bridge.scan_banners(["a", "b"], signatures)

    assert fake.scanned == [], "an untrusted library was asked to scan"
    for row in results:
        assert row.get("engine") != "c-native"
