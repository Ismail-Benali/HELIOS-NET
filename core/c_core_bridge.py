"""HELIOS-NET :: core/c_core_bridge.py
Python interface to the native C signature & fingerprint core.

The core (`transport/c_core`) is a small C11 library with a streaming NDJSON
front end. This module owns the process contract: it locates the binary, feeds
banners on stdin, and parses one JSON result per line.

Every failure path degrades to a pure-Python fallback so a missing, unbuilt, or
host-blocked binary can never abort a campaign.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess  # nosec B404 - the native core is a project-built binary at a fixed path
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
_CORE_DIR = ROOT / "transport" / "c_core"

_EXE = ".exe" if os.name == "nt" else ""
_BINARY_CANDIDATES = (
    _CORE_DIR / "build" / f"helios_core{_EXE}",
    _CORE_DIR / f"helios_core{_EXE}",
)
_ENV_KEY = "HELIOS_C_CORE"

# The native core is byte-oriented and always speaks UTF-8 on stdin/stdout.
# Every subprocess call must therefore pin the encoding explicitly: relying on
# `text=True` alone would use the host locale (cp1252 on Windows) and silently
# hash non-ASCII banners as different bytes than the Python fallback does.
_IO_ENCODING = "utf-8"

# FNV-1a constants mirror transport/c_core/src/hashing.c so the Python fallback
# produces byte-identical digests to the native core.
_FNV32_OFFSET = 0x811C9DC5
_FNV32_PRIME = 0x01000193
_FNV64_OFFSET = 0xCBF29CE484222325
_FNV64_PRIME = 0x100000001B3
_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _newest_c_source() -> Path | None:
    """The most recently modified .c/.h the native core is built from."""
    inputs = [
        p
        for sub in ("src", "include", "tests")
        for p in (_CORE_DIR / sub).glob("*")
        if p.suffix in (".c", ".h")
    ]
    return max(inputs, key=lambda p: p.stat().st_mtime) if inputs else None


def staleness_note() -> str:
    """Why a present binary is not being used, or "" when it is current.

    A binary that predates its own source would otherwise be reported as a
    healthy core: `core_available()` used to test only that the file existed, so
    an out-of-date build could pass a health probe while describing code that is
    no longer in the tree. Falling back to the Python implementation is the safe
    direction, because it is at least the code in the repository.
    """
    for candidate in _BINARY_CANDIDATES:
        if not candidate.exists():
            continue
        newest = _newest_c_source()
        if newest is None or candidate.stat().st_mtime >= newest.stat().st_mtime:
            return ""
        return (
            f"{candidate.name} predates {newest.relative_to(_CORE_DIR)}; "
            "rebuild before trusting the native core"
        )
    return ""


def _locate_binary() -> Path | None:
    override = os.environ.get(_ENV_KEY)
    if override and Path(override).exists():
        return Path(override)
    newest = _newest_c_source()
    for candidate in _BINARY_CANDIDATES:
        if not candidate.exists():
            continue
        # A stale binary is worse than no binary: it answers with older code and
        # still looks healthy. Skip it and let the Python fallback serve.
        if newest is not None and candidate.stat().st_mtime < newest.stat().st_mtime:
            continue
        return candidate
    return None


_BINARY = _locate_binary()

#: Cached result of the execution probe behind `core_available()`, so a policy
#: refusal is paid for once instead of on every dispatch.
_probe_cache: dict[str, Any] = {}


# ------------------------------------------------------- shared library (FFI)
#
# The process front end costs a subprocess per batch and re-reads the signature
# file, which means rebuilding the Aho-Corasick automaton, for every call. The
# shared library exposes the same code in-process, so the automaton is built
# once and reused across batches.
#
# Both front ends run the *same* C functions (helios_batch.c) rather than a
# parallel implementation, so an FFI result and a CLI result cannot disagree
# about the same input. Where they could differ is in what this module *claims*
# about them, which is why the path in use is a first-class value: `ffi`,
# `process` or `python`, and never two of them at once.

_LIBRARY_ENV_KEY = "HELIOS_C_CORE_LIB"
_library_cache: dict[str, Any] = {}
_handles: dict[str, tuple[int, Any]] = {}


def _library_filename() -> str:
    if os.name == "nt":
        return "helios_core.dll"
    if sys.platform == "darwin":
        return "libhelios_core.dylib"
    return "libhelios_core.so"


def _locate_library() -> Path | None:
    """The shared library to load, or None.

    A library older than its sources is skipped for the same reason a stale
    executable is: it answers with code that is no longer in the tree, while
    still looking healthy.
    """
    override = os.environ.get(_LIBRARY_ENV_KEY)
    candidates = []
    if override:
        candidates.append(Path(override))
    name = _library_filename()
    candidates.append(_CORE_DIR / "build" / name)
    candidates.append(_CORE_DIR / name)

    newest = _newest_c_source()
    for candidate in candidates:
        if not candidate.exists():
            continue
        if newest is not None and candidate.stat().st_mtime < newest.stat().st_mtime:
            continue
        return candidate
    return None


def _bind(lib: Any) -> None:
    """Declares the C signatures Python will rely on.

    Without this, ctypes assumes `int` for every return value. A pointer-sized
    handle truncated to 32 bits survives only by accident on x64, and the
    resulting address is a wild pointer: the failure surfaces far from the call
    that caused it. `c_char_p` matters for the same reason, since a returned
    buffer pointer would otherwise be read as a small integer.
    """
    lib.hc_free.argtypes = [ctypes.c_void_p]
    lib.hc_free.restype = None

    lib.hc_dll_version.argtypes = []
    lib.hc_dll_version.restype = ctypes.c_char_p

    lib.hc_dll_strerror.argtypes = [ctypes.c_int]
    lib.hc_dll_strerror.restype = ctypes.c_char_p

    lib.hc_dll_open.argtypes = [ctypes.c_char_p]
    lib.hc_dll_open.restype = ctypes.c_void_p

    lib.hc_dll_close.argtypes = [ctypes.c_void_p]
    lib.hc_dll_close.restype = None

    lib.hc_dll_pattern_count.argtypes = [ctypes.c_void_p]
    lib.hc_dll_pattern_count.restype = ctypes.c_ulong

    lib.hc_dll_node_count.argtypes = [ctypes.c_void_p]
    lib.hc_dll_node_count.restype = ctypes.c_ulong

    lib.hc_dll_match_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.hc_dll_match_json.restype = ctypes.c_void_p

    lib.hc_dll_fp_json.argtypes = [ctypes.c_char_p]
    lib.hc_dll_fp_json.restype = ctypes.c_void_p

    lib.hc_dll_selftest_json.argtypes = []
    lib.hc_dll_selftest_json.restype = ctypes.c_void_p


def _library() -> Any | None:
    """The loaded shared library, or None. Cached, including the failure."""
    if "lib" in _library_cache:
        return _library_cache["lib"]

    path = _locate_library()
    lib: Any | None = None
    reason = "the native shared library was not found"
    if path is not None:
        try:
            lib = ctypes.CDLL(str(path))
        except OSError as exc:
            # Loading a DLL is subject to the same application-control policy as
            # executing one, and a refusal here is a policy decision, not a
            # missing file. It is reported through the same helper so the reason
            # keeps its WinError.
            reason = _describe_startup_failure(exc)
            lib = None
        else:
            try:
                _bind(lib)
            except AttributeError as exc:
                reason = (
                    f"the native shared library does not export the expected "
                    f"interface: {exc}"
                )
                lib = None
            else:
                reason = ""

    _library_cache["lib"] = lib
    _library_cache["path"] = path
    _library_cache["reason"] = reason
    return lib


def library_note() -> str:
    """Why the shared library is not in use. Empty when it loaded."""
    _library()
    return str(_library_cache.get("reason") or "")


def _library_present() -> bool:
    """True when a library file was found, whether or not it loaded.

    This distinction decides which diagnosis is reported. "There is no shared
    library" is not a diagnosis - it is the absence of a preferred path, and it
    says nothing about why the core could not be used. Letting that string
    displace a real one replaced "the host policy refused to execute the C core
    (WinError 4551)" with "the native shared library was not found", which is
    true, uninformative, and hides the only fact an operator can act on.
    """
    _library()
    return _library_cache.get("path") is not None


def _ffi_call(fn_name: str, *args: Any) -> bytes | None:
    """Calls a `char *`-returning export, copies it and releases the original.

    These three exports are declared c_void_p rather than c_char_p, and the
    distinction is the whole point. A c_char_p restype makes ctypes copy the
    buffer into a Python bytes and hand back *that*, discarding the malloc'd
    address; freeing whatever the call returned then hands the C library the
    address of a Python object, which is not an allocation it owns. glibc
    answers that with `munmap_chunk(): invalid pointer` and aborts the process.
    So the address is carried as an integer, the bytes are copied out with
    string_at, and hc_free() receives the pointer that malloc actually returned.

    The free is in a finally rather than after the copy so a decoding failure
    cannot leak the buffer.
    """
    lib = _library()
    if lib is None:
        return None
    raw = getattr(lib, fn_name)(*args)
    if not raw:
        return None
    try:
        return ctypes.string_at(raw)
    finally:
        lib.hc_free(ctypes.c_void_p(raw))


def _ffi_selftest() -> dict[str, Any] | None:
    """Runs the library's own consistency checks, or None when unavailable."""
    lib = _library()
    if lib is None:
        return None
    raw = _ffi_call("hc_dll_selftest_json")
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode(_IO_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def ffi_available() -> bool:
    """True when the shared library loaded *and* passed its own checks.

    Loading alone is not enough. A library can be present, current, and still
    disagree with the contract, so the same built-in suite the CLI runs is
    executed in-process first. Reporting availability from the load alone would
    repeat the original sin at a new address: a usable-looking handle that
    answers with the wrong numbers.
    """
    if "ffi" in _probe_cache:
        return bool(_probe_cache["ffi"])
    lib = _library()
    if lib is None:
        _probe_cache["ffi"] = False
        return False
    result = _ffi_selftest()
    healthy = False
    if result is not None and result.get("status") == "ok":
        # A library that reports an unreadable failure count is not evidence of
        # health. `int()` on an unparseable value would otherwise raise out of a
        # function whose entire job is to answer a yes/no question without
        # failing, turning a broken library into an exception at every call site.
        try:
            healthy = int(result.get("failures", 1) or 0) == 0
        except (TypeError, ValueError):
            healthy = False
    _probe_cache["ffi"] = healthy
    if not healthy:
        _probe_cache["ffi_reason"] = (
            "the native shared library failed its built-in consistency checks"
            if result
            else "the native shared library returned no usable selftest result"
        )
    return healthy


def ffi_version() -> str:
    """The library's version string, or "unavailable"."""
    lib = _library()
    if lib is None:
        return "unavailable"
    # Annotated rather than inferred: the handle is untyped, so `raw` would be
    # Any and the returned `Any` would escape into every caller of this function.
    raw: bytes | None = lib.hc_dll_version()
    if not raw:
        return "unknown"
    try:
        decoded: str = raw.decode(_IO_ENCODING)
    except UnicodeDecodeError:
        return "unknown"
    return decoded


def _open_signatures(sig_path: Path) -> Any | None:
    """Opens a signature file once and keeps the automaton.

    Keyed on the file's mtime: an edited signature file must not keep matching
    against the automaton built from the previous contents, and rebuilding on
    every dispatch is the cost this path exists to remove.
    """
    lib = _library()
    if lib is None:
        return None
    try:
        stamp = sig_path.stat().st_mtime_ns
    except OSError:
        return None

    key = str(sig_path)
    previous = _handles.get(key)
    if previous is not None:
        if previous[0] == stamp:
            return previous[1]
        # The file changed underneath us. The old automaton describes patterns
        # that are no longer there, so it is released rather than reused.
        lib.hc_dll_close(previous[1])
        del _handles[key]

    handle = lib.hc_dll_open(str(sig_path).encode(_IO_ENCODING))
    if not handle:
        return None
    _handles[key] = (stamp, handle)
    return handle


def _ffi_match(handle: Any, banner: str) -> dict[str, Any] | None:
    """Scans one banner in-process. None means "no usable answer"."""
    lib = _library()
    if lib is None:
        return None
    raw = _ffi_call("hc_dll_match_json", handle, banner.encode(_IO_ENCODING))
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode(_IO_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    if isinstance(parsed, dict) and parsed.get("status") == "ok":
        return parsed
    return None


def _ffi_fingerprint(banner: str) -> dict[str, str] | None:
    lib = _library()
    if lib is None:
        return None
    raw = _ffi_call("hc_dll_fp_json", banner.encode(_IO_ENCODING))
    if raw is None:
        return None
    try:
        parsed = json.loads(raw.decode(_IO_ENCODING))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or parsed.get("status") != "ok":
        return None
    return {
        "fp_fnv1a32": str(parsed["fp_fnv1a32"]),
        "fp_fnv1a64": str(parsed["fp_fnv1a64"]),
        "fp_crc32": str(parsed["fp_crc32"]),
    }


def native_path() -> str:
    """Which front end is actually serving: "ffi", "process" or "python".

    Reported so a caller can state the provenance of a result instead of
    inferring it from which binary happens to exist. Never returns a value for
    a path that did not run.
    """
    if ffi_available():
        return "ffi"
    if core_available():
        return "process"
    return "python"


def core_available() -> bool:
    """True when the native C core binary exists *and* the host will run it.

    Existence is not enough. A binary can sit on disk, be newer than every
    source file and still be unrunnable: a Windows application-control policy
    (Smart App Control, AppLocker, WDAC) refuses to execute it with WinError
    4551. Reporting that as "available" made `core.accel` label Python results
    as `c-native`, and made a three-way cross-backend check quietly compare two
    implementations instead of three.

    The probe is cached because this is called on every dispatch. `_probe_cache`
    is reset by `reset_availability()` for tests and by anything that changes
    which binary is in play.
    """
    if _probe_cache.get("result") is not None:
        return bool(_probe_cache["result"])

    # The in-process library is preferred when it loaded: it runs the same C
    # functions as the executable, minus a subprocess and an automaton rebuild
    # per batch. Its probe is a real selftest, not an existence check.
    if ffi_available():
        _probe_cache["result"] = True
        _probe_cache["reason"] = ""
        return True

    # Only a library that was actually found can explain anything. A missing one
    # is not a diagnosis and must not displace the executable's reason.
    ffi_reason = str(_probe_cache.get("ffi_reason") or "")
    if not ffi_reason and _library_present():
        ffi_reason = library_note()

    if _BINARY is None:
        _probe_cache["result"] = False
        _probe_cache["reason"] = ffi_reason or "the native C core was not found"
        return False

    try:
        proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(_BINARY), "version"],
            capture_output=True, text=True, encoding=_IO_ENCODING, errors="replace", timeout=10.0,
        )
    except OSError as exc:
        # A refusal is a host policy decision, not a missing file: recording it
        # keeps the reason visible instead of collapsing it into "not found".
        _probe_cache["result"] = False
        # The library is the preferred path, so its reason is the more
        # informative one when both are unavailable.
        _probe_cache["reason"] = ffi_reason or _describe_startup_failure(exc)
        return False
    except subprocess.SubprocessError as exc:
        _probe_cache["result"] = False
        _probe_cache["reason"] = f"the C core did not complete a version probe: {exc}"
        return False

    if proc.returncode != 0:
        _probe_cache["result"] = False
        _probe_cache["reason"] = f"the C core version probe exited {proc.returncode}"
        return False

    _probe_cache["result"] = True
    _probe_cache["reason"] = ""
    return True


def availability_note() -> str:
    """Why `core_available()` said no. Empty when the core is usable."""
    core_available()
    return str(_probe_cache.get("reason") or "")


def reset_availability() -> None:
    """Forgets the cached probe so the next call re-tests execution."""
    _probe_cache.clear()


def _describe_startup_failure(exc: OSError) -> str:
    """Names the reason a binary would not start, in a language-neutral form.

    WinError 4551 is an application-control refusal and is worth distinguishing
    from a missing file or a permissions problem: it means the code is fine and
    the host declined to run it.

    Both `winerror` and `errno` are inspected. Windows populates `winerror` when
    it raises, but an `OSError` rebuilt or re-raised by an intermediate layer
    carries the code in `errno` instead, and a refusal that arrives that way must
    not be reported as an unclassifiable failure.
    """
    code = getattr(exc, "winerror", None)
    if code is None:
        code = getattr(exc, "errno", None)
    if code == 4551:
        return (
            "the host application-control policy refused to execute the C core "
            "(WinError 4551); the binary is present but the policy blocks it"
        )
    if code == 2:
        return "the C core binary was not found at the recorded path"
    return f"the C core could not be started: {exc}"


def core_version() -> str:
    """Returns the native core version string, or "unavailable".

    A refused execution is reported as "unavailable", not "unknown": "unknown"
    is what a healthy binary that printed something unexpected returns, and
    conflating the two hides a host policy decision behind an oddity.
    """
    if ffi_available():
        return ffi_version()
    if _BINARY is None:
        return "unavailable"
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(_BINARY), "version"],
            capture_output=True, text=True, encoding=_IO_ENCODING, errors="replace", timeout=10.0,
        )
        return str(json.loads(proc.stdout).get("version", "unknown"))
    except OSError:
        return "unavailable"
    except (subprocess.SubprocessError, json.JSONDecodeError, ValueError):
        return "unknown"


def selftest() -> dict[str, Any]:
    """Runs the native built-in consistency checks.

    Returns a dict with at least `ok` and `failures`. A binary that ran but
    produced nothing usable reports `ok=False` with the reason rather than
    raising.

    An `OSError` is deliberately NOT converted into that dict. WinError 4551
    means the host application-control policy refused to execute the image, and
    that fact only reaches `core.cores._policy_blocked` through the exception's
    `winerror`. Flattening it into a message string lost the code, so a policy
    refusal was reported as FAILED and failed the build as if the C core were
    broken.
    """
    # The library runs the identical check suite, so a host that refuses to
    # execute the executable can still be probed in-process.
    if ffi_available():
        parsed = _ffi_selftest()
        if parsed is not None:
            return parsed
    if _BINARY is None:
        return {"ok": False, "failures": None, "error": "binary not found"}

    try:
        proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(_BINARY), "selftest"],
            capture_output=True, text=True, encoding=_IO_ENCODING, errors="replace", timeout=60.0,
        )
    except subprocess.SubprocessError as exc:
        return {"ok": False, "failures": None, "error": f"subprocess error: {exc}"}

    try:
        parsed = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"ok": False, "failures": None, "error": "unparseable selftest output"}
    if not isinstance(parsed, dict):
        return {"ok": False, "failures": None, "error": "selftest output was not an object"}
    return parsed


def scan_banners(
    banners: Sequence[str],
    signatures_path: str | Path,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """Streams `banners` through the native matcher.

    Three front ends, in order of cost, all running the same C code:
    the in-process library (one automaton, reused across batches), then the
    executable (one subprocess for the whole list), then Python.

    Returns one result dict per input banner, in order. A batch is served by
    exactly one backend: if a single banner fails in-process the whole batch
    falls through to the next front end rather than returning a list whose
    entries came from different implementations. Such a list would be
    indistinguishable from a correct one, and a backend disagreement hidden
    inside it is exactly what this fallback logic exists to surface.
    """
    if not banners:
        return []

    sig_path = Path(signatures_path)
    if not sig_path.exists():
        return []

    # Gated on ffi_available(), not merely on the library loading: a library that
    # loads but fails its own selftest is not usable, and answering from it would
    # report results the project has already declared untrustworthy. native_path()
    # says "process" in that state, so this must agree.
    handle = _open_signatures(sig_path) if ffi_available() else None
    if handle is not None:
        results: list[dict[str, Any]] = []
        for banner in banners:
            parsed = _ffi_match(handle, banner)
            if parsed is None:
                results = []
                break
            results.append(parsed)
        if results:
            return results

    if _BINARY is not None:
        payload = "\n".join(b.replace("\n", " ").replace("\r", " ") for b in banners)
        payload += "\n"
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
                [str(_BINARY), "match", str(sig_path)],
                input=payload, capture_output=True, text=True, encoding=_IO_ENCODING, errors="replace", timeout=timeout,
            )
        except OSError:
            proc = None
        except subprocess.SubprocessError:
            proc = None

        if proc is not None and proc.stdout:
            process_results: list[dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict) and parsed.get("status") == "ok":
                    process_results.append(parsed)
            if process_results:
                return process_results

    return _python_fallback(banners, sig_path)


def fingerprint(banner: str) -> dict[str, str]:
    """Returns FNV-1a 32/64 and CRC-32 digests for a single banner.

    Uses the in-process library, then the executable, then computes identical
    values in Python, so callers always receive a complete digest set.
    """
    if ffi_available():
        parsed = _ffi_fingerprint(banner)
        if parsed is not None:
            return parsed

    if _BINARY is not None:
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
                [str(_BINARY), "fp"],
                input=banner + "\n", capture_output=True, text=True, encoding=_IO_ENCODING, errors="replace", timeout=15.0,
            )
            parsed = json.loads(proc.stdout.strip() or "{}")
            if isinstance(parsed, dict) and parsed.get("status") == "ok":
                return {
                    "fp_fnv1a32": parsed["fp_fnv1a32"],
                    "fp_fnv1a64": parsed["fp_fnv1a64"],
                    "fp_crc32": parsed["fp_crc32"],
                }
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError,
                ValueError, KeyError):
            pass

    return {
        "fp_fnv1a32": f"0x{fnv1a32_py(banner):08X}",
        "fp_fnv1a64": f"0x{fnv1a64_py(banner):016X}",
        "fp_crc32": f"0x{crc32_py(banner):08X}",
    }


# --------------------------------------------------------------- fallbacks

_ASCII_FOLD = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)


def fold_ascii(text: str) -> str:
    """Lowercases ASCII A-Z only, leaving every other character untouched.

    The native core compares case-insensitively over ASCII alone, so a fallback
    built on `str.lower()` disagreed with it on exactly the inputs the fallback
    exists to cover: `str.lower()` folds 'Ü' to 'ü', so the Python path reported
    a match for 'Über' against the pattern 'über' that the C core does not
    produce. A degraded campaign therefore invented detections a healthy one
    never reported, which is the opposite of what a fallback is for.
    """
    return text.translate(_ASCII_FOLD)


def find_all_occurrences(folded_text: str, folded_pattern: str) -> list[int]:
    """Every character index at which `folded_pattern` occurs, overlaps included.

    The native matcher advances one character past each hit, so a pattern can
    match inside its own previous match: 'aa' in 'aaaa' is four characters long
    and reports positions 0, 1 and 2. A fallback that looped on `str.find` while
    advancing by the pattern length would drop the overlapping hits, and a
    banner that advertised several versions of the same service would then be
    reported once by a degraded run and repeatedly by a healthy one.
    """
    if not folded_pattern:
        return []
    found: list[int] = []
    start = folded_text.find(folded_pattern)
    while start >= 0:
        found.append(start)
        start = folded_text.find(folded_pattern, start + 1)
    return found


def byte_offset(text: str, char_index: int) -> int:
    """Converts a character index into the UTF-8 byte offset the cores report.

    The native matcher reports byte positions, and the Rust bridge documents the
    same contract, so a fallback returning `str.find()`'s character index
    disagreed with both as soon as a banner contained a multi-byte character.
    """
    return -1 if char_index < 0 else len(text[:char_index].encode("utf-8"))


def _load_signatures(sig_path: Path) -> list[tuple[str, str]]:
    """Reads a signature file into (name, pattern) pairs.

    Mirrors the native parser: '#' comments, blank lines, and an optional
    "name<TAB>pattern" form.

    An identical (name, pattern) line is kept only once, matching
    hc_ac_add()'s HC_ERR_DUP. Without this, a file that repeats a line made the
    same signature appear twice in one detection and inflated match_count, so a
    degraded campaign scored differently from a healthy one. The check is on
    both fields: two names sharing one pattern are two real signatures and both
    survive, exactly as in the native core.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    try:
        # utf-8-sig, not utf-8: a UTF-8 BOM is what PowerShell 5.1, Notepad and
        # several other Windows editors write by default. Plain utf-8 leaves the
        # BOM as U+FEFF on the first signature name, so "alpha<TAB>foo" was
        # registered as "\ufeffalpha" and matched nothing the operator expected.
        text = sig_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return pairs

    # The native read_line() splits on '\n' and drops a trailing '\r', trim()
    # then removes leading and trailing spaces and tabs from the whole line, and
    # only afterwards is the line split at its first tab. The pattern is never
    # trimmed on its own.
    #
    # Trimming each field separately, as this used to, silently moved every
    # signature that began or ended in a space: "n<TAB> SSH" was registered as
    # 'SSH' in Python and as ' SSH' in C, so a degraded run reported a hit at a
    # different position than a healthy one, and matched text the core rejected.
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip(" \t")
        if not line or line.startswith("#"):
            continue
        tab = line.find("\t")
        if tab >= 0:
            pair = (line[:tab], line[tab + 1:])
        else:
            pair = (line, line)
        if pair in seen:
            continue
        seen.add(pair)
        pairs.append(pair)
    return pairs


def _python_fallback(banners: Iterable[str], sig_path: Path) -> list[dict[str, Any]]:
    """Pure-Python equivalent of `scan_banners`, used when the binary is absent.

    Folding and offsets follow the native contract exactly: ASCII-only
    case-insensitivity, byte positions, and every occurrence of a pattern
    including overlapping ones. All three were wrong here, so a run that fell
    back to Python reported different matches and different offsets from a run
    that reached the C core.
    """
    pairs = _load_signatures(sig_path)
    results: list[dict[str, Any]] = []
    for banner in banners:
        folded = fold_ascii(banner)
        # The contract is the set of (signature, position) pairs, not the order
        # they arrive in: the native differential harness qsorts both sides
        # before it compares them, which is the project's own statement of what
        # a match is. Emission order here is therefore only kept deterministic,
        # so that two runs are comparable, by position then pattern length then
        # insertion order.
        located = [
            (byte_offset(folded, index), len(pattern.encode("utf-8")), order, name)
            for order, (name, pattern) in enumerate(pairs)
            if pattern
            for index in find_all_occurrences(folded, fold_ascii(pattern))
        ]
        matches = [
            {"signature": name, "position": position}
            for position, _, _, name in sorted(located)
        ]
        results.append({
            "status": "ok",
            "banner": banner,
            "fp_fnv1a32": f"0x{fnv1a32_py(banner):08X}",
            "fp_fnv1a64": f"0x{fnv1a64_py(banner):016X}",
            "fp_crc32": f"0x{crc32_py(banner):08X}",
            "matches": matches,
            "match_count": len(matches),
            "truncated": False,
            "engine": "python-fallback",
        })
    return results


def fnv1a32_py(text: str) -> int:
    """FNV-1a 32-bit, byte-identical to the native implementation."""
    digest = _FNV32_OFFSET
    for byte in text.encode("utf-8"):
        digest = ((digest ^ byte) * _FNV32_PRIME) & _MASK32
    return digest


def fnv1a64_py(text: str) -> int:
    """FNV-1a 64-bit, byte-identical to the native implementation."""
    digest = _FNV64_OFFSET
    for byte in text.encode("utf-8"):
        digest = ((digest ^ byte) * _FNV64_PRIME) & _MASK64
    return digest


def crc32_py(text: str) -> int:
    """CRC-32 (IEEE, reflected), byte-identical to the native implementation."""
    crc = 0xFFFFFFFF
    for byte in text.encode("utf-8"):
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF
