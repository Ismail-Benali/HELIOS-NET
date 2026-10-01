"""HELIOS-NET :: core/rust_bridge.py
Native Rust acceleration bridge (ctypes).

Loads the `helios_rust_core` shared library produced by `cargo build --release`
and exposes Python-callable entry points for signature matching, digests, and
graph analytics. Every entry point degrades gracefully: if the library is absent
or the host blocks it, callers fall back to pure Python.
"""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import c_char_p, c_int, c_uint, c_void_p, CDLL, POINTER
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parent.parent

_LIB_NAMES = (
    "helios_rust_core.dll",
    "libhelios_rust_core.so",
    "libhelios_rust_core.dylib",
)

_CANDIDATE_DIRS = (
    ROOT / "rust-core" / "target" / "release",
    ROOT / "rust-core" / "target" / "debug",
)

# Exported ABI revision of the loaded library.
ABI_VERSION = 2

_IO_ENCODING = "utf-8"


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    override = os.environ.get("HELIOS_RUST_LIB")
    if override:
        paths.append(Path(override))
    for directory in _CANDIDATE_DIRS:
        paths.extend(directory / name for name in _LIB_NAMES)
    return paths


def _load() -> CDLL | None:
    for path in _candidate_paths():
        if not path.exists():
            continue
        try:
            lib = CDLL(str(path))
        except OSError:
            # Blocked by host policy, or wrong architecture.
            continue

        try:
            lib.helios_free_string.restype = None
            lib.helios_free_string.argtypes = [c_void_p]

            lib.helios_rust_version.restype = c_char_p
            lib.helios_rust_version.argtypes = []

            lib.helios_abi_version.restype = c_int
            lib.helios_abi_version.argtypes = []

            lib.helios_selftest.restype = c_int
            lib.helios_selftest.argtypes = []

            lib.helios_match_signatures.restype = c_void_p
            lib.helios_match_signatures.argtypes = [c_char_p, c_char_p]

            lib.helios_match_json.restype = c_void_p
            lib.helios_match_json.argtypes = [c_char_p, c_char_p]

            lib.helios_fnv1a32.restype = c_void_p
            lib.helios_fnv1a32.argtypes = [c_char_p]

            graph_args: list[Any] = [c_int, POINTER(c_uint), c_int]
            lib.helios_graph_components.restype = c_void_p
            lib.helios_graph_components.argtypes = graph_args
            lib.helios_graph_centrality.restype = c_void_p
            lib.helios_graph_centrality.argtypes = graph_args
            lib.helios_graph_betweenness.restype = c_void_p
            lib.helios_graph_betweenness.argtypes = graph_args
            lib.helios_graph_shortest_path.restype = c_void_p
            lib.helios_graph_shortest_path.argtypes = graph_args + [c_uint, c_uint]
        except AttributeError:
            # A stale library from an older build: missing entry points.
            continue

        return lib
    return None


_LIB = _load()


def rust_available() -> bool:
    """True when the native library loaded successfully."""
    return _LIB is not None


def rust_version() -> str:
    if _LIB is None:
        return "unavailable"
    try:
        return (_LIB.helios_rust_version() or b"").decode(_IO_ENCODING, "replace")
    except Exception:
        return "unknown"


def rust_abi_version() -> int:
    if _LIB is None:
        return 0
    try:
        return int(_LIB.helios_abi_version())
    except Exception:
        return 0


def rust_selftest() -> bool:
    """Proves the loaded library actually executes, rather than just being present.

    Presence on disk is not evidence of a working core: an ABI mismatch or a
    blocked export can both leave a loadable file that cannot do the work.
    """
    if _LIB is None:
        return False
    try:
        return int(_LIB.helios_selftest()) == 0
    except Exception:
        return False


def _take(raw: int | None) -> str:
    """Decodes a library-allocated string and always releases it."""
    if not raw:
        return ""
    try:
        return ctypes.string_at(raw).decode(_IO_ENCODING, "replace")
    except Exception:
        return ""
    finally:
        try:
            # Checked explicitly rather than relying on AttributeError being
            # caught: _LIB is None whenever the native core is unavailable, and
            # a free that silently does not happen would leak the buffer.
            if _LIB is not None:
                _LIB.helios_free_string(raw)
        except Exception:  # nosec B110 - cleanup of a foreign allocation; raising here would run during error handling
            pass


def _encode(value: str) -> bytes:
    return value.encode(_IO_ENCODING, "surrogateescape")


def _edge_buffer(edges: Sequence[tuple[int, int]]) -> Any:
    """Packs edges into the flat u32 array the C ABI expects."""
    array = (c_uint * (2 * len(edges)))()
    for i, (a, b) in enumerate(edges):
        array[2 * i] = int(a)
        array[2 * i + 1] = int(b)
    return array


# ---------------------------------------------------------------- matching


def match_signatures_rust(text: str, patterns: list[str]) -> list[str]:
    """Returns the subset of `patterns` present in `text` (case-insensitive).

    Returns an empty list when the library is unavailable or on any error,
    so the caller transparently uses the pure-Python automaton instead.
    """
    if _LIB is None or not text or not patterns:
        return []

    payload = "\n".join(patterns)
    try:
        raw = _LIB.helios_match_signatures(_encode(text), _encode(payload))
    except Exception:
        return []

    decoded = _take(raw)
    return [line for line in decoded.split("\n") if line]


def match_json_rust(text: str, patterns: list[str]) -> list[dict[str, Any]]:
    """Returns `[{"signature": str, "position": int}, ...]` for matches in `text`.

    Positions are byte offsets, matching the C core's contract.
    """
    if _LIB is None or not text or not patterns:
        return []
    payload = "\n".join(patterns)
    try:
        raw = _LIB.helios_match_json(_encode(text), _encode(payload))
    except Exception:
        return []
    decoded = _take(raw)
    if not decoded:
        return []
    try:
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


def fnv1a32_rust(text: str) -> str:
    """Returns the native FNV-1a 32-bit digest as `0xXXXXXXXX`, or "" on failure."""
    if _LIB is None or not text:
        return ""
    try:
        raw = _LIB.helios_fnv1a32(_encode(text))
    except Exception:
        return ""
    return _take(raw)


# ------------------------------------------------------------------- graph


def graph_components_rust(node_count: int, edges: Sequence[tuple[int, int]]) -> list[list[int]]:
    if _LIB is None:
        return []
    try:
        array = _edge_buffer(edges)
        raw = _LIB.helios_graph_components(
            int(node_count), array if edges else None, len(edges)
        )
    except Exception:
        return []
    decoded = _take(raw)
    if not decoded:
        return []
    try:
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return []
    return parsed.get("components", []) if isinstance(parsed, dict) else []


def graph_centrality_rust(
    node_count: int, edges: Sequence[tuple[int, int]]
) -> list[tuple[int, float]]:
    """Returns `[(node_index, centrality), ...]` sorted by centrality descending."""
    if _LIB is None:
        return []
    try:
        array = _edge_buffer(edges)
        raw = _LIB.helios_graph_centrality(
            int(node_count), array if edges else None, len(edges)
        )
    except Exception:
        return []
    decoded = _take(raw)
    if not decoded:
        return []
    try:
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, dict):
        return []
    return [
        (int(row["node"]), float(row["centrality"]))
        for row in parsed.get("ranking", [])
    ]


def graph_betweenness_rust(node_count: int, edges: Sequence[tuple[int, int]]) -> list[float]:
    if _LIB is None:
        return []
    try:
        array = _edge_buffer(edges)
        raw = _LIB.helios_graph_betweenness(
            int(node_count), array if edges else None, len(edges)
        )
    except Exception:
        return []
    decoded = _take(raw)
    if not decoded:
        return []
    try:
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return []
    return [float(v) for v in parsed.get("values", [])] if isinstance(parsed, dict) else []


def graph_shortest_path_rust(
    node_count: int, edges: Sequence[tuple[int, int]], source: int, goal: int
) -> tuple[int, list[int]] | None:
    """Returns `(hops, path)`, or None when `goal` is unreachable from `source`."""
    if _LIB is None:
        return None
    try:
        array = _edge_buffer(edges)
        raw = _LIB.helios_graph_shortest_path(
            int(node_count), array if edges else None, len(edges), int(source), int(goal)
        )
    except Exception:
        return None
    decoded = _take(raw)
    if not decoded:
        return None
    try:
        parsed = json.loads(decoded)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict) or "error" in parsed:
        return None
    return int(parsed["hops"]), list(parsed.get("path", []))
