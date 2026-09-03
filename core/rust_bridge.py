"""
HELIOS-NET :: core/rust_bridge.py
Zero-dependency Python-to-Rust FFI Bridge using standard `ctypes`.
Loads helios_core cdylib natively for high-performance graph traversal and TTL analysis,
with graceful fallback to pure Python if the compiled library is unavailable.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import List, Tuple, Optional

ROOT = Path(__file__).resolve().parents[1]
_EXT = ".dll" if os.name == "nt" else (".dylib" if os.uname().sysname == "Darwin" else ".so") if hasattr(os, "uname") else ".dll"

LIB_CANDIDATES = [
    ROOT / "rust-core" / "target" / "release" / f"helios_core{_EXT}",
    ROOT / "rust-core" / f"libhelios_core{_EXT}",
    ROOT / f"helios_core{_EXT}",
]

_rust_lib = None
for cand in LIB_CANDIDATES:
    if cand.exists():
        try:
            _rust_lib = ctypes.CDLL(str(cand))
            break
        except Exception:
            pass


class RustGraphFFI:
    """Wrapper for Rust high-performance graph pathfinding via ctypes."""

    def __init__(self):
        self.obj = None
        if _rust_lib:
            try:
                _rust_lib.helios_graph_new.restype = ctypes.c_void_p
                self.obj = _rust_lib.helios_graph_new()
            except Exception:
                self.obj = None

    def add_edge(self, from_node: str, to_node: str, cost: float) -> None:
        if not self.obj or not _rust_lib:
            return
        try:
            _rust_lib.helios_graph_add_edge(
                self.obj,
                from_node.encode("utf-8"),
                to_node.encode("utf-8"),
                ctypes.c_double(cost)
            )
        except Exception:
            pass

    def shortest_path(self, start: str, goal: str) -> Optional[Tuple[List[str], float]]:
        if not self.obj or not _rust_lib:
            return None
        try:
            buf = ctypes.create_string_buffer(1024)
            _rust_lib.helios_graph_shortest_path.restype = ctypes.c_int
            res = _rust_lib.helios_graph_shortest_path(
                self.obj,
                start.encode("utf-8"),
                goal.encode("utf-8"),
                buf,
                1024
            )
            if res > 0:
                path_str = buf.value.decode("utf-8")
                path = path_str.split(",")
                return path, 0.0
        except Exception:
            pass
        return None

    def __del__(self):
        if self.obj and _rust_lib:
            try:
                _rust_lib.helios_graph_free(self.obj)
            except Exception:
                pass


def get_rust_ttl(ttl: int) -> Optional[str]:
    if not _rust_lib:
        return None
    try:
        _rust_lib.helios_ttl_family.argtypes = [ctypes.c_int]
        _rust_lib.helios_ttl_family.restype = ctypes.c_char_p
        res = _rust_lib.helios_ttl_family(ttl)
        if res:
            return res.decode("utf-8")
    except Exception:
        pass
    return None
