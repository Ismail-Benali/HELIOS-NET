"""HELIOS-NET :: transport/__init__.py
The low-level performance core package - a unified contract between Python and
the two native cores (Go/C).

Responsibilities:
  - Provide the compat shims that earlier call sites still import.
  - Delegate to the real bridges: `core.c_core_bridge` and
    `modules.discovery.goscan_bridge`.

History:
  This module used to own binary discovery (`find_binary`) and process
  invocation (`_run`), and it declared a `RAWSOCKET` binary. None of that
  survived: the `rawsync` and `fingerprint` helpers were removed, but two
  modules kept importing the old names, so importing them raised ImportError.
  The subprocess helper is gone with the binaries, which also retires its two
  defects: it used `text=True` without pinning an encoding (a cp1252 bug on
  Windows, the same contract violation documented in docs/Architecture.md) and
  it read stderr from two places at once, which races the `communicate()` drain.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def match_banner(banner: str, signature: str) -> int:
    """Delegates to the native C core via `core.c_core_bridge`.

    Kept for compatibility with earlier call sites; new code should use
    `c_core_bridge.scan_banners` to batch many banners in one process.
    """
    with tempfile.TemporaryDirectory() as tmp:
        sig_file = Path(tmp) / "sig.txt"
        sig_file.write_text(signature, encoding="utf-8")
        results = _scan_via_bridge([banner], sig_file)
    if not results:
        return -1
    hits = results[0].get("matches") or []
    if not hits:
        return -1
    return int(hits[0].get("position", -1))


def banner_fingerprint(banner: str) -> str:
    """Returns the FNV-1a 32-bit digest of a banner.

    Routed through `core.accel` so the digest comes from the same backend
    selection, and degrades to the Python implementation, as every other
    signature operation does. Calling `c_core_bridge.fingerprint` directly made
    this the one signature helper that raised instead of falling back whenever
    the C core was absent.
    """
    from core.accel import fingerprint

    return fingerprint(banner).fnv1a32


def _scan_via_bridge(banners: list[str], sig_path) -> list[dict]:
    from core.c_core_bridge import scan_banners

    return scan_banners(banners, sig_path)