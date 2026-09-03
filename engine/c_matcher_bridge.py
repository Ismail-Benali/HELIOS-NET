"""HELIOS-NET :: engine/c_matcher_bridge.py
C-Powered Native Memory Banner Matcher Bridge.

Delegates high-speed string and banner signature matching to the compiled
C binary (c_matcher.exe) for near-instantaneous pointer-level analysis.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_EXE = ".exe" if os.name == "nt" else ""
CMATCHER_BIN = ROOT / "transport" / "c_matcher" / f"c_matcher{_EXE}"


def run_c_matcher(banner: str) -> list[str]:
    """Executes the native C binary for ultra-fast memory-level signature matching."""
    if not CMATCHER_BIN.exists() or not banner.strip():
        return []

    try:
        proc = subprocess.run(
            [str(CMATCHER_BIN), banner],
            capture_output=True, text=True, timeout=5.0
        )
        if proc.returncode != 0:
            return []

        raw_out = proc.stdout.strip()
        if not raw_out:
            return []

        data = json.loads(raw_out)
        return data.get("matches", [])
    except Exception:
        return []
