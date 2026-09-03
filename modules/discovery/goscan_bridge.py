"""HELIOS-NET :: modules/discovery/goscan_bridge.py
Go-Powered High-Performance Port Scanner Bridge.

Delegates heavy port discovery to the compiled Go binary (goscan.exe)
to achieve maximum concurrency via Goroutines and zero Python GIL overhead.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if os.name == "nt" else ""
GOSCAN_BIN = ROOT / "transport" / "goscan" / f"goscan{_EXE}"


def run_go_scan(target: str, port_arg: str = "common") -> list[dict]:
    """Executes the native Go scanner binary and returns parsed open ports."""
    if not GOSCAN_BIN.exists():
        return []

    try:
        proc = subprocess.run(
            [str(GOSCAN_BIN), target, port_arg],
            capture_output=True, text=True, timeout=10.0
        )
        if proc.returncode != 0:
            return []
        
        raw_out = proc.stdout.strip()
        if not raw_out:
            return []

        ports_data = json.loads(raw_out)
        results = []
        for p in ports_data:
            results.append({
                "module": "discovery",
                "host": target,
                "port": p["port"],
                "service": "tcp-native",
                "open": True,
                "source": "native(Go-Goroutines)"
            })
        return results
    except Exception:
        return []
