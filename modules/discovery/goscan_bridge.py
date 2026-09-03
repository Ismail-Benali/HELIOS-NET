"""
HELIOS-NET :: modules/discovery/goscan_bridge.py
Go-Powered High-Performance Port Scanner Bridge with Asynchronous NDJSON Streaming.

Delegates heavy port discovery to the compiled Go binary (goscan.exe)
using non-blocking asynchronous stream readers to prevent OS pipe buffer saturation and deadlocks.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if os.name == "nt" else ""
GOSCAN_BIN = ROOT / "transport" / "goscan" / f"goscan{_EXE}"


async def run_go_scan_async(target: str, port_arg: str = "common") -> list[dict]:
    """Executes the native Go scanner binary asynchronously using NDJSON line streaming."""
    if not GOSCAN_BIN.exists():
        return []

    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            str(GOSCAN_BIN), target, port_arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )

        if proc.stdout:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                try:
                    data = json.loads(line.decode("utf-8").strip())
                    if isinstance(data, dict) and data.get("open"):
                        results.append({
                            "module": "discovery",
                            "host": target,
                            "port": data["port"],
                            "service": "tcp-native",
                            "open": True,
                            "source": "native(Go-Goroutines-NDJSON)"
                        })
                except json.JSONDecodeError:
                    continue

        await proc.wait()
    except Exception:
        pass
    return results


def run_go_scan(target: str, port_arg: str = "common") -> list[dict]:
    """Synchronous wrapper for Go scanner execution."""
    try:
        return asyncio.run(run_go_scan_async(target, port_arg))
    except Exception:
        return []
