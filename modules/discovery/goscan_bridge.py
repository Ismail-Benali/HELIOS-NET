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

from core.error_envelope import parse_envelope

ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if os.name == "nt" else ""
GOSCAN_BIN = ROOT / "transport" / "goscan" / f"goscan{_EXE}"

# Optional hook so the broker can feed native error envelopes into MutationEngine.
mutation_engine = None


def attach_mutation_engine(engine) -> None:
    """Allows the orchestrator to bind a MutationEngine for tactical adaptation."""
    global mutation_engine
    mutation_engine = engine


async def run_go_scan_async(target: str, port_arg: str = "common") -> list[dict]:
    """Executes the native Go scanner binary asynchronously using NDJSON line streaming."""
    if not GOSCAN_BIN.exists():
        return []

    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            str(GOSCAN_BIN), target, port_arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Capture stderr line-by-line and parse standardized error envelopes.
        async def _drain_errors():
            if not proc.stderr:
                return
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                env = parse_envelope(text)
                if env and mutation_engine:
                    # Let the engine adapt tactics automatically (e.g. EDR_BLOCKED).
                    mutation_engine.adapt_to_envelope(env)

        err_task = asyncio.create_task(_drain_errors()) if proc.stderr else None

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

        if err_task:
            await err_task
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
