"""
HELIOS-NET :: modules/discovery/goscan_bridge.py
Go-Powered High-Performance Port Scanner Bridge with Asynchronous NDJSON Streaming.

Delegates heavy port discovery to the compiled Go binary (goscan.exe) using
non-blocking asynchronous stream readers to prevent OS pipe buffer saturation.

Failure policy
--------------
An empty result set is a real answer ("nothing was open"), so it must never be
returned for a different reason. The previous version of this bridge returned
`[]` for a missing binary, a crashed process, a timeout, and a genuine
all-closed sweep alike. That ambiguity is exactly what allowed a Go core that
deadlocked on every call to pass unnoticed for the life of the project.

So a failure is now recorded in `LAST_ERROR` and, when `strict=True`, raised.
Callers that legitimately want best-effort behaviour pass `strict=False`.
"""

from __future__ import annotations

from typing import Any

import asyncio
import json
import os
import subprocess  # nosec B404 - the native core is a project-built binary at a fixed path
from pathlib import Path

from core.envelope import parse_envelope

ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if os.name == "nt" else ""
GOSCAN_BIN = ROOT / "transport" / "goscan" / f"goscan{_EXE}"

_IO_ENCODING = "utf-8"

# Optional hook so the broker can feed native error envelopes into MutationEngine.
mutation_engine = None

#: Reason the most recent scan could not be performed, or None on success.
#: An empty list from `run_go_scan` is trustworthy only when this is None.
LAST_ERROR: str | None = None


def attach_mutation_engine(engine: Any) -> None:
    """Allows the orchestrator to bind a MutationEngine for tactical adaptation."""
    global mutation_engine
    mutation_engine = engine


def core_available() -> bool:
    """True when the Go binary exists on disk."""
    return GOSCAN_BIN.exists()


def core_version() -> str:
    """Returns the binary's version string, or "unavailable"."""
    if not core_available():
        return "unavailable"
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(GOSCAN_BIN), "version"],
            capture_output=True,
            text=True,
            encoding=_IO_ENCODING,
            errors="replace",
            timeout=20.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return "unavailable"
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip() or "unknown"


def selftest() -> dict[str, Any] | None:
    """Runs the binary's offline self test.

    Returns the parsed report, or None when the core ran but produced nothing
    usable. This is the only way to prove the Go core actually runs without
    touching the network.

    An `OSError` is deliberately NOT swallowed. WinError 4551 means the host
    application-control policy refused to execute the image, which is an
    environment condition, not a broken core. Swallowing it here returned None,
    and `core.cores.check_go` then reported FAILED, so a policy refusal failed
    the build as if the code were at fault. Letting the error propagate is what
    lets the caller separate BLOCKED from FAILED.
    """
    if not core_available():
        return None
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(GOSCAN_BIN), "selftest"],
            capture_output=True,
            text=True,
            encoding=_IO_ENCODING,
            errors="replace",
            timeout=120.0,
        )
    except subprocess.SubprocessError:
        return None
    if not proc.stdout.strip():
        return None
    try:
        report = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    return report if isinstance(report, dict) else None


class GoscanError(RuntimeError):
    """Raised in strict mode when the native core could not be used."""


async def run_go_scan_async(target: str, port_arg: str = "common", strict: bool = False) -> list[dict[str, Any]]:
    """Executes the native Go scanner binary asynchronously using NDJSON line streaming.

    Returns one dict per open port. An empty list means "the core ran and found
    nothing open" only when `LAST_ERROR` is None.
    """
    global LAST_ERROR
    LAST_ERROR = None

    if not GOSCAN_BIN.exists():
        LAST_ERROR = f"Go core binary not found at {GOSCAN_BIN}"
        if strict:
            raise GoscanError(LAST_ERROR)
        return []

    results: list[dict[str, Any]] = []
    envelopes: list[dict[str, Any]] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            str(GOSCAN_BIN), target, port_arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Capture stderr line-by-line and parse standardized error envelopes.
        async def _drain_errors() -> None:
            if not proc.stderr:
                return
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode(_IO_ENCODING, errors="replace").strip()
                env = parse_envelope(text)
                if env:
                    envelopes.append(env)
                    if mutation_engine:
                        # Let the engine adapt tactics automatically (e.g. EDR_BLOCKED).
                        mutation_engine.adapt_to_envelope(env)

        err_task = asyncio.create_task(_drain_errors()) if proc.stderr else None

        if proc.stdout:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode(_IO_ENCODING, errors="replace").strip()
                if not text:
                    continue
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict) and data.get("open"):
                    # Preserve everything the core reported. The previous bridge
                    # discarded the banner, the detected service and the latency,
                    # and hardcoded a generic "tcp-native" service, throwing away
                    # the entire point of running the Go core.
                    results.append({
                        "module": "discovery",
                        "host": target,
                        "port": data.get("port"),
                        # Empty when the core did not identify the service.
                        # This used to substitute "tcp-native", which reads like
                        # a detection but is a label the bridge invented. A
                        # caller checking truthiness already treats an absent
                        # service as no service, and modules/core.py keys its
                        # service graph node off exactly that check.
                        "service": data.get("service") or "",
                        "banner": data.get("banner", ""),
                        "latency_ms": data.get("latency_ms"),
                        "time": data.get("time", ""),
                        "open": True,
                        "source": "native(Go-Goroutines-NDJSON)",
                    })

        if err_task:
            await err_task
        returncode = await proc.wait()

        if returncode != 0:
            reason = envelopes[0].get("message", "") if envelopes else ""
            LAST_ERROR = f"Go core exited {returncode}: {reason}".strip()
            if strict:
                raise GoscanError(LAST_ERROR)
    except GoscanError:
        raise
    except (OSError, asyncio.CancelledError) as exc:
        LAST_ERROR = f"Go core could not be executed: {exc}"
        if strict:
            raise GoscanError(LAST_ERROR) from exc
    except Exception as exc:  # noqa: BLE001 - surfaced through LAST_ERROR
        LAST_ERROR = f"Go core failed: {type(exc).__name__}: {exc}"
        if strict:
            raise GoscanError(LAST_ERROR) from exc

    return results


def run_go_scan(target: str, port_arg: str = "common", strict: bool = False) -> list[dict[str, Any]]:
    """Synchronous wrapper for Go scanner execution.

    With `strict=True` a core failure raises instead of silently returning an
    empty result set.
    """
    try:
        return asyncio.run(run_go_scan_async(target, port_arg, strict=strict))
    except GoscanError:
        raise
    except Exception as exc:  # noqa: BLE001 - surfaced through LAST_ERROR
        global LAST_ERROR
        LAST_ERROR = f"Go core failed: {type(exc).__name__}: {exc}"
        if strict:
            raise GoscanError(LAST_ERROR) from exc
        return []
