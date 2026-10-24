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

import asyncio
import atexit
import json
import os
import subprocess  # nosec B404 - the native core is a project-built binary at a fixed path
import threading
from pathlib import Path
from typing import Any

from core.envelope import parse_envelope
from core.input_guard import sanitize_banner

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
    except (OSError, subprocess.SubprocessError):
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


class _ServeWorker:
    """A long-lived `goscan serve` process.

    Starting the native core per sweep costs process creation and loses the
    worker pool between calls. This keeps one process and speaks the documented
    NDJSON protocol, with a per-request deadline so a wedged worker is killed and
    replaced instead of hanging the campaign.
    """

    def __init__(self) -> None:
        self._proc: subprocess.Popen[str] | None = None
        self._bin = ""
        self._lock = threading.Lock()
        self._seq = 0

    def _drain_errors(self, proc: subprocess.Popen[str]) -> None:
        if proc.stderr is None:
            return
        for line in proc.stderr:
            envelope = parse_envelope(line.strip())
            if envelope and mutation_engine:
                mutation_engine.adapt_to_envelope(envelope)

    def _start(self) -> None:
        proc = subprocess.Popen(  # nosec B603 - fixed argv against a project-built binary, shell=False
            [str(GOSCAN_BIN), "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=_IO_ENCODING,
            errors="replace",
            bufsize=1,
        )
        self._proc = proc
        self._bin = str(GOSCAN_BIN)
        self._seq = 0
        threading.Thread(target=self._drain_errors, args=(proc,), daemon=True).start()

    def _stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2.0)
        except (OSError, subprocess.SubprocessError):
            try:
                proc.kill()
            except OSError:
                pass

    def close(self) -> None:
        """Stops the worker; safe to call when it was never started."""
        with self._lock:
            self._stop()

    def scan(self, target: str, port_arg: str, timeout: float) -> list[dict[str, Any]]:
        with self._lock:
            if (
                self._proc is None
                or self._proc.poll() is not None
                or self._bin != str(GOSCAN_BIN)
            ):
                self._stop()
                self._start()
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                raise GoscanError("Go serve worker did not start")
            stdout = proc.stdout

            self._seq += 1
            request = json.dumps({"id": self._seq, "target": target, "ports": port_arg})
            try:
                proc.stdin.write(request + "\n")
                proc.stdin.flush()
            except (OSError, ValueError) as exc:
                self._stop()
                raise GoscanError(
                    f"Go serve worker refused the request: {exc}"
                ) from exc

            box: list[str] = []
            reader = threading.Thread(
                target=lambda: box.append(stdout.readline()), daemon=True
            )
            reader.start()
            reader.join(timeout)
            if reader.is_alive():
                self._stop()
                raise GoscanError(f"Go serve worker timed out after {timeout:.0f}s")
            line = box[0] if box else ""
            if not line:
                self._stop()
                raise GoscanError("Go serve worker exited without a response")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError as exc:
                self._stop()
                raise GoscanError(f"Go serve worker sent invalid JSON: {exc}") from exc
            if not isinstance(reply, dict):
                self._stop()
                raise GoscanError("Go serve worker sent a non-object response")
            if reply.get("id") != self._seq:
                self._stop()
                raise GoscanError("Go serve worker answered a different request")
            if reply.get("error"):
                raise GoscanError(f"Go serve worker failed: {reply['error']}")

            raw_results = reply.get("results")
            if not isinstance(raw_results, list):
                self._stop()
                raise GoscanError("Go serve worker sent a non-list results field")

            results: list[dict[str, Any]] = []
            for data in raw_results:
                if not isinstance(data, dict) or not data.get("open"):
                    continue
                port = data.get("port")
                if not isinstance(port, int) or not 1 <= port <= 65535:
                    # A record without a valid port cannot be acted on; keeping
                    # it would invent a destination the core never reported.
                    continue
                banner = data.get("banner", "")
                if not isinstance(banner, str):
                    banner = ""
                results.append(
                    {
                        "module": "discovery",
                        "host": target,
                        "port": port,
                        "service": data.get("service") or "",
                        "banner": sanitize_banner(banner),
                        "latency_ms": data.get("latency_ms"),
                        "time": data.get("time", ""),
                        "open": True,
                        "source": "native(Go-Goroutines-NDJSON)",
                    }
                )
            return results


_WORKER = _ServeWorker()
atexit.register(_WORKER.close)


def shutdown_worker() -> None:
    """Stops the persistent scanner process, if one is running."""
    _WORKER.close()


def run_go_scan_persistent(
    target: str, port_arg: str = "common", strict: bool = False, timeout: float = 300.0
) -> list[dict[str, Any]]:
    """Scans through the long-lived `goscan serve` worker."""
    global LAST_ERROR
    LAST_ERROR = None
    if not GOSCAN_BIN.exists():
        LAST_ERROR = f"Go core binary not found at {GOSCAN_BIN}"
        if strict:
            raise GoscanError(LAST_ERROR)
        return []
    try:
        return _WORKER.scan(target, port_arg, timeout)
    except GoscanError as exc:
        LAST_ERROR = str(exc)
        if strict:
            raise
        return []
    except (OSError, subprocess.SubprocessError) as exc:
        LAST_ERROR = f"Go serve worker could not be executed: {exc}"
        if strict:
            raise GoscanError(LAST_ERROR) from exc
        return []


async def run_go_scan_async(
    target: str, port_arg: str = "common", strict: bool = False
) -> list[dict[str, Any]]:
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
            str(GOSCAN_BIN),
            target,
            port_arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
                    banner = data.get("banner", "")
                    if not isinstance(banner, str):
                        banner = ""
                    # Preserve everything the core reported. The previous bridge
                    # discarded the banner, the detected service and the latency,
                    # and hardcoded a generic "tcp-native" service, throwing away
                    # the entire point of running the Go core.
                    results.append(
                        {
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
                            "banner": sanitize_banner(banner),
                            "latency_ms": data.get("latency_ms"),
                            "time": data.get("time", ""),
                            "open": True,
                            "source": "native(Go-Goroutines-NDJSON)",
                        }
                    )

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


def run_go_scan(
    target: str,
    port_arg: str = "common",
    strict: bool = False,
    timeout: float = 300.0,
) -> list[dict[str, Any]]:
    """Synchronous wrapper for Go scanner execution.

    The long-lived worker is tried first so repeated sweeps do not pay process
    creation. Any worker failure falls back to the one-shot path, which keeps
    the historical failure semantics: a core that cannot run leaves
    `LAST_ERROR` set (or raises with `strict=True`) instead of looking like a
    clean sweep.

    `timeout` bounds a whole sweep on the persistent worker, not a single dial.
    It is generous by default because a full 65k-port sweep is a long request;
    a wedged worker is still killed and replaced rather than blocking forever.
    """
    global LAST_ERROR
    worker_error: str | None = None
    if GOSCAN_BIN.exists():
        try:
            rows = _WORKER.scan(target, port_arg, timeout)
            LAST_ERROR = None
            return rows
        except (GoscanError, OSError, subprocess.SubprocessError) as exc:
            worker_error = f"{type(exc).__name__}: {exc}"

    try:
        return asyncio.run(run_go_scan_async(target, port_arg, strict=strict))
    except GoscanError:
        raise
    except Exception as exc:  # noqa: BLE001 - surfaced through LAST_ERROR
        LAST_ERROR = f"Go core failed: {type(exc).__name__}: {exc}"
        if worker_error:
            LAST_ERROR = f"{LAST_ERROR}; persistent worker: {worker_error}"
        if strict:
            raise GoscanError(LAST_ERROR) from exc
        return []
