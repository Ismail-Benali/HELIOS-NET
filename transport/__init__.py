"""HELIOS-NET :: transport/__init__.py
The low-level performance core package — a unified contract between Python and
the two cores (Go/C).

Responsibilities:
  - Locate the built binaries (rawsync.exe / fingerprint.exe).
  - Invoke them via subprocess safely (timeouts, truncation, error handling).
  - Failure never drops the campaign: when a binary is absent, the module is
    failed, not the system.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Names of the built binaries per core — platform-dependent.
_EXE = ".exe" if os.name == "nt" else ""
RAWSYNC = ROOT / "rawsocket" / f"rawsync{_EXE}"
FINGERPRINT = ROOT / "fingerprint" / f"fingerprint{_EXE}"


def find_binary(name: str, default_abs: Path, env_key: str) -> Path | None:
    """Finds the binary: first an env variable, then the absolute default path,
    then PATH."""
    env = os.environ.get(env_key)
    if env and Path(env).exists():
        return Path(env)
    if default_abs.exists():
        return default_abs
    found = shutil.which(name)
    return Path(found) if found else None


def _run(binpath: Path | None, args: list[str], timeout: float = 10.0) -> tuple[bool, str]:
    """Runs a binary and contains all errors; returns (success, safe text output)."""
    if binpath is None:
        return False, "binary not found (transport not built)"
    try:
        proc = subprocess.run(
            [str(binpath), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            return False, out or f"exit={proc.returncode}"
        return True, out
    except FileNotFoundError:
        return False, "binary not found"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except OSError as exc:
        return False, f"os error: {exc}"
