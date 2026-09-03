"""HELIOS-NET :: transport/__init__.py
حزمة نواة الأداء المنخفض — عقد موحّد بين Python والنواتين (Go/C).

المسؤولية:
  - تحديد مسار الثنائيات المبنيّة (rawsync.exe / fingerprint.exe).
  - استدعاؤها عبر subprocess بأمان (قيود زمنية، بتر، معالجة أخطاء).
  - الفشل لا يُسقط الحملة: عند تغيّب ثنائي، نُفشِل الوحدة لا النظام.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# أسماء الثنائيات المبنية لكل نواة — وفق platform.
_EXE = ".exe" if os.name == "nt" else ""
RAWSYNC = ROOT / "rawsocket" / f"rawsync{_EXE}"
FINGERPRINT = ROOT / "fingerprint" / f"fingerprint{_EXE}"


def find_binary(name: str, default_abs: Path, env_key: str) -> Path | None:
    """يجد الثنائي: أولًا متغير بيئة، ثم المسار المطلق الافتراضي، ثم PATH."""
    env = os.environ.get(env_key)
    if env and Path(env).exists():
        return Path(env)
    if default_abs.exists():
        return default_abs
    found = shutil.which(name)
    return Path(found) if found else None


def _run(binpath: Path | None, args: list[str], timeout: float = 10.0) -> tuple[bool, str]:
    """ينفّذ ثنائيًا ويكبح كل الأخطاء؛ يعيد (نجاح، مخرج نص أمن)."""
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
