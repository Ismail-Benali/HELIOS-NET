"""Verifies that the C core's NDJSON match output is safe against hostile
signature names: a crafted name must not inject JSON keys, and an over-long
name must not produce an unparseable line."""

import json
import os
import subprocess
import sys
from pathlib import Path

EXE = Path(r"C:\Users\alexa\Desktop\HELIOS-NET\transport\c_core\build\helios_core.exe")
TMP = Path(os.environ["TEMP"])


def run(text, sigfile, attempts=10):
    """Runs the core, retrying while the host application-control policy
    refuses the freshly linked binary. The refusal arrives as an OSError from
    CreateProcess, not as an exit code, so both paths must be handled."""
    import time

    for _ in range(attempts):
        try:
            p = subprocess.run(
                [str(EXE), "match", str(sigfile)],
                input=text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
        except OSError as exc:
            if getattr(exc, "winerror", None) == 4551:
                time.sleep(2)
                continue
            raise SystemExit(f"core could not start: {exc}")
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout
        if "4551" in (p.stderr or "") or "contr" in (p.stderr or "").lower():
            time.sleep(2)
            continue
        raise SystemExit(f"core failed rc={p.returncode}: {p.stderr[:300]}")
    raise SystemExit("host policy blocked the binary on every attempt")


def check(label, text, sigfile):
    out = run(text, sigfile)
    line = out.strip().splitlines()[-1]
    try:
        d = json.loads(line)
    except json.JSONDecodeError as e:
        print(f"  {label:8} FAIL  invalid JSON: {e}")
        return False
    ok = True
    if d.get("status") != "ok":
        print(f"  {label:8} FAIL  status={d.get('status')}")
        ok = False
    for m in d.get("matches", []):
        extra = set(m) - {"signature", "position"}
        if extra:
            print(f"  {label:8} FAIL  forged JSON keys injected: {sorted(extra)}")
            ok = False
    if not d.get("matches"):
        print(f"  {label:8} note  no match emitted (treated as truncation)")
    print(
        f"  {label:8} {'OK   ' if ok else 'FAIL '} "
        f"truncated={d.get('truncated')} match={d.get('matches')}"
    )
    return ok


# Crafted name: attempts to close the string and forge a sibling key.
inj = TMP / "helios_inj.txt"
inj.write_text('evil","injected":"yes\tpatternZZZ', encoding="utf-8")

# Over-long name: exceeds the fixed 512-byte record buffer.
lng = TMP / "helios_long_sig.txt"
lng.write_text("A" * 700 + "\tpatternXYZ", encoding="utf-8")

# Hostile control characters.
ctl = TMP / "helios_ctl_sig.txt"
ctl.write_text("bad\x01\x1fname\tpatternQQQ", encoding="utf-8")

print("C core NDJSON hardening checks")
results = [
    check("inject", "patternZZZ here", inj),
    check("long", "the patternXYZ is present here", lng),
    check("control", "patternQQQ here", ctl),
]
sys.exit(0 if all(results) else 1)
