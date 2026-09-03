"""
HELIOS-NET :: build.py
Unified Polyglot Build Automation Script.
Compiles Go and Rust native components across platforms without external pip dependencies.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run_cmd(cmd: list[str], cwd: Path) -> bool:
    print(f"[*] Running: {' '.join(cmd)} in {cwd}")
    try:
        res = subprocess.run(cmd, cwd=str(cwd), check=True)
        return res.returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[-] Error executing {' '.join(cmd)}: {e}")
        return false


def build_go_components() -> None:
    print("\n" + "=" * 50)
    print("[HELIOS-NET] Building Go Networking & Scanning Binaries...")
    print("=" * 50)

    transport_dir = ROOT / "transport"
    if not transport_dir.exists():
        print("[-] transport directory not found.")
        return

    for sub in transport_dir.iterdir():
        if sub.is_dir() and (sub / "go.mod").exists():
            print(f"\n[+] Building Go module: {sub.name}")
            run_cmd(["go", "build", "-o", f"{sub.name}.exe" if os.name == "nt" else sub.name, "."], sub)


def build_rust_core() -> None:
    print("\n" + "=" * 50)
    print("[HELIOS-NET] Building High-Performance Rust Core...")
    print("=" * 50)

    rust_dir = ROOT / "rust-core"
    if not rust_dir.exists() or not (rust_dir / "Cargo.toml").exists():
        print("[-] rust-core directory or Cargo.toml not found.")
        return

    print("\n[+] Compiling Rust core (release mode)...")
    success = run_cmd(["cargo", "build", "--release"], rust_dir)
    if success:
        print("[+] Rust core compiled successfully.")
    else:
        print("[-] Rust core compilation failed (ensure Rust/Cargo is installed).")


def main() -> None:
    print("[HELIOS-NET] Initializing Polyglot Build Pipeline...")
    
    # Check Go
    try:
        res = subprocess.run(["go", "version"], capture_output=True, text=True)
        print(f"[+] Found Go: {res.stdout.strip()}")
        build_go_components()
    except FileNotFoundError:
        print("[-] Go compiler not found in PATH. Skipping Go builds.")

    # Check Cargo/Rust
    try:
        res = subprocess.run(["cargo", "--version"], capture_output=True, text=True)
        print(f"[+] Found Cargo: {res.stdout.strip()}")
        build_rust_core()
    except FileNotFoundError:
        print("[-] Cargo/Rust compiler not found in PATH. Skipping Rust builds.")

    print("\n" + "=" * 50)
    print("[HELIOS-NET] Build Pipeline Completed.")
    print("=" * 50)


if __name__ == "__main__":
    main()
