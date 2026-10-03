"""HELIOS-NET :: modules/internal/subnet_discovery.py
Internal Subnet & Routing Table Discovery Module.

Parses local host routing tables and interface configurations
to dynamically map internal private subnets for network topology awareness.
"""

from __future__ import annotations

import platform
import socket
import subprocess  # nosec B404 - reads the local routing table via the OS utility
from typing import Any


def get_local_interfaces() -> list[dict[str, Any]]:
    """Retrieves active network interfaces and IP configurations."""
    interfaces = []
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
        interfaces.append({"interface": "primary", "ip": ip})
    except Exception:  # nosec B110 - routing tables are optional; the caller falls back to a private prefix
        pass
    return interfaces


def extract_internal_subnets() -> list[str]:
    """Parses system routing tables to identify internal private CIDR prefixes."""
    subnets = []
    sys_platform = platform.system().lower()

    try:
        # The encoding is pinned rather than left to the console codepage:
        # errors="ignore" with a locale decoder silently drops bytes, and a
        # dropped character turns a subnet prefix into a wrong one.
        if sys_platform == "windows":
            output = subprocess.check_output(  # nosec B603, B607 - fixed argv, no shell, no external input; OS utility found via PATH
                ["route", "print"], text=True, encoding="utf-8", errors="replace"
            )
            for line in output.splitlines():
                if "192.168." in line or "10." in line or "172." in line:
                    parts = line.strip().split()
                    if parts:
                        subnets.append(parts[0])
        else:
            # Two direct calls instead of `sh -c "netstat -rn || ip route"`.
            # The shell adds nothing here, both commands are invoked without
            # one, and the fallback becomes explicit rather than encoded in a
            # string that nothing can test.
            output = ""
            for argv in (["netstat", "-rn"], ["ip", "route"]):
                try:
                    output = subprocess.check_output(  # nosec B603 - fixed argv, no shell, no external input
                        argv,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                if output.strip():
                    break
            for line in output.splitlines():
                if "192.168" in line or "10." in line or "172." in line:
                    parts = line.strip().split()
                    if parts:
                        subnets.append(parts[0])
    except Exception:  # nosec B110 - routing tables are optional; the caller falls back to a private prefix
        pass

    # Fallback to standard private prefix if nothing parsed
    if not subnets:
        subnets.append("192.168.1.")

    return list(set(subnets))
