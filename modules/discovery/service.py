"""HELIOS-NET :: modules/discovery/service.py
Reconnaissance: service and port discovery.

Contract:
  - Probes the (authorized/owned) target and emits a unified service sheet.
  - Relies on nothing but the standard socket in the core — no external tools.
  - Any extension (nmap-parser...) is added as a side module, not a branch of this.
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor

from transport import RAWSYNC, _run

# Common ports for a quick observation pass — extensible from outside.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def discover_ports(host: str, ports: list[int] | None = None,
                   timeout: float = 2.0, max_workers: int = 64) -> list[dict]:
    """Discovers open ports on a host in the lab.

    Args:
      host: the target host (must be authorized/owned).
      ports: a port list; falls back to COMMON_PORTS if not given.
      timeout: connection timeout in seconds.
      max_workers: parallel concurrency for the probe operations.

    Returns:
      A list of findings shaped like {module, host, port, service, open}.
    """
    ports = ports or list(COMMON_PORTS.keys())
    results: list[dict] = []
    lock = __import__("threading").Lock()

    def probe(p: int) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            open_port = True
        except OSError:
            open_port = False
        finally:
            s.close()
        if open_port:
            with lock:
                results.append({
                    "module": "discovery",
                    "host": host,
                    "port": p,
                    "service": COMMON_PORTS.get(p, "unknown"),
                    "open": True,
                })

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(probe, ports))

    results.sort(key=lambda d: d["port"])
    return results


def native_syn_probe(host: str, port: int, timeout: float = 5.0) -> dict:
    """Probes the port via the Go core (rawsync) listening for a real SYN-ACK reply.

    Relies on the JSON output from the raw socket:
      - open:     received a SYN-ACK.
      - closed:   received RST.
      - filtered: timed out or raw-socket restrictions.

    If privileges fail or the binary is missing, it falls back safely to the
    standard socket.
    """
    ok, out = _run(RAWSYNC, [host, str(port)], timeout=timeout)
    if not ok:
        # safety fallback to the standard socket under system restrictions
        return discover_ports(host, ports=[port], timeout=2.0) and {"module": "discovery", "host": host, "port": port, "open": True, "source": "fallback(socket)"} or {"module": "discovery", "host": host, "port": port, "open": False, "source": "fallback(socket)"}

    # try to read the JSON output from the binary
    try:
        data = json.loads(out.strip())
        state = data.get("state", "filtered")
        is_open = (state == "open")
        return {
            "module": "discovery",
            "host": host,
            "port": port,
            "open": is_open,
            "state": state,
            "source": data.get("source", "native(Go-raw)"),
            "note": data.get("error", "")
        }
    except json.JSONDecodeError:
        # standard fallback
        return {"module": "discovery", "host": host, "port": port, "open": False, "source": "native(Go-raw:parse-error)", "raw_out": out}
