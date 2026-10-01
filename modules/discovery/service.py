"""HELIOS-NET :: modules/discovery/service.py
Reconnaissance: service and port discovery.

Contract:
  - Probes the (authorized/owned) target and emits a unified service sheet.
  - Relies on nothing but the standard socket in the core - no external tools.
  - Any extension (nmap-parser...) is added as a side module, not a branch of this.
"""

from __future__ import annotations

from typing import Any

import socket
from concurrent.futures import ThreadPoolExecutor

# Common ports for a quick observation pass - extensible from outside.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}


def discover_ports(host: str, ports: list[int] | None = None,
                   timeout: float = 2.0, max_workers: int = 64) -> list[dict[str, Any]]:
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
    results: list[dict[str, Any]] = []
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


def native_connect_probe(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """Probes a single port through the Go core's concurrent scanner.

    Truth about the method: the Go core performs a full TCP connect, not a raw
    SYN probe. Raw-socket SYN scanning is not implemented in this codebase, and
    it would need elevated privileges, so this function does not claim to do it.
    The state is reported honestly:

      - open:     the connect completed.
      - closed:   the peer actively refused the connection.
      - filtered: the connection timed out.

    If the Go core cannot run, `core.accel` serves this from the socket probe and
    the answer says which one produced it in `source` and `engine`, because a
    caller must be able to tell how the result was obtained.
    """
    from core.accel import scan_ports

    outcome = scan_ports(host, [int(port)], timeout=timeout)
    native = outcome.engine == "go-native"

    if not outcome.rows:
        # No backend could run at all: nothing was probed, so nothing is known.
        if outcome.engine == "none":
            return {
                "module": "discovery", "host": host, "port": port,
                "open": False, "state": "unknown",
                "source": "none", "engine": "none", "note": outcome.reason,
            }
        # A backend ran and reported the port closed. That is only a real
        # "closed" verdict when the Go core said so: a socket probe returning
        # nothing proves less, so it stays "unknown" with the reason attached.
        return {
            "module": "discovery", "host": host, "port": port,
            "open": False,
            "state": "closed" if native else "unknown",
            "source": "native(Go)" if native else "fallback(socket)",
            "engine": outcome.engine,
            "engine_reason": outcome.reason,
            **({} if native else {"note": outcome.reason}),
        }

    row = dict(outcome.rows[0])
    return {
        "module": "discovery", "host": host, "port": port,
        "open": True,
        # `open` is the factual claim and holds whichever core observed it. The
        # `state` field is the qualified one, and only the Go core can tell a
        # refused connection from a timed-out one, so a socket-probe hit stays
        # "unknown": a connect says the port answered, not how it answered.
        "state": row.get("state", "open") if native else "unknown",
        "service": row.get("service"),
        "banner": row.get("banner", ""),
        "latency_ms": row.get("latency_ms"),
        "source": row.get("source", "native(Go)" if native else "fallback(socket)"),
        "engine": outcome.engine,
        "engine_reason": outcome.reason,
        **({} if native else {"note": outcome.reason}),
    }


def native_syn_probe(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """Deprecated alias for :func:`native_connect_probe`.

    The old name promised a raw SYN probe, which this project does not
    implement. Callers that switch to the new name stop advertising a method
    they were never getting.
    """
    return native_connect_probe(host, port, timeout)
