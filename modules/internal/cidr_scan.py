"""HELIOS-NET :: modules/internal/cidr_scan.py
Asynchronous CIDR Subnet Sweeper & Port Discovery Module.
Uses Python stdlib ipaddress and asyncio for high-speed network reconnaissance.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any


async def probe_host_port(host: str, port: int, timeout: float = 1.0) -> dict[str, Any]:
    """Probes a single host and port asynchronously."""
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return {
            "host": host,
            "port": port,
            "open": True,
            "latency": round(time.time() - start, 4),
        }
    except (asyncio.TimeoutError, OSError):
        return {
            "host": host,
            "port": port,
            "open": False,
            "latency": round(time.time() - start, 4),
        }


async def scan_cidr(
    cidr_str: str, ports: list[int], concurrency: int = 100
) -> list[dict[str, Any]]:
    """Scans all hosts in a CIDR block across specified ports concurrently."""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as e:
        return [{"error": f"Invalid CIDR: {e}"}]

    sem = asyncio.Semaphore(concurrency)
    tasks = []

    async def bounded_probe(host: str, port: int) -> dict[str, Any]:
        async with sem:
            return await probe_host_port(host, port)

    for ip in network.hosts():
        host = str(ip)
        for p in ports:
            tasks.append(bounded_probe(host, p))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    active = [r for r in results if isinstance(r, dict) and r.get("open")]
    return active
