"""HELIOS-NET :: engine/tunneled_scanner.py
Tunneled Multi-Hop Async Recon Scanner.

Routes reconnaissance probes through pivot proxies to scan firewalled
internal subnets without direct external exposure.
"""

from __future__ import annotations

import asyncio
import time
from typing import List


async def tunneled_tcp_probe(target_host: str, target_port: int, proxy_host: str = "127.0.0.1", proxy_port: int = 1080, timeout: float = 3.0) -> dict:
    """Probes an internal target port by tunneling through the pivot proxy."""
    start = time.time()
    try:
        # Connect through proxy relay
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port),
            timeout=timeout
        )
        # Send target destination framing to proxy
        tunnel_header = f"{target_host}:{target_port}\n".encode("utf-8")
        writer.write(tunnel_header)
        await writer.drain()

        writer.close()
        await writer.wait_closed()
        return {
            "target": target_host,
            "port": target_port,
            "tunneled": True,
            "open": True,
            "latency": round(time.time() - start, 4)
        }
    except (asyncio.TimeoutError, OSError):
        return {
            "target": target_host,
            "port": target_port,
            "tunneled": True,
            "open": False,
            "latency": round(time.time() - start, 4)
        }


async def tunneled_subnet_scan(subnet_prefix: str, ports: List[int], proxy_host: str = "127.0.0.1", proxy_port: int = 1080, concurrency: int = 50) -> List[dict]:
    """Scans an entire internal CIDR subnet through the active pivot tunnel."""
    sem = asyncio.Semaphore(concurrency)
    tasks = []

    async def bounded_scan(host: str, port: int):
        async with sem:
            return await tunneled_tcp_probe(host, port, proxy_host, proxy_port)

    # Generate hosts in subnet (e.g., '192.168.1.')
    for i in range(1, 255):
        host = f"{subnet_prefix}{i}"
        for p in ports:
            tasks.append(bounded_scan(host, p))

    results = await asyncio.gather(*tasks)
    return [r for r in results if r["open"]]
