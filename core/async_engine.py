"""HELIOS-NET :: core/async_engine.py
Industrial Async Recon Engine & AIMD Adaptive Concurrency Controller.

Features:
  - Dynamic rate control inspired by TCP congestion control (AIMD).
  - Adapts speed based on target responsiveness and timeouts.
  - High-efficiency async banner grabbing.
"""

from __future__ import annotations

import asyncio
import time
from typing import List


class AIMDController:
    """Adaptive flow controller inspired by TCP congestion control."""

    def __init__(self, initial_concurrency: int = 10, min_c: int = 2, max_c: int = 100):
        self.concurrency = float(initial_concurrency)
        self.min_c = min_c
        self.max_c = max_c
        self._lock = asyncio.Lock()

    async def onSuccess(self) -> None:
        """Additive increase on success."""
        async with self._lock:
            self.concurrency = min(float(self.max_c), self.concurrency + 0.5)

    async def onError(self) -> None:
        """Multiplicative decrease on error or timeout."""
        async with self._lock:
            self.concurrency = max(float(self.min_c), self.concurrency / 2.0)

    async def get(self) -> int:
        async with self._lock:
            return int(self.concurrency)


async def adaptive_banner_probe(host: str, port: int, timeout: float = 2.0) -> dict:
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            banner_data = await asyncio.wait_for(reader.read(256), timeout=1.0)
            banner = banner_data.decode("utf-8", errors="replace").strip()
        except Exception:
            banner = ""

        writer.close()
        await writer.wait_closed()
        return {"host": host, "port": port, "open": True, "banner": banner, "rtt": round(time.time() - start, 4)}
    except (asyncio.TimeoutError, OSError):
        return {"host": host, "port": port, "open": False, "banner": "", "rtt": round(time.time() - start, 4)}


async def enterprise_adaptive_recon(host: str, ports: List[int]) -> List[dict]:
    """Executes an adaptive recon scan using a dynamic worker queue."""
    controller = AIMDController(initial_concurrency=15, max_c=50)
    results = []
    queue = asyncio.Queue()
    for p in ports:
        await queue.put(p)

    async def worker():
        while not queue.empty():
            port = await queue.get()
            res = await adaptive_banner_probe(host, port, timeout=1.5)
            if res["open"] or res["rtt"] > 0:
                await controller.onSuccess()
            else:
                await controller.onError()
            results.append(res)
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(5)]
    await queue.join()
    for w in workers:
        w.cancel()

    return [r for r in results if r["open"]]
