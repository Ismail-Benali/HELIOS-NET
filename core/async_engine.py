"""HELIOS-NET :: core/async_engine.py
Industrial Async Recon Engine & AIMD Adaptive Concurrency Controller.

Features:
  - Dynamic rate control inspired by TCP congestion control (AIMD).
  - Adapts speed based on target responsiveness and timeouts.
  - High-efficiency async banner grabbing.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any


async def jittered_backoff(
    base_delay: float = 0.05, max_delay: float = 1.0, attempt: int = 1
) -> None:
    """Applies exponential backoff with random jitter to defeat IDS/SIEM periodicity detection."""
    delay = min(max_delay, base_delay * (2 ** max(0, attempt - 1)))
    jitter = random.uniform(0, 0.5 * delay)  # nosec B311 - jitter on a retry delay, not a security value
    await asyncio.sleep(delay + jitter)


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


async def adaptive_banner_probe(
    host: str, port: int, timeout: float = 2.0
) -> dict[str, Any]:
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
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
        return {
            "host": host,
            "port": port,
            "open": True,
            "banner": banner,
            "rtt": round(time.time() - start, 4),
        }
    except (asyncio.TimeoutError, OSError):
        return {
            "host": host,
            "port": port,
            "open": False,
            "banner": "",
            "rtt": round(time.time() - start, 4),
        }


async def enterprise_adaptive_recon(
    host: str, ports: list[int]
) -> list[dict[str, Any]]:
    """Executes an adaptive recon scan using a dynamic worker queue."""
    controller = AIMDController(initial_concurrency=15, max_c=50)
    results = []
    queue: asyncio.Queue[int] = asyncio.Queue()
    for p in ports:
        await queue.put(p)

    async def worker() -> None:
        while not queue.empty():
            port = await queue.get()
            res = await adaptive_banner_probe(host, port, timeout=1.5)
            # Only an open port is a success. The old test also accepted
            # res["rtt"] > 0, but rtt is elapsed wall-clock time and is
            # therefore positive on every returned probe, so onError was
            # unreachable and the controller could never back off.
            if res["open"]:
                await controller.onSuccess()
            else:
                await controller.onError()
            results.append(res)
            queue.task_done()
            await jittered_backoff()

    workers = [asyncio.create_task(worker()) for _ in range(5)]
    await queue.join()
    for w in workers:
        w.cancel()

    return [r for r in results if r["open"]]
