"""HELIOS-NET :: core/pivot_proxy.py
Embedded Asynchronous TCP Pivot Proxy & Tunneling Relay.

Enables routing traffic from the orchestrator through a compromised edge node
to reach internal, firewalled private subnets. Pure Python asyncio stdlib.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class PivotProxyServer:
    """Asynchronous TCP Tunneling Pivot Relay."""

    def __init__(self, bind_host: str = "127.0.0.1", bind_port: int = 1080):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._server: asyncio.Server | None = None
        self._active_sessions = 0

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._active_sessions += 1
        peer = writer.get_extra_info("peername")
        try:
            # Expect target handshake: target_ip:target_port\n
            header = await reader.readline()
            if not header:
                return
            header_str = header.decode("utf-8", errors="replace").strip()
            if ":" not in header_str:
                return
            target_host, target_port_str = header_str.rsplit(":", 1)
            target_port = int(target_port_str)

            # Connect to actual target destination
            try:
                target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            except Exception as e:
                log.error(f"Pivot failed to connect to target {target_host}:{target_port}: {e}")
                return

            # Bidirectional relay pipe between client and target
            async def forward(src_reader, dst_writer):
                try:
                    while True:
                        data = await src_reader.read(4096)
                        if not data:
                            break
                        dst_writer.write(data)
                        await dst_writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst_writer.close()
                        await dst_writer.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(reader, target_writer),
                forward(target_reader, writer),
                return_exceptions=True
            )
        except Exception as exc:
            log.error(f"Pivot session error with {peer}: {exc}")
        finally:
            self._active_sessions -= 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.bind_host, self.bind_port
        )
        log.info(f"Pivot Proxy listening on {self.bind_host}:{self.bind_port}")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            log.info("Pivot Proxy stopped.")
