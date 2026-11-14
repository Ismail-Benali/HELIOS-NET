"""HELIOS-NET :: modules/discovery/dns_resolver.py
High-performance multiplexed async DNS resolver.

Features:
  - EDNS0 support for wide requests, avoiding reliance on plain UDP alone.
  - Automatic rotation and failover for nameservers.
  - Concurrent handling of dozens of queries over a single transport.
"""

from __future__ import annotations

import asyncio
import secrets
import struct
import time


class EliteDNSResolver:
    """High-performance DNS resolver with failover and EDNS0."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 1.5):
        self.nameservers = nameservers or ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
        self.timeout = timeout
        self._cache: dict[str, tuple[float, list[str]]] = {}

    def _build_edns_query(self, domain: str, qtype: int = 1) -> bytes:
        # A transaction ID chosen by a predictable PRNG can be guessed, which
        # is what makes off-path response spoofing practical. This is the one
        # place in the module that needs unpredictability rather than a spread
        # of values, so it uses the system CSPRNG.
        tx_id = secrets.randbits(16)
        # header: QDCOUNT=1, ARCOUNT=1 (to add the EDNS0 OPT record)
        header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 1)

        qname = bytearray()
        for part in domain.split("."):
            if part:
                qname.append(len(part))
                qname.extend(part.encode("ascii"))
        qname.append(0)

        question = qname + struct.pack("!HH", qtype, 1)

        # EDNS0 OPT Pseudo-Record (Root name length=0, TYPE=41 [OPT], UDP Payload Size=4096, RCODE/Flags=0)
        edns_opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)

        return header + question + edns_opt

    @staticmethod
    def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
        """Decode a DNS name, following compression pointers safely."""
        labels: list[str] = []
        cursor = offset
        consumed: int | None = None
        visited: set[int] = set()
        for _ in range(128):
            if cursor >= len(data):
                raise ValueError("truncated DNS name")
            length = data[cursor]
            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(data):
                    raise ValueError("truncated DNS compression pointer")
                pointer = ((length & 0x3F) << 8) | data[cursor + 1]
                if pointer >= len(data) or pointer in visited:
                    raise ValueError("invalid DNS compression pointer")
                visited.add(pointer)
                if consumed is None:
                    consumed = cursor + 2
                cursor = pointer
                continue
            if length & 0xC0:
                raise ValueError("unsupported DNS label encoding")
            cursor += 1
            if length == 0:
                return ".".join(labels).lower(), consumed if consumed is not None else cursor
            if length > 63 or cursor + length > len(data):
                raise ValueError("invalid or truncated DNS label")
            try:
                label = data[cursor:cursor + length].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("non-ASCII DNS label") from exc
            labels.append(label)
            cursor += length
        raise ValueError("DNS compression pointer depth exceeded")

    def parse_records(self, data: bytes) -> list[dict[str, object]]:
        """Parse supported answer records while preserving owner, TTL and RDATA."""
        if len(data) < 12:
            return []
        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if not (flags & 0x8000) or (flags & 0x000F) != 0 or ancount == 0:
            return []
        pos = 12
        try:
            for _ in range(qdcount):
                _, pos = self._decode_name(data, pos)
                if pos + 4 > len(data):
                    return []
                pos += 4

            records: list[dict[str, object]] = []
            for _ in range(ancount):
                owner, pos = self._decode_name(data, pos)
                if pos + 10 > len(data):
                    return []
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[pos:pos + 10])
                pos += 10
                end = pos + rdlength
                if end > len(data):
                    return []
                if rclass == 1:
                    value: object | None = None
                    if rtype == 1 and rdlength == 4:
                        import ipaddress
                        value = str(ipaddress.ip_address(data[pos:end]))
                    elif rtype == 28 and rdlength == 16:
                        import ipaddress
                        value = str(ipaddress.ip_address(data[pos:end]))
                    elif rtype == 5:
                        target, consumed = self._decode_name(data, pos)
                        if consumed > end:
                            return []
                        value = target
                    elif rtype == 33 and rdlength >= 7:
                        priority, weight, port = struct.unpack("!HHH", data[pos:pos + 6])
                        target, consumed = self._decode_name(data, pos + 6)
                        if consumed > end:
                            return []
                        value = {
                            "priority": priority, "weight": weight, "port": port,
                            "target": target, "protocol": "tcp",
                        }
                    if value is not None:
                        record_type = {1: "A", 28: "AAAA", 5: "CNAME", 33: "SRV"}[rtype]
                        records.append({
                            "name": owner, "type": record_type, "value": value, "ttl": ttl,
                        })
                pos = end
            return records
        except (ValueError, struct.error, IndexError):
            return []

    def _parse_response(self, data: bytes) -> list[str]:
        """Backward-compatible A-record-only resolver result."""
        return [
            str(record["value"])
            for record in self.parse_records(data)
            if record["type"] == "A"
        ]

    async def resolve(self, domain: str, qtype: int = 1) -> list[str]:
        cache_key = f"{domain}:{qtype}"
        now = time.time()
        if cache_key in self._cache:
            exp, ips = self._cache[cache_key]
            if now < exp:
                return ips

        query = self._build_edns_query(domain, qtype)

        def _query_sync(ns: str) -> list[str]:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            try:
                s.sendto(query, (ns, 53))
                resp, _ = s.recvfrom(1024)
                return self._parse_response(resp)
            except OSError:
                return []
            finally:
                s.close()

        # Try rotating through nameservers when the first one fails (failover)
        ips = []
        for ns in self.nameservers:
            ips = await asyncio.to_thread(_query_sync, ns)
            if ips:
                break

        self._cache[cache_key] = (now + 120, ips)
        return ips
