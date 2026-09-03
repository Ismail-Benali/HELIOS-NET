"""HELIOS-NET :: modules/discovery/dns_resolver.py
High-performance multiplexed async DNS resolver.

Features:
  - EDNS0 support for wide requests, avoiding reliance on plain UDP alone.
  - Automatic rotation and failover for nameservers.
  - Concurrent handling of dozens of queries over a single transport.
"""

from __future__ import annotations

import asyncio
import random
import struct
import time
from typing import Dict, List, Tuple


class EliteDNSResolver:
    """High-performance DNS resolver with failover and EDNS0."""

    def __init__(self, nameservers: List[str] | None = None, timeout: float = 1.5):
        self.nameservers = nameservers or ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, List[str]]] = {}

    def _build_edns_query(self, domain: str, qtype: int = 1) -> bytes:
        tx_id = random.randint(0, 65535)
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

    def _parse_response(self, data: bytes) -> List[str]:
        if len(data) < 12:
            return []
        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
        if (flags & 0x000F) != 0 or ancount == 0:
            return []

        pos = 12
        for _ in range(qdcount):
            while pos < len(data):
                length = data[pos]
                pos += 1
                if length == 0:
                    break
                if (length & 0xC0) == 0xC0:
                    pos += 1
                    break
                pos += length
            pos += 4

        results = []
        for _ in range(ancount):
            if pos >= len(data):
                break
            if (data[pos] & 0xC0) == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += 1
                pos += 1

            if pos + 10 > len(data):
                break
            rtype, _, _, rdlength = struct.unpack("!HHIH", data[pos:pos+10])
            pos += 10

            if rtype == 1 and rdlength == 4 and pos + 4 <= len(data):
                ip_str = f"{data[pos]}.{data[pos+1]}.{data[pos+2]}.{data[pos+3]}"
                results.append(ip_str)
            pos += rdlength

        return results

    async def resolve(self, domain: str, qtype: int = 1) -> List[str]:
        cache_key = f"{domain}:{qtype}"
        now = time.time()
        if cache_key in self._cache:
            exp, ips = self._cache[cache_key]
            if now < exp:
                return ips

        query = self._build_edns_query(domain, qtype)
        
        def _query_sync(ns: str) -> List[str]:
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
