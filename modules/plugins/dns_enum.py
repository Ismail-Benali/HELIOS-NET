"""HELIOS-NET :: modules/plugins/dns_enum.py
Asynchronous Subdomain Enumeration Module with Common Wordlist.
Registers via the @module decorator for dynamic plugin discovery.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from core.planner import PlanStep
from modules.core import module

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "webserver",
    "dns",
    "ns2",
    "smtp",
    "imap",
    "mail1",
    "imap1",
    "ns3",
    "ipv4",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "vpn",
    "gateway",
    "secure",
    "login",
    "portal",
    "cloud",
]


async def _async_resolve(fqdn: str) -> dict[str, Any] | None:
    loop = asyncio.get_running_loop()
    try:
        ip = await loop.getaddrinfo(fqdn, None, family=socket.AF_INET)
        if ip:
            return {"subdomain": fqdn, "ip": ip[0][4][0], "resolves": True}
    except Exception:  # nosec B110 - a name that does not resolve is the expected branch, not an error
        pass
    return None


async def async_subdomain_enum(
    domain: str, wordlist: list[str] = DEFAULT_WORDLIST
) -> list[dict[str, Any]]:
    """Asynchronously resolves common subdomains for the target domain."""
    tasks = [_async_resolve(f"{w}.{domain}") for w in wordlist]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


@module("dns_enum", kind="discovery", wordlist=DEFAULT_WORDLIST)
def dns_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Runs high-performance asynchronous subdomain enumeration."""
    wordlist = step.params.get("wordlist", DEFAULT_WORDLIST)
    try:
        found = asyncio.run(async_subdomain_enum(step.target, wordlist=list(wordlist)))
    except Exception:
        found = []

    ctx.setdefault("findings", []).extend(
        {
            "module": "dns_enum",
            "host": step.target,
            "subdomain": h["subdomain"],
            "ip": h["ip"],
        }
        for h in found
    )
    return {
        "module": "dns_enum",
        "host": step.target,
        "resolved": [h["subdomain"] for h in found],
        "count": len(found),
    }
