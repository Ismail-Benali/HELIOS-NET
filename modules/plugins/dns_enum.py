"""HELIOS-NET :: modules/plugins/dns_enum.py
Asynchronous Subdomain Enumeration Module with Common Wordlist.
Registers via the @module decorator for dynamic plugin discovery.

Scope discipline
----------------
The previous version resolved every word in the list against the target and
emitted whatever answered. That made a single module a way to query names the
operator never authorised: the scope was enforced for network connections made
by other runners, but not for DNS questions. The runner now refuses to run
without a scope, drops candidate names that fall outside it before any resolver
call, and, when the scope declares networks, also drops answers whose address is
outside those networks.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from core.planner import PlanStep
from core.scope import ScopeEnforcer, ScopeError
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


def _candidate_names(domain: str, wordlist: list[str]) -> list[str]:
    return [f"{w}.{domain}" for w in wordlist]


def _ip_in_scope(scope: ScopeEnforcer, address: str) -> bool:
    """Network policy for a resolved address.

    A scope that only lists domains authorises names, so an address it returned
    is informational. A scope that lists networks is an address allow-list, and
    an answer outside it must not be emitted as a finding.
    """
    if not scope.networks:
        return True
    return scope.is_target_allowed(address)


async def async_subdomain_enum(
    domain: str,
    wordlist: list[str] = DEFAULT_WORDLIST,
    scope: ScopeEnforcer | None = None,
) -> list[dict[str, Any]]:
    """Asynchronously resolves common subdomains for the target domain.

    With a scope, candidate names are filtered before resolution and answers
    outside the scope's networks are discarded.
    """
    names = _candidate_names(domain, list(wordlist))
    if scope is not None:
        names = [name for name in names if scope.is_target_allowed(name)]
    tasks = [_async_resolve(name) for name in names]
    results = await asyncio.gather(*tasks)
    found = [r for r in results if r is not None]
    if scope is not None:
        found = [r for r in found if _ip_in_scope(scope, r["ip"])]
    return found


@module("dns_enum", kind="discovery", wordlist=DEFAULT_WORDLIST)
def dns_runner(step: PlanStep, ctx: dict[str, Any]) -> dict[str, Any]:
    """Runs scope-bound asynchronous subdomain enumeration."""
    scope = ctx.get("scope")
    if not isinstance(scope, ScopeEnforcer):
        return {
            "module": "dns_enum",
            "host": step.target,
            "count": 0,
            "resolved": [],
            "error": "scope required for DNS enumeration",
        }
    try:
        scope.check(step.target)
    except ScopeError as exc:
        return {
            "module": "dns_enum",
            "host": step.target,
            "count": 0,
            "resolved": [],
            "error": str(exc),
        }

    wordlist = step.params.get("wordlist", DEFAULT_WORDLIST)
    candidates = _candidate_names(step.target, list(wordlist))
    blocked = [name for name in candidates if not scope.is_target_allowed(name)]
    try:
        found = asyncio.run(
            async_subdomain_enum(step.target, wordlist=list(wordlist), scope=scope)
        )
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
        "blocked": len(blocked),
    }
