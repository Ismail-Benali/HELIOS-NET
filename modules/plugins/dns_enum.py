"""HELIOS-NET :: modules/plugins/dns_enum.py
Example extension module: DNS reconnaissance (subdomain enumeration).

Registers itself via the @module decorator — discovered and loaded by
modules.core.discover without editing any manual registry. This is a live
example of adding a new strategy to the system in just two lines.
"""

from __future__ import annotations

import socket

from modules.core import module


def _subdomains(domain: str, wordlist: list[str],
                timeout: float = 2.0) -> list[dict]:
    """Probes standard subdomains and keeps the ones that resolve.

    Arg:
      domain: the (authorized/owned) domain.
      wordlist: subdomain transformation words.
      timeout: query timeout (native quality, no library).

    Returns:
      A list of subdomains that resolve.
    """
    hits = []
    for w in wordlist:
        fqdn = f"{w}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            hits.append({"subdomain": fqdn, "resolves": True})
        except OSError:
            continue
    return hits


@module("dns_enum", kind="discovery", wordlist=("www", "admin", "api", "mail", "dev"))
def dns_runner(step, ctx) -> dict:
    """Runs subdomain enumeration against the step's target."""
    wordlist = step.params.get("wordlist", ("www", "admin", "api", "mail", "dev"))
    found = _subdomains(step.target, wordlist=list(wordlist))
    # record the raw findings into the shared campaign context.
    ctx.setdefault("findings", []).extend(
        {"module": "dns_enum", "host": step.target, "subdomain": h["subdomain"]}
        for h in found
    )
    return {"module": "dns_enum", "host": step.target,
            "resolved": [h["subdomain"] for h in found], "count": len(found)}
