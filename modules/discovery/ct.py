"""HELIOS-NET :: modules/discovery/ct.py

Certificate Transparency expansion.

Certificate Transparency logs publish every name a certificate was issued for,
which makes them the cheapest source of subdomains that actually existed in
public. The client is deliberately narrow:

  * it returns names, never URLs, and drops wildcards (``*.example.test``);
  * every candidate is validated syntactically before it leaves this module,
    so a log entry cannot smuggle a header, a path, or a different host;
  * the caller is still responsible for checking the result against the scope.
    This module does not decide what is authorized.

The HTTP fetcher is injectable so tests do not reach the network.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from typing import Any

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
USER_AGENT = "HELIOS-NET/1.0 (+authorized reconnaissance)"
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")

Fetcher = Callable[[str], bytes]


def is_valid_hostname(name: str) -> bool:
    """True for a lowercase DNS name that is safe to use in a request."""
    return bool(_HOST_RE.fullmatch(name)) and len(name) <= 253


def normalise_name(raw: str) -> str | None:
    """Canonicalises one CT entry, returning None when it must be dropped."""
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or not is_valid_hostname(name):
        return None
    return name


def parse_ct_payload(payload: bytes | str) -> list[str]:
    """Extracts unique, valid names from a crt.sh JSON response.

    crt.sh returns a list of objects whose ``name_value`` may contain several
    newline-separated names. Malformed payloads yield an empty list rather than
    an exception: a log outage is not a campaign failure.
    """
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return []
    else:
        text = payload

    try:
        document: Any = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    if isinstance(document, dict):
        document = [document]
    if not isinstance(document, list):
        return []

    names: set[str] = set()
    for entry in document:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if isinstance(value, str):
            candidates = value.split("\n")
        elif isinstance(value, list):
            candidates = [item for item in value if isinstance(item, str)]
        else:
            continue
        for candidate in candidates:
            name = normalise_name(candidate)
            if name is not None:
                names.add(name)
    return sorted(names)


def _default_fetch(url: str, timeout: float = 8.0) -> bytes:
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        return bytes(response.read(MAX_PAYLOAD_BYTES))


def fetch_ct_names(
    domain: str,
    *,
    fetcher: Fetcher | None = None,
    timeout: float = 8.0,
) -> list[str]:
    """Returns CT names for `domain`, or an empty list if the log is unusable.

    Literal addresses have no certificates of their own in CT, so they are
    rejected before a request is made.
    """
    name = normalise_name(domain)
    if name is None:
        return []
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return []

    fetch = fetcher or (lambda url: _default_fetch(url, timeout=timeout))
    try:
        payload = fetch(CRTSH_URL.format(domain=name))
    except Exception:
        return []
    return parse_ct_payload(payload)
