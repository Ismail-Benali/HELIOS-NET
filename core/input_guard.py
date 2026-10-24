"""HELIOS-NET :: core/input_guard.py

Hardening for untrusted network text.

Service banners are attacker-controlled: a target can answer with control
characters, embedded NULs, or megabytes of data. Nothing downstream (the C
core, the Rust core, or the Python matcher) should ever see raw socket bytes,
so this is the single place where the policy is applied.

The policy is deliberately applied at the network boundary and not inside the
core bridges: the core contract is byte-faithful, and the golden differential
suite compares native and Python answers on the same raw input. Sanitizing in
the bridge would make the two engines disagree on control characters and
silently change the recorded contract.
"""

from __future__ import annotations

#: Upper bound on what one banner may contribute, in UTF-8 bytes. Chosen to
#: cover the largest banners real services send while keeping every downstream
#: allocation bounded.
MAX_BANNER_BYTES = 2048


def sanitize_banner(banner: str, max_bytes: int = MAX_BANNER_BYTES) -> str:
    """Returns `banner` stripped of non-printable characters and length-capped.

    The result is guaranteed to encode to at most `max_bytes` UTF-8 bytes, so a
    caller that hands it to a native core cannot be made to allocate past the
    cap by multi-byte input either.
    """
    if not banner:
        return ""
    cleaned = "".join(char for char in banner if char.isprintable())
    encoded = cleaned.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        encoded = encoded[:max_bytes]
        cleaned = encoded.decode("utf-8", errors="ignore")
    return cleaned
