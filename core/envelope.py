"""HELIOS-NET :: core/envelope.py
Standardized Error Envelope (SEE) parser for native core output.

Native components (Go/C) emit single-line JSON error objects on stderr:

    {"status": "error", "code": "EDR_BLOCKED", "message": "...", "component": "..."}

This module parses those lines defensively; malformed output yields ``None``
rather than raising, because a native fault must never abort a campaign.
"""

from __future__ import annotations

import json
from typing import Any

REQUIRED_KEYS = ("status", "code", "message")


def parse_envelope(line: str | bytes | None) -> dict[str, Any] | None:
    """Parses one SEE line into a dict, or returns None if it is not an envelope."""
    if not line:
        return None

    if isinstance(line, (bytes, bytearray)):
        line = line.decode("utf-8", errors="replace")

    line = line.strip()
    if not line.startswith("{"):
        return None

    try:
        data = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None
    if not all(key in data for key in REQUIRED_KEYS):
        return None
    if data.get("status") != "error":
        return None

    return data
