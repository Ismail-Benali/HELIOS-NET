"""
HELIOS-NET :: core/error_envelope.py
Standardized Error Envelope (SEE) — a shared, machine-readable error contract.

All native components (Go, C, Rust) and the Python core exchange failures using a
consistent JSON envelope so the orchestrator can interpret the root cause and adapt
tactics automatically. This eliminates brittle string-matching and unifies diagnostics.

Envelope shape:
    {
        "status": "error",
        "code": "EDR_BLOCKED",
        "message": "Anti-evasion interception detected.",
        "component": "transport/evasion",
        "module": "direct_syscalls"
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Canonical error codes
# ---------------------------------------------------------------------------
ERR_EDR_BLOCKED = "EDR_BLOCKED"
ERR_WAF_TRAP = "WAF_TRAP"
ERR_TIMEOUT = "TIMEOUT"
ERR_CONNECTION_RESET = "CONNECTION_RESET"
ERR_MODULE_MISSING = "MODULE_MISSING"
ERR_BINARY_MISSING = "BINARY_MISSING"
ERR_PARSE = "PARSE_ERROR"
ERR_MEMORY = "MEMORY_FAULT"
ERR_UNKNOWN = "UNKNOWN"

# Tactic fallback map: a failed tactic's preferred replacement.
# mutation_engine.py uses this to pivot automatically without human intervention.
TACTIC_FALLBACK: Dict[str, str] = {
    "direct_syscalls": "memory_loader",
    "memory_loader": "fingerprint",
    "fingerprint": "evasion",
    "evasion": "direct_syscalls",
}


def build_envelope(
    code: str,
    message: str,
    component: str,
    module: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Constructs a standardized error envelope as a Python dict."""
    envelope: Dict[str, Any] = {
        "status": "error",
        "code": code,
        "message": message,
        "component": component,
    }
    if module:
        envelope["module"] = module
    if extra:
        envelope.update(extra)
    return envelope


def parse_envelope(payload: str) -> Optional[Dict[str, Any]]:
    """Attempts to parse a raw string (from stdout/stderr) into an error envelope."""
    try:
        data = json.loads(payload.strip())
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(data, dict) and data.get("status") == "error":
        return data
    return None


def is_alarm(status: Dict[str, Any]) -> bool:
    """True when the envelope reports an alarm-worthy condition (EDR/WAF-trap)."""
    if not status:
        return False
    return status.get("code") in (ERR_EDR_BLOCKED, ERR_WAF_TRAP)


def dump_envelope(envelope: Dict[str, Any]) -> str:
    """Serializes an envelope to a single-line JSON string for stream transport."""
    return json.dumps(envelope, ensure_ascii=True)
