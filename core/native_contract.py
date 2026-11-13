"""Versioned capability and normalized-result contract for native engines.

The registry describes what each backend implements independently from whether
its binary is usable on this host. Transport boundaries remain backend-specific:
Go/C use their existing process protocols, Rust uses its C ABI, and Python is
the reference/fallback implementation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

CONTRACT_VERSION = "1.0.0"

# This is the source-level capability matrix. Runtime availability must never
# erase knowledge of what a backend is designed to implement.
SUPPORTED_CAPABILITIES: dict[str, frozenset[str]] = {
    "go": frozenset({"scan_ports"}),
    "c": frozenset({"match", "fingerprint"}),
    "rust": frozenset({
        "match", "fnv1a32", "graph_degree", "graph_betweenness",
        "graph_components", "graph_shortest_path",
    }),
    "python": frozenset({
        "match", "fingerprint", "scan_ports", "graph_degree",
        "graph_betweenness", "graph_components", "graph_shortest_path",
    }),
}

TRANSPORTS = {
    "go": "ndjson-process",
    "c": "ndjson-process-or-ffi",
    "rust": "c-abi",
    "python": "in-process",
}

STATES = frozenset({
    "ready", "fallback", "blocked", "failed", "unavailable", "unsupported",
})


@dataclass(frozen=True)
class CapabilityEntry:
    backend: str
    capability: str
    state: str
    transport: str
    reason: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _unavailable_state(reason: str) -> str:
    lowered = reason.lower()
    if any(token in lowered for token in ("4551", "application control", "policy refused", "blocked")):
        return "blocked"
    if any(token in lowered for token in ("stale", "failed", "raised", "error", "could not execute")):
        return "failed"
    return "unavailable"


def capability_registry() -> dict[str, Any]:
    """Return the versioned backend/capability matrix for this host."""
    from core.accel import backend_infos

    infos = {info.name: info for info in backend_infos()}
    entries: list[CapabilityEntry] = []
    for backend, supported in SUPPORTED_CAPABILITIES.items():
        info = infos.get(backend)
        for capability in sorted(set().union(*SUPPORTED_CAPABILITIES.values())):
            if capability not in supported:
                state, reason = "unsupported", "backend does not implement this capability"
            elif backend == "python":
                state, reason = "fallback", info.reason if info else "reference backend"
            elif info is None:
                state, reason = "failed", "backend probe returned no registry entry"
            elif info.available:
                state, reason = "ready", info.reason
            else:
                reason = info.reason or "backend is not available on this host"
                state = _unavailable_state(reason)
            entries.append(CapabilityEntry(
                backend=backend,
                capability=capability,
                state=state,
                transport=TRANSPORTS[backend],
                reason=reason,
            ))
    return {
        "contract_version": CONTRACT_VERSION,
        "capabilities": sorted(set().union(*SUPPORTED_CAPABILITIES.values())),
        "backends": [
            {
                "name": name,
                "transport": TRANSPORTS[name],
                "supported_capabilities": sorted(capabilities),
            }
            for name, capabilities in SUPPORTED_CAPABILITIES.items()
        ],
        "entries": [entry.to_dict() for entry in entries],
    }


def normalize_outcome(capability: str, outcome: Any) -> dict[str, Any]:
    """Serialize an existing accel outcome without discarding provenance.

    This is an additive reporting contract; existing Python return types and
    backend-specific transport boundaries remain unchanged.
    """
    if capability not in set().union(*SUPPORTED_CAPABILITIES.values()):
        raise ValueError(f"unknown capability: {capability}")

    engine = str(getattr(outcome, "engine", "none"))
    reason = str(getattr(outcome, "reason", "") or "")
    if engine == "none":
        state = "failed" if any(
            token in reason.lower() for token in ("raised", "failed", "error", "timeout")
        ) else "unavailable"
    elif engine == "python-fallback":
        state = "degraded"
    else:
        state = "success"

    if hasattr(outcome, "to_dicts"):
        data: Any = outcome.to_dicts()
    elif hasattr(outcome, "to_dict"):
        data = outcome.to_dict()
    elif hasattr(outcome, "value"):
        data = outcome.value
    elif hasattr(outcome, "ports") and hasattr(outcome, "rows"):
        data = {"ports": list(outcome.ports), "rows": list(outcome.rows)}
    else:
        data = None

    return {
        "contract_version": CONTRACT_VERSION,
        "capability": capability,
        "status": state,
        "backend": engine,
        "reason": reason,
        "result": data,
    }
