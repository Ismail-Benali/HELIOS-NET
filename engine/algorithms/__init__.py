"""HELIOS-NET :: engine/algorithms — the swappable algorithm system.

Imports the algorithm subclasses (balancing, fingerprint, ...) automatically
so the central registry is populated as soon as the package is imported.

Philosophy:
  Every algorithm is registered in a unified central registry and carries a
  name and a fixed interface. Switching an algorithm (balancing, fingerprint,
  ...) is done by name without touching the core.
"""

from __future__ import annotations

import importlib

from typing import Callable, TypeVar

T = TypeVar("T")


class AlgorithmError(Exception):
    """Execution error of an algorithm — isolated so it cannot drop a campaign."""


# Central registry: algorithm kind -> {algorithm name -> factory/function}. Generic model.
ALGO_REGISTRY: dict[str, dict[str, Callable[..., T]]] = {}
DEFAULT_FALLBACK = "__default__"


def register_algo(kind: str, name: str, factory: Callable[..., T], default: bool = False) -> None:
    """Registers an algorithm in its kind, optionally as the default fallback."""
    bucket = ALGO_REGISTRY.setdefault(kind, {})
    bucket[name] = factory
    if default:
        bucket[DEFAULT_FALLBACK] = factory


def get_algo(kind: str, name: str | None = None):
    """Retrieves an algorithm, with a safe fallback to the default when absent."""
    bucket = ALGO_REGISTRY.get(kind)
    if not bucket:
        raise AlgorithmError(f"no algorithm class {kind!r}")
    if name and name in bucket:
        return bucket[name]
    if DEFAULT_FALLBACK in bucket:
        return bucket[DEFAULT_FALLBACK]
    return next(iter(bucket.values()))


def list_algos(kind: str | None = None) -> dict:
    if kind is not None:
        return {kind: sorted(ALGO_REGISTRY.get(kind, {}).keys())}
    return {k: sorted(v.keys()) for k, v in ALGO_REGISTRY.items()}


# Load the algorithm subclasses and register them automatically.
for _m in ("balancing", "fingerprint"):
    try:
        importlib.import_module(f".{_m}", __name__)
    except Exception:
        pass
