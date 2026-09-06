"""
HELIOS-NET :: core/drift.py
Attack Surface Drift & Diff Detection Engine.
Compares historical campaign states / WAL snapshots to detect new or removed ASM assets.
"""

from __future__ import annotations

from typing import Any, Dict, List


def compute_surface_drift(previous_findings: List[dict], current_findings: List[dict]) -> Dict[str, Any]:
    """Compares two sets of discovered findings/services and computes delta drift."""
    prev_set = {(f.get("host"), f.get("port")) for f in previous_findings}
    curr_set = {(f.get("host"), f.get("port")) for f in current_findings}

    new_assets = [{"host": h, "port": p} for h, p in (curr_set - prev_set)]
    removed_assets = [{"host": h, "port": p} for h, p in (prev_set - curr_set)]
    stable_assets = [{"host": h, "port": p} for h, p in (curr_set & prev_set)]

    return {
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "stable_assets": stable_assets,
        "drift_detected": len(new_assets) > 0 or len(removed_assets) > 0
    }
