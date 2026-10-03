"""HELIOS-NET :: tests/test_scanner.py
Pytest suite for Scanner and load-balancing engine.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.scanner import Scanner, ScanTask


def test_scanner_load_balancing():
    s = Scanner(max_workers=3)
    tasks = [
        ScanTask(name=f"t{i}", fn=lambda i=i: {"i": i}, weight=float(i + 1))
        for i in range(5)
    ]
    batches = s.balanced_batches(tasks, 3)
    assert len(batches) == 3
    results = s.scan(tasks)
    assert len(results) == 5
    assert all(r["ok"] for r in results)
