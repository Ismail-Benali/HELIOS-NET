"""Reproducible throughput measurement for the discovery path.

The README makes performance claims, so there has to be a command that
produces the number on the machine in front of you rather than a number copied
from an old run. This measures `core.accel.scan_ports` end to end: argument
marshalling, the chosen native backend, and result parsing.

    python tools/bench_scan.py --host 127.0.0.1 --ports 1-1024
    python tools/bench_scan.py --ports 22,80,443 --repeat 5

Ports are whatever you ask for. Closed ports are fine and are the default
target of convenience, but they measure refusal handling; point it at a host
you own to measure real service responses.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import accel  # noqa: E402


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, _, end = chunk.partition("-")
            first, last = int(start), int(end)
            if first > last:
                raise SystemExit(f"invalid range {chunk!r}: start is after end")
            ports.extend(range(first, last + 1))
        else:
            ports.append(int(chunk))
    if not ports:
        raise SystemExit("no ports requested")
    for port in ports:
        if not 1 <= port <= 65535:
            raise SystemExit(f"port {port} is out of range")
    return ports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--ports", default="1-512", help="e.g. '22,80,443' or '1-1024'")
    parser.add_argument(
        "--repeat", type=int, default=3, help="number of timed runs (median reported)"
    )
    args = parser.parse_args(argv)

    ports = parse_ports(args.ports)
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")

    samples: list[float] = []
    open_ports = 0
    engine = "unknown"
    for run in range(args.repeat):
        started = time.perf_counter()
        outcome = accel.scan_ports(args.host, ports)
        elapsed = time.perf_counter() - started
        samples.append(elapsed)
        engine = outcome.engine
        open_ports = len(outcome.rows)
        print(
            f"run {run + 1}/{args.repeat}: {elapsed * 1000:.1f} ms  "
            f"({len(ports) / elapsed:,.0f} ports/s)"
        )

    median = statistics.median(samples)
    print()
    print(f"host      : {args.host}")
    print(f"ports     : {len(ports)}")
    print(f"open      : {open_ports}")
    print(f"engine    : {engine}")
    print(f"median    : {median * 1000:.1f} ms")
    print(f"throughput: {len(ports) / median:,.0f} ports/s")
    if args.repeat > 1:
        spread = max(samples) - min(samples)
        print(f"spread    : {spread * 1000:.1f} ms across {args.repeat} runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
