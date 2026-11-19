"""Reproducible benchmarks for the components that do the heavy lifting.

`tools/bench_scan.py` measures one path against a real host; this script
measures the deterministic parts against synthetic input so a number can be
reproduced on any machine and compared across releases:

    python tools/bench.py
    python tools/bench.py --repeat 5 --json
    python tools/bench.py --backend python --markdown

Every case runs the same input for every backend, so the only variable is the
implementation. Numbers are medians of the timed runs, in milliseconds.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import accel  # noqa: E402
from core.reporter_interactive import generate_interactive_report  # noqa: E402
from modules.ingest.nmap import parse_nmap_xml  # noqa: E402

TEXT = (
    "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
    "OpenSSH_9.6 protocol 2.0\r\nApache/2.4.58\r\n"
) * 400
PATTERNS = [f"service-{index}" for index in range(200)] + [
    "nginx",
    "OpenSSH",
    "Apache",
    "redis",
]


def _graph(node_count: int, edge_count: int) -> list[tuple[int, int]]:
    rng = random.Random(20240101)
    edges: set[tuple[int, int]] = set()
    while len(edges) < edge_count:
        a, b = rng.randrange(node_count), rng.randrange(node_count)
        if a != b:
            edges.add((a, b))
    return sorted(edges)


def _weighted_graph(node_count: int, edge_count: int) -> list[tuple[int, int, int]]:
    rng = random.Random(20240101)
    edges: set[tuple[int, int, int]] = set()
    while len(edges) < edge_count:
        a, b = rng.randrange(node_count), rng.randrange(node_count)
        if a != b:
            edges.add((a, b, rng.randrange(1, 100)))
    return sorted(edges)


def _nmap_document(hosts: int = 500, ports: int = 10) -> str:
    records = []
    for host in range(hosts):
        rows = "".join(
            f'<port protocol="tcp" portid="{port}"><state state="open"/>'
            f'<service name="svc{port}" product="demo" version="1.0"/></port>'
            for port in range(1, ports + 1)
        )
        records.append(
            f'<host><status state="up"/><address addr="10.0.0.{host % 250}" '
            f'addrtype="ipv4"/><ports>{rows}</ports></host>'
        )
    return f'<?xml version="1.0"?><nmaprun>{"".join(records)}</nmaprun>'


def _report_payload(assets: int = 1000, edges: int = 2500) -> dict:
    nodes = [
        {
            "id": f"asset:{index}",
            "type": "host" if index % 3 else "service",
            "value": f"10.0.0.{index % 250}",
            "metadata": {"index": index},
            "evidence": [{"source": "bench"}],
        }
        for index in range(assets)
    ]
    rng = random.Random(7)
    relationships = []
    for index in range(edges):
        source = rng.randrange(assets)
        target = rng.randrange(assets)
        relationships.append(
            {
                "id": f"edge:{index}",
                "source": f"asset:{source}",
                "target": f"asset:{target}",
                "type": "connects_to",
                "metadata": {},
                "evidence": [],
            }
        )
    return {"schema_version": "1.0", "assets": nodes, "relationships": relationships}


@dataclass(frozen=True)
class Case:
    name: str
    backend: str
    run: Callable[[], None]
    note: str


def _report_case() -> Callable[[], None]:
    payload = _report_payload()
    destination = Path(tempfile.gettempdir()) / "helios-bench-report.html"

    def run() -> None:
        generate_interactive_report(payload, destination)

    return run


def cases(backend: str) -> list[Case]:
    nmap_document = _nmap_document()
    graph_degree = _graph(2000, 8000)
    graph_betweenness = _graph(300, 1200)
    graph_analytics = _weighted_graph(1500, 6000)
    graph_route = [(node, node + 1, 1) for node in range(1499)]
    graph_weighted = sorted(set(graph_analytics + graph_route))
    prefer = None if backend == "auto" else backend
    degree_backend = accel.graph_degree_centrality(
        2000, graph_degree, prefer=prefer
    ).engine
    betweenness_backend = accel.graph_betweenness(
        300, graph_betweenness, prefer=prefer
    ).engine
    pagerank_backend = accel.graph_pagerank(
        1500, graph_weighted, directed=True, prefer=prefer
    ).engine
    route_backend = accel.graph_weighted_shortest_path(
        1500, graph_weighted, 0, 1499, prefer=prefer
    ).engine
    articulation_backend = accel.graph_articulation(
        1500, [(a, b) for a, b, _ in graph_weighted], prefer=prefer
    ).engine
    match_backend = accel.match_signatures(TEXT, PATTERNS, prefer=prefer).engine
    fingerprint_backend = accel.fingerprint(TEXT, prefer=prefer).engine

    return [
        Case(
            "nmap-parse",
            "python",
            lambda: parse_nmap_xml(nmap_document),
            "5,000 ports from 500 hosts",
        ),
        Case(
            "match-signatures",
            match_backend,
            lambda: accel.match_signatures(TEXT, PATTERNS, prefer=prefer),
            f"{len(TEXT) / 1024:.0f} KiB text, {len(PATTERNS)} patterns",
        ),
        Case(
            "fingerprint",
            fingerprint_backend,
            lambda: accel.fingerprint(TEXT, prefer=prefer),
            f"{len(TEXT) / 1024:.0f} KiB text, FNV-1a 32-bit",
        ),
        Case(
            "graph-degree",
            degree_backend,
            lambda: accel.graph_degree_centrality(2000, graph_degree, prefer=prefer),
            "2,000 nodes, 8,000 edges",
        ),
        Case(
            "graph-betweenness",
            betweenness_backend,
            lambda: accel.graph_betweenness(300, graph_betweenness, prefer=prefer),
            "300 nodes, 1,200 edges",
        ),
        Case(
            "graph-pagerank",
            pagerank_backend,
            lambda: accel.graph_pagerank(
                1500, graph_weighted, directed=True, prefer=prefer
            ),
            "1,500 nodes, 7,499 edges",
        ),
        Case(
            "graph-weighted-path",
            route_backend,
            lambda: accel.graph_weighted_shortest_path(
                1500, graph_weighted, 0, 1499, prefer=prefer
            ),
            "1,500 nodes, 7,499 weighted edges",
        ),
        Case(
            "graph-articulation",
            articulation_backend,
            lambda: accel.graph_articulation(
                1500, [(a, b) for a, b, _ in graph_weighted], prefer=prefer
            ),
            "1,500 nodes, 7,499 edges",
        ),
        Case("html-report", "python", _report_case(), "1,000 assets, 2,500 edges"),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument(
        "--backend",
        default="auto",
        choices=["auto", "python", "c", "rust", "go"],
        help="pin a backend; 'auto' lets the dispatcher choose",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--markdown", action="store_true", help="Markdown table")
    args = parser.parse_args(argv)
    if args.repeat < 1:
        raise SystemExit("--repeat must be >= 1")

    results = []
    for case in cases(args.backend):
        samples = []
        for _ in range(args.repeat):
            started = time.perf_counter()
            case.run()
            samples.append((time.perf_counter() - started) * 1000)
        results.append(
            {
                "case": case.name,
                "backend": case.backend,
                "median_ms": statistics.median(samples),
                "runs": args.repeat,
                "note": case.note,
            }
        )

    host = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.machine(),
        "backends": [info.name for info in accel.backend_infos() if info.available],
    }

    if args.json:
        print(json.dumps({"host": host, "results": results}, indent=2))
        return 0

    if args.markdown:
        print("| Case | Backend | Median (ms) | Workload |")
        print("| --- | --- | ---: | --- |")
        for row in results:
            print(
                f"| `{row['case']}` | {row['backend']} | "
                f"{row['median_ms']:.2f} | {row['note']} |"
            )
        return 0

    print(f"platform : {host['platform']}")
    print(f"python   : {host['python']} ({host['processor']})")
    print(f"backends : {', '.join(host['backends'])}")
    print()
    print(f"{'case':<20}{'backend':<10}{'median':>10}   workload")
    for row in results:
        print(
            f"{row['case']:<20}{row['backend']:<10}"
            f"{row['median_ms']:>8.2f}ms   {row['note']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
