# Benchmarks

HELIOS-NET publishes no fixed performance claim. This page records one
reproducible measurement and the command that produced it, so a number can be
replayed on the machine that matters instead of being copied from a blog post.

## How to reproduce

Build the native cores first; without them the dispatcher falls back to Python
and the numbers measure the fallback, not the intended path:

```bash
python -m pip install -r requirements-dev.txt
python build.py
python tools/bench.py --repeat 5 --markdown
```

`tools/bench.py` uses fixed synthetic input for every case, so two runs on the
same host are comparable and a slow result is the implementation rather than a
different workload. It reports the median of the timed runs. `--backend python`
forces the reference path; `--json` emits the same data for a release script.

Network throughput is measured separately against a host you own:

```bash
python tools/bench_scan.py --host 127.0.0.1 --ports 1-1024 --repeat 3
```

## Reference host

| Field | Value |
| --- | --- |
| Platform | Windows 11 (10.0.26200), AMD64 |
| Python | 3.12.0 |
| Native backends available | C, Rust, Go, Python |
| Date | 2026-11-18 |

## Results (5 runs, median)

| Case | Backend | Median (ms) | Workload |
| --- | --- | ---: | --- |
| `nmap-parse` | python | 72.04 | 5,000 ports from 500 hosts |
| `match-signatures` | c-native | 5.22 | 31 KiB text, 204 patterns |
| `fingerprint` | c-native | 0.43 | 31 KiB text, FNV-1a 32-bit |
| `graph-degree` | rust-native | 6.97 | 2,000 nodes, 8,000 edges |
| `graph-betweenness` | rust-native | 14.89 | 300 nodes, 1,200 edges |
| `html-report` | python | 8.81 | 1,000 assets, 2,500 edges |

## Interpretation

- These are single-process, cold-CPU measurements of the library call only;
  they exclude interpreter startup, campaign orchestration and any socket work.
- `nmap-parse` and `html-report` have no native implementation. They are the
  Python cost of reading a document and writing a page, not a claim about the
  Python parser being slow.
- The difference between `auto` and `--backend python` is the point of the
  native cores. On this host, forcing Python moves fingerprinting from 0.43 ms
  to 49.81 ms, degree centrality from 6.97 ms to 30.83 ms, and betweenness from
  14.89 ms to 276.77 ms. Matching barely moves because the Python implementation
  is already a tight loop over a small pattern set.
- Absolute numbers are not portable. Compare the same host across revisions;
  compare different hosts only in ratios.

## What is deliberately not benchmarked

- Live scanning against third-party hosts. Latency, loss and rate limits belong
  to the network, and scanning someone else's host to produce a table is not a
  benchmark, it is an unauthorized test.
- Daemon and long-running campaigns. Their cost is dominated by I/O and task
  scheduling, which needs a different harness than a single library call.
