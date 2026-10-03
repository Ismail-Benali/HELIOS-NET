"""HELIOS-NET :: core/accel.py
One interface over the native signature and fingerprint cores.

The project carried three implementations of the same two operations:

* the C core, reached as a subprocess over NDJSON (``core.c_core_bridge``)
* the Rust core, reached as a CDLL inside the process (``core.rust_bridge``)
* a pure-Python matcher that stood in for both when they were unavailable

They had different entry-point names, different return shapes, and no shared
selection policy, so a caller had to know which core was present to use it
correctly. The C bridge's matcher was in fact not called from production code at
all: it was exercised by tests and then bypassed.

This module is the seam. It fixes three things:

1. One result shape for one operation, whatever ran it.
2. One selection policy, with the reason for the choice attached to the result,
   so a degraded run can be explained instead of merely detected.
3. A cross-backend agreement check, because the whole safety argument for a
   fallback is that it produces the same answer as the core it replaces. That
   argument is only worth something if it is actually tested, and two real
   divergences went unnoticed here until this module existed: the Python
   fallback case-folded non-ASCII characters that the native core leaves alone
   (so it invented matches), and it returned character offsets where the cores
   return byte offsets.

Deliberately not included: the C core as a graph backend. It ships no graph
code, so it is registered as a backend that does not implement the capability
rather than quietly being left out of the table.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "BackendInfo",
    "GraphOutcome",
    "Match",
    "MatchOutcome",
    "FingerprintOutcome",
    "PortScanOutcome",
    "backend_infos",
    "backend_infos_by_name",
    "match_signatures",
    "fingerprint",
    "graph_degree_centrality",
    "graph_betweenness",
    "graph_components",
    "graph_shortest_path",
    "scan_ports",
    "compare_backends",
]


# --------------------------------------------------------------- result types

#: The graph operations both the Rust core and the Python fallback implement. The
#: C core ships no graph code, so it is registered without them.
GRAPH_CAPABILITIES = (
    "graph_degree",
    "graph_betweenness",
    "graph_components",
    "graph_shortest_path",
)

#: Port scanning, served by the Go core and by a plain socket probe. The C and
#: Rust cores ship no network code, so they are registered without it.
SCAN_CAPABILITIES = ("scan_ports",)


@dataclass(frozen=True)
class Match:
    """One signature hit, in the shape every core must produce.

    ``position`` is a UTF-8 byte offset, matching the native contract, not a
    character index.
    """

    signature: str
    position: int

    def to_dict(self) -> dict[str, Any]:
        return {"signature": self.signature, "position": self.position}


@dataclass(frozen=True)
class MatchOutcome:
    """The result of one match request, plus how it was produced."""

    matches: tuple[Match, ...]
    engine: str
    reason: str = ""

    def to_dicts(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self.matches]


@dataclass(frozen=True)
class FingerprintOutcome:
    """Digests plus provenance, so a caller can tell native from fallback."""

    fnv1a32: str
    fnv1a64: str = ""
    crc32: str = ""
    engine: str = "python-fallback"
    reason: str = ""

    def to_dict(self) -> dict[str, str]:
        out = {
            "fp_fnv1a32": self.fnv1a32,
            "fp_fnv1a64": self.fnv1a64,
            "fp_crc32": self.crc32,
        }
        return out


@dataclass(frozen=True)
class BackendInfo:
    """What a backend can do and why it is not being used, when it is not."""

    name: str
    available: bool
    reason: str = ""
    capabilities: frozenset[str] = field(default_factory=frozenset)


# ------------------------------------------------------------------- backends


def _c_path() -> str:
    """Which C front end is serving: "ffi", "process", or "python".

    Reported rather than inferred, so a result can state how it was produced.
    """
    from core import c_core_bridge

    return c_core_bridge.native_path()


def _c_info() -> BackendInfo:
    from core import c_core_bridge

    if not c_core_bridge.core_available():
        # A refusal by the host is a different fact from a missing file, and the
        # two are kept apart so a report can say "the C core was blocked by policy"
        # rather than "the C core was not built".
        note = c_core_bridge.availability_note() or c_core_bridge.staleness_note()
        return BackendInfo(
            name="c",
            available=False,
            reason=note or "the C core binary was not found",
            capabilities=frozenset(),
        )
    # A single-pattern Boyer-Moore search exists in the C core, but the Rust core
    # has no equivalent, so exposing it here would make the interface lie about
    # what "match" means across backends.
    return BackendInfo(
        name="c",
        available=True,
        capabilities=frozenset({"match", "fingerprint"}),
    )


def _rust_info() -> BackendInfo:
    from core import rust_bridge

    if not rust_bridge.rust_available():
        return BackendInfo(
            name="rust",
            available=False,
            reason="the Rust library was not found in any candidate directory",
            capabilities=frozenset(),
        )
    # The Rust core implements FNV-1a 32 only. It is not asked for the 64-bit or
    # CRC-32 digests, and pretending otherwise would hand back a partial digest
    # set that looks complete.
    return BackendInfo(
        name="rust",
        available=True,
        capabilities=frozenset({"match", "fnv1a32"}) | frozenset(GRAPH_CAPABILITIES),
    )


def _python_info() -> BackendInfo:
    return BackendInfo(
        name="python",
        available=True,
        reason="always available; this is the fallback of last resort",
        capabilities=frozenset({"match", "fingerprint"})
        | frozenset(GRAPH_CAPABILITIES)
        | frozenset(SCAN_CAPABILITIES),
    )


def _go_info() -> BackendInfo:
    from modules.discovery import goscan_bridge

    if not goscan_bridge.core_available():
        return BackendInfo(
            name="go",
            available=False,
            reason=goscan_bridge.LAST_ERROR or "the Go core binary was not found",
            capabilities=frozenset(),
        )
    # Implemented separately from the others on purpose: this is the only core
    # that opens sockets, and a backend that also served `match` would make
    # "which engine ran" ambiguous for a capability it cannot do.
    return BackendInfo(
        name="go",
        available=True,
        capabilities=frozenset(SCAN_CAPABILITIES),
    )


_BACKENDS = {"c": _c_info, "rust": _rust_info, "go": _go_info, "python": _python_info}

#: Preference order for the text capabilities. The C core is first because its
#: matcher is the one the differential fuzzer and the C↔Python parity work
#: actually cover; the Rust core is next; Python is the floor and is never
#: unavailable, so this list always resolves to something.
#:
#: The Go core is deliberately absent: it opens sockets and implements no text
#: capability, so listing it here would import the discovery bridge on every
#: signature call and prepend "does not implement match" to every reason string.
#: Its preference order lives with `scan_ports`.
_PREFERENCE = ("c", "rust", "python")

#: Every registered backend, for the registry report. The preference order is
#: per capability; this is the full set of things that can answer anything.
_ALL_BACKENDS = ("c", "rust", "go", "python")


def backend_infos() -> list[BackendInfo]:
    """Reports every backend's availability without calling any of them."""
    out: list[BackendInfo] = []
    for name in _ALL_BACKENDS:
        try:
            out.append(_BACKENDS[name]())
        except Exception as exc:  # noqa: BLE001 - a broken import is a state, not a crash
            out.append(
                BackendInfo(
                    name=name,
                    available=False,
                    reason=f"probe raised {type(exc).__name__}: {exc}",
                )
            )
    return out


def backend_infos_by_name() -> dict[str, BackendInfo]:
    """The same report, keyed by backend name."""
    return {info.name: info for info in backend_infos()}


# --------------------------------------------------------------------- python


def _normalise(hits: Iterable[Match]) -> tuple[Match, ...]:
    """Collapses a backend's raw hits into the unified contract.

    Two rules, applied identically to every backend so that a comparison between
    them is meaningful:

    * one hit per (pattern, position). A signature file that lists the same
      pattern under two names makes the C core report it twice, and a pattern
      present at several places is reported once per place. Neither is a
      distinct detection, so neither may inflate the count.
    * deterministic order, so a result does not depend on which backend ran.
    """
    return tuple(sorted(set(hits), key=lambda m: (m.position, m.signature)))


def _python_match(text: str, patterns: Sequence[str]) -> tuple[Match, ...]:
    from core import c_core_bridge

    folded_text = c_core_bridge.fold_ascii(text)
    hits: list[Match] = []
    for pattern in patterns:
        if not pattern:
            continue
        for index in c_core_bridge.find_all_occurrences(
            folded_text, c_core_bridge.fold_ascii(pattern)
        ):
            hits.append(Match(pattern, c_core_bridge.byte_offset(folded_text, index)))
    return tuple(hits)


def _python_fingerprint(text: str) -> FingerprintOutcome:
    from core import c_core_bridge

    return FingerprintOutcome(
        fnv1a32=f"0x{c_core_bridge.fnv1a32_py(text):08X}",
        fnv1a64=f"0x{c_core_bridge.fnv1a64_py(text):016X}",
        crc32=f"0x{c_core_bridge.crc32_py(text):08X}",
        engine="python-fallback",
    )


# --------------------------------------------------------------------- public


def match_signatures(
    text: str,
    patterns: Iterable[str],
    prefer: str | None = None,
) -> MatchOutcome:
    """Matches `patterns` in `text` using the best available backend.

    One call is served by exactly one backend. Results are never merged across
    backends, because a mixed result set would not correspond to any single
    implementation's view of the input and could not be compared against a later
    run on a healthy host.

    `prefer` pins a backend by name; if it is unavailable the reason travels with
    the result and the next available backend is used instead.
    """
    pattern_list = list(patterns)
    if not text or not pattern_list:
        return MatchOutcome((), "none", "nothing to match: empty text or pattern set")

    order = list(_PREFERENCE)
    if prefer:
        if prefer not in _BACKENDS:
            raise ValueError(
                f"unknown backend {prefer!r}; expected one of {sorted(_BACKENDS)}"
            )
        order = [prefer] + [name for name in order if name != prefer]

    reasons: list[str] = []
    for name in order:
        info = _BACKENDS[name]()
        if not info.available:
            reasons.append(f"{name}: {info.reason}")
            continue
        if "match" not in info.capabilities:
            reasons.append(f"{name}: does not implement match")
            continue

        try:
            if name == "c":
                raw_hits = _c_match(text, pattern_list)
            elif name == "rust":
                raw_hits = _rust_match(text, pattern_list)
            else:
                raw_hits = _python_match(text, pattern_list)
        except Exception as exc:  # noqa: BLE001 - degradation is the design
            reasons.append(f"{name}: raised {type(exc).__name__}: {exc}")
            continue

        engine = (
            "c-native"
            if name == "c"
            else "rust-native"
            if name == "rust"
            else "python-fallback"
        )
        reason = "skipped " + "; ".join(reasons) if reasons else ""
        if name == "c":
            # Both C front ends run the same native code, so the engine label is
            # the same either way. Which of the two actually served is still
            # worth stating: an in-process call and a subprocess are different
            # cost and different failure modes, and a report that cannot tell
            # them apart cannot explain why one host is fast and another is not.
            reason = (reason + "; " if reason else "") + f"served by {_c_path()}"
        return MatchOutcome(_normalise(raw_hits), engine, reason)

    # Unreachable: python is registered as always available.
    return MatchOutcome(
        (), "none", "no backend could serve the request: " + "; ".join(reasons)
    )


def _c_match(text: str, patterns: Sequence[str]) -> tuple[Match, ...]:
    from core import c_core_bridge

    if not c_core_bridge.core_available():
        raise RuntimeError(
            c_core_bridge.staleness_note() or "the C core is unavailable"
        )

    # The C core receives patterns as `name<TAB>pattern` lines, so the in-memory
    # interface is projected onto a signature file for this call. The generated
    # names are placeholders that exist only to satisfy that format, so they are
    # translated back to the caller's pattern: a hit has to be identifiable the
    # same way whichever backend produced it, otherwise the same detection
    # compares unequal across cores.
    placeholders = {f"s{i}": p for i, p in enumerate(patterns)}

    with tempfile.TemporaryDirectory() as tmp:
        sig = Path(tmp) / "accel_signatures.txt"
        sig.write_text(
            "".join(f"{name}\t{pattern}\n" for name, pattern in placeholders.items()),
            encoding="utf-8",
        )
        results = c_core_bridge.scan_banners([text], sig)

    if not results:
        return ()
    return tuple(
        Match(
            placeholders.get(str(m["signature"]), str(m["signature"])),
            int(m["position"]),
        )
        for m in results[0].get("matches", [])
        if isinstance(m, dict) and "signature" in m and "position" in m
    )


def _rust_match(text: str, patterns: Sequence[str]) -> tuple[Match, ...]:
    from core import rust_bridge

    raw = rust_bridge.match_json_rust(text, list(patterns))
    return tuple(
        Match(str(m["signature"]), int(m["position"]))
        for m in raw
        if isinstance(m, dict) and "signature" in m and "position" in m
    )


def fingerprint(text: str, prefer: str | None = None) -> FingerprintOutcome:
    """Digests for `text` from the best available backend.

    The digest set is only complete on a backend that implements all three
    algorithms, so a backend that can only produce part of it is not used for
    this call unless it is pinned with `prefer`. An FNV-1a 32 digest from the
    Rust core is available on request, but it is never silently returned in place
    of a full set.
    """
    if not text:
        return FingerprintOutcome("", engine="none", reason="empty text has no digest")

    order = list(_PREFERENCE)
    if prefer:
        if prefer not in _BACKENDS:
            raise ValueError(
                f"unknown backend {prefer!r}; expected one of {sorted(_BACKENDS)}"
            )
        order = [prefer] + [name for name in order if name != prefer]

    reasons: list[str] = []
    for name in order:
        info = _BACKENDS[name]()
        if not info.available:
            reasons.append(f"{name}: {info.reason}")
            continue
        if "fingerprint" not in info.capabilities:
            reasons.append(
                f"{name}: implements only {sorted(info.capabilities)}, not a full digest set"
            )
            continue
        try:
            if name == "c":
                raw = _c_fingerprint(text)
            else:
                raw = _python_fingerprint(text)
        except Exception as exc:  # noqa: BLE001 - degradation is the design
            reasons.append(f"{name}: raised {type(exc).__name__}: {exc}")
            continue
        reason = "skipped " + "; ".join(reasons) if reasons else ""
        if name == "c":
            reason = (reason + "; " if reason else "") + f"served by {_c_path()}"
        return FingerprintOutcome(
            fnv1a32=raw.fnv1a32,
            fnv1a64=raw.fnv1a64,
            crc32=raw.crc32,
            engine="c-native" if name == "c" else "python-fallback",
            reason=reason,
        )

    return FingerprintOutcome(
        "",
        engine="none",
        reason="no backend could serve the request: " + "; ".join(reasons),
    )


def _c_fingerprint(text: str) -> FingerprintOutcome:
    from core import c_core_bridge

    if not c_core_bridge.core_available():
        raise RuntimeError(
            c_core_bridge.staleness_note() or "the C core is unavailable"
        )
    digests = c_core_bridge.fingerprint(text)
    return FingerprintOutcome(
        fnv1a32=digests["fp_fnv1a32"],
        fnv1a64=digests["fp_fnv1a64"],
        crc32=digests["fp_crc32"],
        engine="c-native",
    )


# ------------------------------------------------------------------ graph


@dataclass(frozen=True)
class GraphOutcome:
    """The result of one graph operation, plus which backend produced it.

    `value` is the backend's own return type. These four operations do not share
    a shape - two return rankings, one returns a partition, one returns a path -
    so unifying them means unifying the selection policy and the provenance, not
    forcing a common container. That is deliberate: a wrapper that reshaped them
    into one structure would be inventing a contract neither core has.
    """

    value: Any
    engine: str
    reason: str = ""


def _graph_dispatch(
    capability: str,
    native: Callable[[], Any],
    fallback: Callable[[], Any],
    prefer: str | None,
) -> GraphOutcome:
    """Runs one graph operation on the best backend that implements it.

    Selection is per operation rather than per analysis, so a host whose Rust
    library answers the centrality call but not the path call degrades one result
    and keeps the rest native, and the `reason` says which happened.
    """
    order = [n for n in _PREFERENCE if n in ("rust", "python")]
    if prefer:
        if prefer not in _BACKENDS:
            raise ValueError(
                f"unknown backend {prefer!r}; expected one of {sorted(_BACKENDS)}"
            )
        order = [prefer] + [n for n in order if n != prefer]

    reasons: list[str] = []
    for name in order:
        info = _BACKENDS[name]()
        if not info.available:
            reasons.append(f"{name}: {info.reason}")
            continue
        if capability not in info.capabilities:
            reasons.append(f"{name}: does not implement {capability}")
            continue
        try:
            value = native() if name == "rust" else fallback()
        except Exception as exc:  # noqa: BLE001 - degradation is the design
            reasons.append(f"{name}: raised {type(exc).__name__}: {exc}")
            continue
        reason = "skipped " + "; ".join(reasons) if reasons else ""
        return GraphOutcome(
            value, "rust-native" if name == "rust" else "python-fallback", reason
        )

    return GraphOutcome(
        None, "none", "no backend could serve the request: " + "; ".join(reasons)
    )


def graph_degree_centrality(
    node_count: int, edges: Sequence[tuple[int, int]], prefer: str | None = None
) -> GraphOutcome:
    """`[(node_index, score)]` for every node, highest score first.

    Self-edges and duplicate edges are ignored by both backends, so a re-ingested
    relationship cannot inflate a host's importance.
    """

    def native() -> Any:
        from core import rust_bridge

        return rust_bridge.graph_centrality_rust(node_count, list(edges))

    def fallback() -> Any:
        from engine.graph.core import AssetGraph  # local: avoids a cycle at import

        g = AssetGraph()
        for i in range(node_count):
            g.add_node(str(i), "asset")
        for a, b in edges:
            if 0 <= a < node_count and 0 <= b < node_count:
                g.add_edge(str(a), str(b))
        ranked = g.degree_centrality()
        # The native call returns (node_index, score) pairs. This fallback builds
        # its nodes as `str(i)`, so the node id *is* the index - it must be
        # converted back rather than replaced by the node's rank, which would
        # report a different asset at every position.
        return [(int(nid), score) for nid, score in ranked]

    return _graph_dispatch("graph_degree", native, fallback, prefer)


def graph_betweenness(
    node_count: int, edges: Sequence[tuple[int, int]], prefer: str | None = None
) -> GraphOutcome:
    """A score per node, indexed by node."""

    def native() -> Any:
        from core import rust_bridge

        return rust_bridge.graph_betweenness_rust(node_count, list(edges))

    def fallback() -> Any:
        from engine.graph.core import AssetGraph

        g = AssetGraph()
        for i in range(node_count):
            g.add_node(str(i), "asset")
        for a, b in edges:
            if 0 <= a < node_count and 0 <= b < node_count:
                g.add_edge(str(a), str(b))
        # `_betweenness_python` returns (id, score) sorted by score; the native
        # call returns a plain list indexed by node, so the ranking is spread back
        # over the indices rather than returned in rank order.
        values = [0.0] * node_count
        for nid, score in g._betweenness_python():
            values[int(nid)] = score
        return values

    return _graph_dispatch("graph_betweenness", native, fallback, prefer)


def graph_components(
    node_count: int, edges: Sequence[tuple[int, int]], prefer: str | None = None
) -> GraphOutcome:
    """A partition of the node indices into connected groups, largest first."""

    def native() -> Any:
        from core import rust_bridge

        return rust_bridge.graph_components_rust(node_count, list(edges))

    def fallback() -> Any:
        from engine.graph.core import AssetGraph

        g = AssetGraph()
        for i in range(node_count):
            g.add_node(str(i), "asset")
        for a, b in edges:
            if 0 <= a < node_count and 0 <= b < node_count:
                g.add_edge(str(a), str(b))
        return [[int(x) for x in group] for group in g.connected_components()]

    return _graph_dispatch("graph_components", native, fallback, prefer)


def graph_shortest_path(
    node_count: int,
    edges: Sequence[tuple[int, int]],
    source: int,
    target: int,
    prefer: str | None = None,
) -> GraphOutcome:
    """Fewest-hop node indices from `source` to `target`, or None if disconnected.

    Both backends walk neighbours in ascending node-index order, so equal-length
    routes resolve to the same one. A backend that returned whichever route its
    iteration order reached first would make the answer depend on `PYTHONHASHSEED`
    and on whether the Rust library happened to be installed.
    """

    def native() -> Any:
        from core import rust_bridge

        return rust_bridge.graph_shortest_path_rust(
            node_count, list(edges), source, target
        )

    def fallback() -> Any:
        from engine.graph.core import AssetGraph

        g = AssetGraph()
        for i in range(node_count):
            g.add_node(str(i), "asset")
        for a, b in edges:
            if 0 <= a < node_count and 0 <= b < node_count:
                g.add_edge(str(a), str(b))
        path = g._shortest_path_python(str(source), str(target))
        return None if path is None else (len(path) - 1, [int(x) for x in path])

    return _graph_dispatch("graph_shortest_path", native, fallback, prefer)


@dataclass(frozen=True)
class PortScanOutcome:
    """Which ports answered on `host`, and which core said so.

    `ports` is the comparable part: ascending open port numbers. `rows` keeps
    whatever detail the backend reported - the Go core adds a banner, a detected
    service and a latency, the socket probe does not - so the two are normalised
    to the same *answer* while staying honest about how much each one knows.
    """

    ports: tuple[int, ...]
    rows: tuple[dict[str, Any], ...]
    engine: str
    reason: str = ""


def _python_scan_ports(
    host: str, ports: Sequence[int], timeout: float
) -> tuple[dict[str, Any], ...]:
    """A plain TCP connect per port, concurrently.

    Self-contained on purpose: it must not import from `modules`, because the
    discovery module is the caller that routes through `accel` and an import back
    the other way would close a cycle.
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor

    def probe(port: int) -> tuple[int, str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return port, "open"
        except ConnectionRefusedError:
            return port, "closed"
        except OSError:
            # A timeout is not proof of a closed port, and is reported as such
            # rather than folded into "closed" the way a bare OSError would.
            return port, "filtered"
        finally:
            sock.close()

    workers = min(64, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        states = list(pool.map(probe, ports))

    return tuple(
        {
            "module": "discovery",
            "host": host,
            "port": port,
            "open": state == "open",
            "state": state,
            "service": None,
        }
        for port, state in sorted(states)
        if state == "open"
    )


def scan_ports(
    host: str,
    ports: Sequence[int],
    timeout: float = 2.0,
    prefer: str | None = None,
) -> PortScanOutcome:
    """Probes `ports` on `host` with the best backend that can reach the network.

    The Go core is preferred because it distinguishes `closed` from `filtered`;
    the socket probe cannot tell a refused connection from a dropped one without
    reading the error, so it reports `filtered` on timeout. Both report only open
    ports in `rows`, which is what makes them comparable at all.
    """
    port_list = [int(p) for p in ports]
    if not host or not port_list:
        return PortScanOutcome((), (), "none", "nothing to probe: no host or no ports")

    order = ["go", "python"]
    if prefer:
        if prefer not in _BACKENDS:
            raise ValueError(
                f"unknown backend {prefer!r}; expected one of {sorted(_BACKENDS)}"
            )
        order = [prefer] + [n for n in order if n != prefer]

    reasons: list[str] = []
    for name in order:
        info = _BACKENDS[name]()
        if not info.available:
            reasons.append(f"{name}: {info.reason}")
            continue
        if "scan_ports" not in info.capabilities:
            reasons.append(f"{name}: does not implement scan_ports")
            continue
        try:
            if name == "go":
                raw: Sequence[dict[str, Any]] = _go_scan(host, port_list, timeout)
            else:
                raw = _python_scan_ports(host, port_list, timeout)
        except Exception as exc:  # noqa: BLE001 - degradation is the design
            reasons.append(f"{name}: raised {type(exc).__name__}: {exc}")
            continue

        rows = tuple(raw)
        reason = "skipped " + "; ".join(reasons) if reasons else ""
        return PortScanOutcome(
            ports=tuple(sorted(int(r["port"]) for r in rows if "port" in r)),
            rows=rows,
            engine="go-native" if name == "go" else "python-fallback",
            reason=reason,
        )

    return PortScanOutcome(
        (), (), "none", "no backend could serve the request: " + "; ".join(reasons)
    )


def _go_scan(host: str, ports: Sequence[int], timeout: float) -> list[dict[str, Any]]:
    from modules.discovery import goscan_bridge

    if not goscan_bridge.core_available():
        raise RuntimeError("the Go core binary was not found")

    # The Go core takes a port specification string, not a list, and its own
    # default is its "common" set rather than the caller's list, so the caller's
    # ports are always passed explicitly.
    spec = ",".join(str(p) for p in ports)
    # `strict=True` so a core failure raises and is reported as a reason here,
    # instead of returning an empty list that reads as "nothing was open".
    rows = list(goscan_bridge.run_go_scan(host, spec, strict=True))

    # The bridge also records failures on a module global. Without this check an
    # empty result and a failed run are the same value, so a refused or blocked
    # core would be reported as "the port is closed" - a confident answer built
    # on a probe that never happened.
    if goscan_bridge.LAST_ERROR:
        raise RuntimeError(goscan_bridge.LAST_ERROR)

    return rows


# ------------------------------------------------------------- cross-checking


def compare_backends(
    text: str,
    patterns: Iterable[str],
) -> dict[str, Any]:
    """Runs every available backend over the same input and compares results.

    This is the check that makes the fallback safe, so it is a first-class
    function rather than something only the tests do. A disagreement between two
    backends is the signature of exactly the class of bug that a differential
    fuzzer cannot see, because such a fuzzer only compares one core against an
    oracle written in its own language.

    Returns a dict with the per-backend matches, the backends that agreed, and
    the specific disagreements.
    """
    pattern_list = list(patterns)
    per_backend: dict[str, list[dict[str, Any]]] = {}
    skipped: dict[str, str] = {}

    for name in _PREFERENCE:
        info = _BACKENDS[name]()
        if not info.available:
            skipped[name] = info.reason
            continue
        try:
            outcome = match_signatures(text, pattern_list, prefer=name)
            per_backend[name] = outcome.to_dicts()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            skipped[name] = f"raised {type(exc).__name__}: {exc}"

    if not per_backend:
        return {
            "text": text,
            "backends": {},
            "skipped": skipped,
            "agree": None,
            "disagreements": {},
        }

    # Order is irrelevant to whether two backends detected the same thing, so
    # comparison is on the sorted set of hits rather than on emission order.
    def key(found: list[dict[str, Any]]) -> tuple[tuple[str, int], ...]:
        return tuple(sorted((m["signature"], m["position"]) for m in found))

    reference_name = next(iter(per_backend))
    reference = key(per_backend[reference_name])
    disagreements = {
        name: {
            "this": [list(hit) for hit in key(found)],
            "reference": [list(hit) for hit in reference],
            "reference_backend": reference_name,
        }
        for name, found in per_backend.items()
        if key(found) != reference
    }

    # One backend cannot corroborate itself. Reporting `agree: true` from a single
    # surviving core would dress a fallback up as a verified result - the exact
    # confusion that made a blocked C core look like a three-way agreement, with
    # its Python answers standing in for the native arm.
    corroborated = len(per_backend) >= 2

    return {
        "text": text,
        "backends": per_backend,
        "skipped": skipped,
        "agree": (not disagreements) if corroborated else None,
        "corroborated": corroborated,
        "disagreements": disagreements,
    }
