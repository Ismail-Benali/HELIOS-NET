"""HELIOS-NET :: engine/pattern_matcher.py
Signature registry with dynamic JSON loading, backed by the native cores.

Signatures and protocol vulnerability definitions can be loaded at runtime from
external configuration files without code modification. The automaton is the
registry: it registers, deduplicates and enumerates patterns. The search is
delegated to :mod:`core.accel`, so a caller here gets the same results, the same
byte offsets and the same provenance as every other caller of the native cores,
and the same answer whether the C core, the Rust core or the Python fallback
served it.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Any

from core import accel


class ACNode:
    def __init__(self) -> None:
        self.children: dict[str, ACNode] = {}
        self.failure: ACNode | None = None
        self.outputs: list[str] = []
        self.is_end: bool = False


class AhoCorasickMatcher:
    """Enterprise Aho-Corasick Automaton with dynamic JSON loading."""

    def __init__(self) -> None:
        self.root = ACNode()
        self._signatures: dict[str, str] = {}
        # Set by match() to explain why the python path was taken; empty when
        # the native Rust core produced the results.
        self.last_engine_reason: str = ""

    def add_pattern(self, pattern: str) -> None:
        node = self.root
        pat_lower = pattern.lower()
        for char in pat_lower:
            if char not in node.children:
                node.children[char] = ACNode()
            node = node.children[char]
        node.is_end = True
        if pattern not in node.outputs:
            node.outputs.append(pattern)

    def build_failure_links(self) -> None:
        queue: deque[ACNode] = deque()
        for char, child in self.root.children.items():
            child.failure = self.root
            queue.append(child)

        while queue:
            current = queue.popleft()
            for char, child in current.children.items():
                queue.append(child)
                fail_state = current.failure
                while fail_state and char not in fail_state.children:
                    fail_state = fail_state.failure
                child.failure = fail_state.children[char] if fail_state else self.root
                for out in child.failure.outputs:
                    if out not in child.outputs:
                        child.outputs.append(out)

    def load_defaults(self) -> None:
        defaults = [
            "openssh",
            "apache",
            "nginx",
            "microsoft-iis",
            "mariadb",
            "postgres",
            "redis",
            "vsftpd",
            "dropbear",
        ]
        for p in defaults:
            self.add_pattern(p)
        self.build_failure_links()

    def load_from_json(self, json_path: str | Path) -> int:
        """Dynamically loads custom signatures from a JSON file."""
        path = Path(json_path)
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            count = 0
            for name, pattern in data.items():
                self.add_pattern(pattern)
                self._signatures[name] = pattern
                count += 1
            self.build_failure_links()
            return count
        except Exception:
            return 0

    def all_patterns(self) -> list[str]:
        """Collects every pattern currently registered in the automaton."""
        patterns: list[str] = []
        stack = [self.root]
        while stack:
            node = stack.pop()
            for out in node.outputs:
                if out not in patterns:
                    patterns.append(out)
            stack.extend(node.children.values())
        return patterns

    def match(self, text: str) -> list[dict[str, Any]]:
        """Returns matches, each labelled with the engine that produced it.

        The search itself is delegated to :mod:`core.accel`, which picks the
        best available core. The automaton above is kept as the pattern
        registry: it is how signatures are registered, deduplicated and
        enumerated, and the matching it used to do here was a fourth
        implementation of a job three cores already had.

        Every returned dict carries an ``engine`` key. This was the one place in
        the project that could lie: the Rust path and the Python path returned
        dicts of identical shape, so a result produced while the Rust core was
        blocked by host policy was indistinguishable from a native one, and a
        report could not honestly say which engine had run.

        ``last_engine_reason`` records why the chosen engine was chosen, so a
        degraded run can be explained rather than merely detected.

        ``position`` is a UTF-8 byte offset. It used to be a character index
        computed with ``str.find()`` on a lowercased string, which disagreed
        with the cores as soon as a banner contained a multi-byte character,
        and the first occurrence only was reported, so a banner advertising
        several versions of a service was reported once here and repeatedly by
        the C core.
        """
        outcome = accel.match_signatures(text, self.all_patterns())
        self.last_engine_reason = outcome.reason
        return [
            {
                "signature": m.signature,
                "matched": m.signature,
                "position": m.position,
                "engine": outcome.engine,
            }
            for m in outcome.matches
        ]
