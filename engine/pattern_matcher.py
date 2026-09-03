"""HELIOS-NET :: engine/pattern_matcher.py
Aho-Corasick Automaton with Dynamic JSON Signature Loading.

Allows loading custom signatures and protocol vulnerability definitions
at runtime from external configuration files without code modification.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Dict, List


class ACNode:
    def __init__(self):
        self.children: Dict[str, ACNode] = {}
        self.failure: ACNode | None = None
        self.outputs: List[str] = []
        self.is_end: bool = False


class AhoCorasickMatcher:
    """Enterprise Aho-Corasick Automaton with dynamic JSON loading."""

    def __init__(self):
        self.root = ACNode()
        self._signatures: dict[str, str] = {}

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
            "openssh", "apache", "nginx", "microsoft-iis", 
            "mariadb", "postgres", "redis", "vsftpd", "dropbear"
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

    def match(self, text: str) -> List[dict]:
        text_lower = text.lower()
        node = self.root
        hits = []
        matched = set()

        for i, char in enumerate(text_lower):
            while node and char not in node.children:
                node = node.failure
            if not node:
                node = self.root
                continue
            node = node.children[char]
            for pattern in node.outputs:
                if pattern not in matched:
                    matched.add(pattern)
                    hits.append({
                        "signature": pattern,
                        "matched": pattern,
                        "position": i - len(pattern) + 1
                    })

        return hits
