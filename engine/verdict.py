"""HELIOS-NET :: engine/verdict.py
Smart if/then rules that classify risks and preliminary decisions.

Responsibilities:
  - Convert finding sheets into a verdict with a weight and severity.
  - Rules are extensible (plugins) and testable — no scattered logic in modules.
  - The verdict stays grounded in recorded findings, not on out-of-scope guessing.

Standing security note:
  - This component analyzes an internal/authorized scope. Any use outside an
    authorized scope is the user's responsibility; the rules here only classify
    and target nothing beyond classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Rule:
    """A single classification rule."""
    name: str
    weight: float                 # severity weight (0..1)
    test: Callable[[dict], bool]  # does it apply to this finding?
    note: str = ""

    def applies(self, finding: dict) -> bool:
        try:
            return bool(self.test(finding))
        except Exception:
            return False


@dataclass
class Verdict:
    """The classified result for a single finding."""
    finding: dict
    rules_hit: list[str] = field(default_factory=list)
    max_weight: float = 0.0

    def to_dict(self) -> dict:
        return {
            "source": self.finding.get("module", "unknown"),
            "target": self.finding.get("target"),
            "finding": self.finding,
            "rules_hit": self.rules_hit,
            "max_weight": round(self.max_weight, 3),
            "severity": "high" if self.max_weight >= 0.7 else ("medium" if self.max_weight >= 0.4 else "low"),
        }


class VerdictEngine:
    """The rules engine — every rule is a growable plugin component."""

    def __init__(self, rules: list[Rule] | None = None):
        self._rules: list[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def load_plugins(self, registry: dict[str, Callable[[], Rule]]) -> None:
        """Imports rules from the plugins/ registry — extensible without touching the core."""
        for name, factory in registry.items():
            self._rules.append(factory())

    def load_from_json(self, json_path: str | Path) -> int:
        """Dynamically loads rules from an external JSON file (Dynamic DSL)."""
        from pathlib import Path
        import json
        path = Path(json_path)
        if not path.exists():
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            count = 0
            for r_def in data.get("rules", []):
                name = r_def.get("name", "custom_rule")
                weight = float(r_def.get("weight", 0.5))
                key = r_def.get("field", "service")
                val = r_def.get("match", "").lower()
                note = r_def.get("note", "")

                test_fn = lambda f, k=key, v=val: v in str(f.get(k, "")).lower()
                self._rules.append(Rule(name=name, weight=weight, test=test_fn, note=note))
                count += 1
            return count
        except Exception:
            return 0

    def judge(self, finding: dict) -> Verdict:
        v = Verdict(finding=finding)
        for r in self._rules:
            if r.applies(finding):
                v.rules_hit.append(r.name)
                v.max_weight = max(v.max_weight, r.weight)
        return v

    def judge_all(self, findings: list[dict]) -> list[Verdict]:
        return [self.judge(f) for f in findings]


# ----------------------------------------------------------------------------
# Ready-made default rules — loaded by default.
# ----------------------------------------------------------------------------
def default_rules() -> list[Rule]:
    return [
        Rule(
            name="open_service",
            weight=0.3,
            test=lambda f: bool(f.get("open") is True or f.get("port") is not None),
            note="Open service that is suspicious/worth inspecting.",
        ),
        Rule(
            name="unpatched_hint",
            weight=0.6,
            test=lambda f: any(k in str(f.get("service", "")).lower() for k in ("old", "deprecated", "eol")),
            note="Indicates an old, unpatched version.",
        ),
        Rule(
            name="admin_interface",
            weight=0.7,
            test=lambda f: any(k in str(f.get("service", "")).lower() for k in ("admin", "management", "ssh", "rdp")),
            note="Admin/management interface — priority for inspection.",
        ),
        Rule(
            name="default_credentials_hint",
            weight=0.8,
            test=lambda f: any(k in str(f.get("finding_note", "")).lower() for k in ("default", "factory", "weak")),
            note="Indicates default/weak credentials.",
        ),
    ]
