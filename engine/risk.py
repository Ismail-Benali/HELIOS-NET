"""Explainable, evidence-backed risk scoring for HELIOS-NET.

This scorer is a deterministic prioritisation heuristic, not a CVSS calculator
or a claim that a vulnerability has been exploited. It consumes existing
VerdictEngine rules and preserves the rule-level explanation in every result.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from engine.verdict import Rule, default_rules

SCORING_VERSION = "1.0"
DEFAULT_CONFIDENCE = 0.75
DEFAULT_EVIDENCE_FIELDS = (
    "host", "ip", "target", "port", "service", "version", "status", "finding_note",
)


@dataclass(frozen=True)
class RiskFactor:
    """One matched rule and the evidence that supports it."""
    rule: str
    weight: float
    confidence: float
    contribution: float
    note: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "weight": round(self.weight, 3),
            "confidence": round(self.confidence, 3),
            "contribution": round(self.contribution, 4),
            "note": self.note,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class RiskAssessment:
    """Stable risk result with traceable factors."""
    score: int
    severity: str
    confidence: float
    factors: tuple[RiskFactor, ...]
    evidence: dict[str, Any]
    scoring_version: str = SCORING_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "factors": [factor.to_dict() for factor in self.factors],
            "evidence": dict(self.evidence),
            "scoring_version": self.scoring_version,
        }


class RiskScorer:
    """Score findings with bounded noisy-OR aggregation of matched rules.

    Rule weights and confidence values are in [0, 1]. A finding without an
    explicit confidence value uses DEFAULT_CONFIDENCE (0.75).
    """

    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        *,
        evidence_fields: Iterable[str] = DEFAULT_EVIDENCE_FIELDS,
        default_confidence: float = DEFAULT_CONFIDENCE,
    ) -> None:
        self._rules = tuple(default_rules() if rules is None else rules)
        self._evidence_fields = tuple(dict.fromkeys(evidence_fields))
        self._default_confidence = self._unit_interval(
            default_confidence, "default_confidence"
        )
        names = [rule.name for rule in self._rules]
        if len(names) != len(set(names)):
            raise ValueError("risk rule names must be unique")

    @staticmethod
    def _unit_interval(value: Any, name: str) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a finite number in [0, 1]") from exc
        if not math.isfinite(number) or not 0.0 <= number <= 1.0:
            raise ValueError(f"{name} must be a finite number in [0, 1]")
        return number

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def assess(self, finding: dict[str, Any]) -> RiskAssessment:
        if not isinstance(finding, dict):
            raise TypeError("finding must be a dictionary")
        confidence = self._unit_interval(
            finding.get("confidence", self._default_confidence), "confidence"
        )
        evidence = {
            key: finding[key]
            for key in self._evidence_fields
            if key in finding and isinstance(finding[key], (str, int, float, bool))
        }
        factors: list[RiskFactor] = []
        for rule in self._rules:
            if not rule.applies(finding):
                continue
            weight = self._unit_interval(rule.weight, f"rule {rule.name} weight")
            contribution = weight * confidence
            if contribution <= 0:
                continue
            refs = tuple(key for key in self._evidence_fields if key in evidence)
            factors.append(RiskFactor(
                rule=rule.name, weight=weight, confidence=confidence,
                contribution=contribution, note=rule.note, evidence_refs=refs,
            ))

        # A bounded heuristic, not a calibrated probability.
        remaining = 1.0
        for factor in factors:
            remaining *= 1.0 - factor.contribution
        score = round((1.0 - remaining) * 100)
        return RiskAssessment(
            score=score, severity=self._severity(score), confidence=confidence,
            factors=tuple(factors), evidence=evidence,
        )

    def assess_all(self, findings: Iterable[dict[str, Any]]) -> list[RiskAssessment]:
        return [self.assess(finding) for finding in findings]
