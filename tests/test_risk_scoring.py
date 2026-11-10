"""Regression tests for explainable risk scoring."""

from __future__ import annotations

import pytest

from engine.risk import DEFAULT_CONFIDENCE, RiskScorer
from engine.verdict import Rule


def test_empty_finding_has_zero_low_score_and_no_factors():
    result = RiskScorer().assess({"module": "discovery"}).to_dict()
    assert result["score"] == 0
    assert result["severity"] == "low"
    assert result["factors"] == []


def test_score_is_deterministic_and_explains_each_matched_rule():
    finding = {
        "module": "discovery",
        "host": "192.0.2.10",
        "port": 23,
        "service": "telnet",
        "open": True,
        "confidence": 1.0,
    }
    first = RiskScorer().assess(finding).to_dict()
    assert first == RiskScorer().assess(finding).to_dict()
    assert first["score"] == 90
    assert first["severity"] == "critical"
    assert {factor["rule"] for factor in first["factors"]} == {
        "open_service",
        "plaintext_telnet_risk",
    }
    assert first["evidence"]["host"] == "192.0.2.10"
    assert "port" in first["factors"][0]["evidence_refs"]


def test_missing_confidence_uses_documented_default():
    result = RiskScorer().assess({"port": 23, "service": "telnet"}).to_dict()
    assert result["confidence"] == DEFAULT_CONFIDENCE
    assert result["score"] == 72


def test_custom_rules_are_supported():
    rule = Rule(
        name="observed_tls_issue",
        weight=0.8,
        test=lambda finding: finding.get("tls_issue") is True,
        note="TLS evidence explicitly records an issue.",
    )
    result = (
        RiskScorer([rule])
        .assess(
            {
                "tls_issue": True,
                "host": "example.test",
                "confidence": 1.0,
            }
        )
        .to_dict()
    )
    assert result["score"] == 80
    assert result["severity"] == "high"
    assert result["factors"][0]["evidence_refs"] == ["host"]


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("nan"), "unknown"])
def test_invalid_confidence_is_rejected(confidence):
    with pytest.raises(ValueError):
        RiskScorer().assess({"confidence": confidence})


def test_invalid_rule_weight_is_rejected_when_rule_matches():
    scorer = RiskScorer([Rule(name="invalid", weight=1.5, test=lambda finding: True)])
    with pytest.raises(ValueError, match="weight"):
        scorer.assess({"host": "example.test"})


def test_duplicate_rule_names_are_rejected():
    rule = Rule(name="same", weight=0.2, test=lambda finding: True)
    with pytest.raises(ValueError, match="unique"):
        RiskScorer([rule, rule])
