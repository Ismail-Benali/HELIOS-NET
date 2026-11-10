# Explainable Risk Scoring

The engine.risk.RiskScorer entry point evaluates existing Rule objects and
returns a deterministic RiskAssessment with matched factors, rule weights,
confidence, and references to recorded evidence.

## Contract

- Rule weights and finding confidence must be finite values in [0, 1].
- Missing confidence uses 0.75. This is an engineering default, not a
  statistically calibrated confidence estimate.
- Each matched rule contributes weight multiplied by confidence.
- Contributions use noisy-OR aggregation and produce an integer score from
  0 to 100. This is a prioritisation heuristic, not CVSS, exploit probability,
  or proof of compromise.
- Severity bands: low 0-39, medium 40-69, high 70-84, critical 85-100.
- Evidence references identify recorded finding fields; they do not imply
  independent validation.
- scoring_version is included so reports can preserve the scoring contract.

## Example

    from engine.risk import RiskScorer

    assessment = RiskScorer().assess({
        "module": "discovery",
        "host": "192.0.2.10",
        "port": 23,
        "service": "telnet",
        "open": True,
        "confidence": 1.0,
    })
    print(assessment.to_dict())

The legacy engine.verdict.VerdictEngine remains unchanged. Consumers can adopt
the richer scorer incrementally without changing existing verdict payloads.
