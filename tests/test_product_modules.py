"""Tests for the pure-logic modules and the module registry.

Two things are being pinned here.

First, a regression: `stealth_runner` used to call `Pacer(base_dwell=...)` while
the constructor argument is `mean_dwell`, so it raised TypeError on every
execution. Nothing exercised it, so the module had never run. The test calls it
directly so that a repeated typo fails the suite rather than production.

Second, several small components whose behaviour is checkable against an
independent reference: the incremental average in the bandit is compared with
`statistics.fmean`, and the load balancer's result is compared with an
exhaustive search for the true optimum.
"""

from __future__ import annotations

import json
import statistics

import pytest

from core.drift import compute_surface_drift
from core.planner import PlanStep
from core.reporter import generate_executive_briefing
from core.state import CampaignState
from engine.ai.adaptive_learner import EpsilonGreedyBandit
from engine.algorithms import balancing
from modules.exfil.collector import Collector
from modules.registry import (
    default_registry,
    exfil_runner,
    recon_runner,
    stealth_runner,
)
from modules.stealth.pacer import Pacer

# --------------------------------------------------------------------------- #
# registry: the regression that mattered
# --------------------------------------------------------------------------- #


def _step(**params) -> PlanStep:
    return PlanStep(
        step_id=1, module="stealth", action="pace", target="10.0.0.1", params=params
    )


def test_stealth_runner_actually_runs():
    """Regression: this raised TypeError on every call before the fix.

    The step parameter is `base_dwell`; Pacer's argument is `mean_dwell`. The
    mismatch was invisible because nothing invoked the runner.
    """
    result = stealth_runner(_step(base_dwell=0.25, jitter=0.05), {"plan": [1, 2, 3]})

    assert result["module"] == "stealth"
    assert result["count"] == 3
    assert len(result["pace_samples"]) == 3


def test_stealth_runner_scales_its_cadence_with_the_requested_mean():
    """The pacer draws -mean*ln(u), whose *mean* is the requested dwell.

    Individual samples are not bounded below by the mean, so the property that
    matters is the expected value over many draws.
    """

    def average_dwell(mean_dwell: float) -> float:
        ctx = {"plan": list(range(4000))}
        stealth_runner(_step(base_dwell=mean_dwell, jitter=0.0), ctx)
        return statistics.fmean(ctx["pace"])

    assert average_dwell(0.05) == pytest.approx(0.05, rel=0.15)
    assert average_dwell(0.5) == pytest.approx(0.5, rel=0.15)
    assert average_dwell(0.5) > average_dwell(0.05)


def test_every_registered_runner_is_callable():
    for name, runner in default_registry().items():
        assert callable(runner), f"{name} is registered but is not callable"


def test_discovery_runner_collects_findings_and_confirms_with_the_native_probe(
    monkeypatch,
):
    # registry imports these names directly, so they must be replaced there.
    import modules.registry as registry

    monkeypatch.setattr(
        registry,
        "discover_ports",
        lambda host, ports=None, **kwargs: [
            {
                "module": "discovery",
                "host": host,
                "port": 22,
                "service": "ssh",
                "open": True,
            }
        ],
    )
    monkeypatch.setattr(
        registry,
        "native_connect_probe",
        lambda host, port, **kwargs: {
            "host": host,
            "port": port,
            "open": True,
            "probe": "connect",
        },
    )

    step = PlanStep(
        step_id=1,
        module="discovery",
        action="scan",
        target="10.0.0.1",
        params={"ports": [22, 80]},
    )
    ctx: dict = {}
    result = registry.discovery_runner(step, ctx)

    assert result["open_ports"] == [22]
    assert result["count"] == 1
    assert result["native"]["port"] == 22
    assert any(
        f.get("port") == 22 and f.get("probe") == "connect" for f in ctx["findings"]
    ), "the confirmed finding must be recorded"


def test_discovery_runner_skips_the_native_probe_without_ports(monkeypatch):
    import modules.registry as registry

    monkeypatch.setattr(
        registry, "discover_ports", lambda host, ports=None, **kwargs: []
    )
    called: list[tuple] = []
    monkeypatch.setattr(
        registry,
        "native_connect_probe",
        lambda host, port, **kwargs: called.append((host, port)),
    )

    step = PlanStep(
        step_id=1, module="discovery", action="scan", target="10.0.0.1", params={}
    )
    result = registry.discovery_runner(step, {})

    assert called == [], "the probe has no port to confirm without one"
    assert result["native"] is None


def test_a_closed_port_is_not_recorded_as_a_finding(monkeypatch):
    import modules.registry as registry

    monkeypatch.setattr(
        registry,
        "discover_ports",
        lambda host, ports=None, **kwargs: [
            {
                "module": "discovery",
                "host": host,
                "port": 22,
                "service": "ssh",
                "open": True,
            }
        ],
    )
    monkeypatch.setattr(
        registry,
        "native_connect_probe",
        lambda host, port, **kwargs: {"host": host, "port": port, "open": False},
    )

    ctx: dict = {}
    result = registry.discovery_runner(
        PlanStep(
            step_id=1,
            module="discovery",
            action="scan",
            target="10.0.0.1",
            params={"ports": [22]},
        ),
        ctx,
    )

    assert result["native"]["open"] is False
    assert all(f.get("probe") != "connect" for f in ctx["findings"]), (
        "a refused connection is not a finding"
    )


def test_recon_runner_records_which_estimator_answered(tmp_path, monkeypatch):
    import modules.registry as registry

    monkeypatch.setattr(
        registry,
        "fingerprint_host",
        lambda host: {"host": host, "source": "http-banners"},
    )

    ctx: dict = {}
    result = recon_runner(
        PlanStep(step_id=1, module="recon", action="fingerprint", target="10.0.0.1"),
        ctx,
    )

    assert result["source"] == "http-banners"
    assert ctx["fingerprint_source"] == "http-banners", (
        "the estimator identity must be recorded, not guessed from a literal"
    )
    assert ctx["findings"] == [result]


def test_exfil_runner_collects_what_discovery_found(tmp_path):
    ctx = {
        "findings": [
            {"module": "discovery", "host": "10.0.0.1", "port": 22, "service": "ssh"},
            {"module": "discovery", "host": "10.0.0.1", "port": 22, "service": "ssh"},
            {"module": "discovery", "host": "10.0.0.1", "port": 80, "service": "http"},
        ]
    }
    result = exfil_runner(
        PlanStep(step_id=1, module="exfil", action="collect", target="10.0.0.1"), ctx
    )

    assert result["total"] == 3
    assert result["collected"] == 2, "the duplicate must be counted out"
    assert ctx["collected"] == 2


# --------------------------------------------------------------------------- #
# Pacer
# --------------------------------------------------------------------------- #


def test_pacer_dwell_is_positive_and_bounded_by_its_mean():
    pacer = Pacer(mean_dwell=0.5, jitter=0.0)
    for _ in range(50):
        assert pacer.dwell("exponential") > 0
        assert pacer.dwell("uniform") == pytest.approx(0.5, abs=1e-9)


def test_pacer_schedule_returns_one_dwell_per_step():
    pacer = Pacer(mean_dwell=0.1, jitter=0.0)
    assert len(pacer.schedule(0)) == 0
    assert len(pacer.schedule(7)) == 7


def test_pacer_clamps_nonsensical_settings():
    assert Pacer(mean_dwell=0.0).mean_dwell == 0.01, "a zero wait would busy-loop"
    assert Pacer(mean_dwell=-5).mean_dwell == 0.01
    assert Pacer(jitter=-1).jitter == 0.0


# --------------------------------------------------------------------------- #
# Collector
# --------------------------------------------------------------------------- #


def test_collector_deduplicates_by_natural_id():
    col = Collector(campaign_id="c1")
    first = {"module": "discovery", "host": "h", "port": 22, "service": "ssh"}
    assert col.add(first) is True
    assert col.add(dict(first)) is False, (
        "an identical finding must not be stored twice"
    )
    assert len(col.all()) == 1


def test_different_services_on_one_port_are_kept_apart():
    col = Collector(campaign_id="c1")
    base = {"module": "discovery", "host": "h", "port": 22}
    assert col.add({**base, "service": "ssh"}) is True
    assert col.add({**base, "service": "mysql"}) is True
    assert len(col.all()) == 2


def test_collector_stamps_time_and_campaign_when_absent():
    col = Collector(campaign_id="c1")
    col.add({"module": "discovery", "host": "h", "port": 1})
    record = col.all()[0]
    assert record["campaign_id"] == "c1"
    assert isinstance(record["ts"], float)


def test_collector_does_not_mutate_the_caller_dict():
    col = Collector(campaign_id="c1")
    original = {"module": "discovery", "host": "h", "port": 1}
    col.add(original)
    assert "ts" not in original, "add() must copy rather than decorate in place"


def test_collector_extend_reports_how_many_were_new():
    col = Collector(campaign_id="c1")
    rows = [
        {"module": "discovery", "host": "h", "port": p, "service": "http"}
        for p in (80, 443, 8080)
    ]
    assert col.extend(rows) == 3
    assert col.extend(rows) == 0
    assert len(col.all()) == 3


def test_collector_serialises_and_writes(tmp_path):
    col = Collector(campaign_id="c1")
    col.add({"module": "discovery", "host": "h", "port": 1, "service": "http"})
    assert len(json.loads(col.to_json())) == 1

    target = tmp_path / "out.json"
    col.write(str(target))
    assert len(json.loads(target.read_text(encoding="utf-8"))) == 1


# --------------------------------------------------------------------------- #
# drift
# --------------------------------------------------------------------------- #


def _finding(host: str, port: int) -> dict:
    return {"host": host, "port": port, "module": "discovery"}


def test_drift_classifies_new_removed_and_stable_assets():
    previous = [_finding("h1", 22), _finding("h1", 80), _finding("h2", 443)]
    current = [_finding("h1", 22), _finding("h3", 8080)]

    report = compute_surface_drift(previous, current)

    assert {(a["host"], a["port"]) for a in report["stable_assets"]} == {("h1", 22)}
    assert {(a["host"], a["port"]) for a in report["new_assets"]} == {("h3", 8080)}
    assert {(a["host"], a["port"]) for a in report["removed_assets"]} == {
        ("h1", 80),
        ("h2", 443),
    }
    assert report["drift_detected"] is True


def test_no_drift_when_the_surface_is_unchanged():
    rows = [_finding("h1", 22), _finding("h1", 80)]
    report = compute_surface_drift(rows, list(reversed(rows)))
    assert report["drift_detected"] is False
    assert report["new_assets"] == [] and report["removed_assets"] == []


def test_duplicate_findings_do_not_change_the_verdict():
    previous = [_finding("h1", 22)] * 5
    report = compute_surface_drift(previous, [_finding("h1", 22)] * 9)
    assert report["drift_detected"] is False
    assert len(report["stable_assets"]) == 1, "the comparison is over sets, not counts"


def test_drift_from_an_empty_baseline_is_all_new():
    report = compute_surface_drift([], [_finding("h1", 22)])
    assert report["drift_detected"] is True
    assert len(report["new_assets"]) == 1


# --------------------------------------------------------------------------- #
# executive briefing
# --------------------------------------------------------------------------- #


def test_briefing_reports_the_state_it_was_given():
    state = CampaignState(target="10.0.0.1")
    state.transition("done")
    state.meta.update(
        {
            "findings_count": 7,
            "graph_nodes": 3,
            "graph_edges": 2,
            "top_targets": ["a", "b"],
        }
    )

    text = generate_executive_briefing(
        state,
        {
            "timeline": [
                {"ts": 1.0, "event": "campaign_start", "module": "core"},
            ]
        },
    )

    assert state.campaign_id in text
    assert "10.0.0.1" in text
    assert "DONE" in text
    assert "7" in text
    assert "`a`" in text and "`b`" in text
    assert "campaign_start" in text


def test_briefing_says_so_when_there_are_no_priority_targets():
    state = CampaignState(target="10.0.0.1")
    text = generate_executive_briefing(state, {"timeline": []})
    assert "No high-centrality assets" in text


def test_briefing_shows_only_the_last_ten_events():
    state = CampaignState(target="h")
    timeline = [
        {"ts": float(i), "event": f"event{i}", "module": "m"} for i in range(25)
    ]
    text = generate_executive_briefing(state, {"timeline": timeline})
    assert "event24" in text
    assert "event14" not in text, "older events must be dropped from the briefing"
    assert text.count("- `[") == 10


# --------------------------------------------------------------------------- #
# adaptive learner
# --------------------------------------------------------------------------- #


def test_bandit_average_matches_the_arithmetic_mean():
    """The incremental update must equal the mean computed from scratch."""
    bandit = EpsilonGreedyBandit([1.0, 2.0, 3.0])
    rewards = {0: [], 1: [], 2: []}
    for arm, reward in [(0, 1.0), (0, 0.0), (1, 5.0), (2, 2.0), (2, 4.0), (1, 1.0)]:
        bandit.update(arm, reward)
        rewards[arm].append(reward)

    for arm, seen in rewards.items():
        assert bandit.values[arm] == pytest.approx(statistics.fmean(seen))


def test_bandit_reports_the_arm_with_the_highest_learned_rate():
    bandit = EpsilonGreedyBandit([10.0, 50.0, 25.0], epsilon=0.0)
    for _ in range(10):
        bandit.update(1, 1.0)  # arm 1 is the only one tried
    assert bandit.get_optimal_rate() == 50.0
    assert bandit.select_arm() == 1, "with epsilon 0 the best arm is always chosen"


def test_bandit_with_zero_epsilon_never_explores():
    bandit = EpsilonGreedyBandit([1.0, 2.0], epsilon=0.0)
    for _ in range(50):
        bandit.update(0, 1.0)
    assert {bandit.select_arm() for _ in range(50)} == {0}


def test_bandit_with_full_epsilon_only_explores():
    bandit = EpsilonGreedyBandit([1.0, 2.0, 3.0], epsilon=1.0)
    bandit.update(0, 99.0)  # arm 0 is far and away the best
    chosen = {bandit.select_arm() for _ in range(200)}
    assert len(chosen) > 1, "epsilon 1 must keep exploring"


def test_bandit_counts_every_update():
    bandit = EpsilonGreedyBandit([1.0, 2.0])
    for _ in range(3):
        bandit.update(1, 1.0)
    assert bandit.counts == [0, 3]
    assert bandit.values[0] == 0.0


# --------------------------------------------------------------------------- #
# load balancing, against the true optimum
# --------------------------------------------------------------------------- #


def _optimal_makespan(weights: list[float], workers: int) -> float:
    """Exhaustive search: the best achievable makespan over all assignments."""
    best = float("inf")
    for combination in _assignments(weights, workers):
        loads = [0.0] * workers
        for index, slot in enumerate(combination):
            loads[slot] += weights[index]
        best = min(best, max(loads) if loads else 0.0)
    return best


def _assignments(weights: list[float], workers: int):
    if not weights:
        yield tuple()
        return
    for rest in _assignments(weights[1:], workers):
        for slot in range(workers):
            yield (slot,) + rest


@pytest.mark.parametrize("kind", ["lpt", "brute"])
def test_balancer_never_beats_or_misses_the_optimum_by_much(kind):
    """Whatever the algorithm, the makespan must equal the true optimum.

    Small inputs are solved exhaustively here, so this pins the result rather
    than the algorithm: a heuristic that quietly lost optimality would fail.
    """
    cases = [
        ([1.0], 1),
        ([1.0, 1.0], 2),
        ([3.0, 1.0, 1.0], 2),
        ([4.0, 3.0, 2.0, 1.0], 2),
        ([5.0, 5.0, 5.0, 5.0, 5.0], 3),
        ([1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 4),
    ]
    for weights, workers in cases:
        result = balancing.solve(kind=kind, weights=list(weights), workers=workers)
        optimum = _optimal_makespan(weights, workers)
        assert result.makespan == pytest.approx(optimum), (
            f"{kind} on {weights} into {workers}: "
            f"got {result.makespan}, optimum {optimum}"
        )


@pytest.mark.parametrize("kind", ["lpt", "brute"])
def test_every_task_is_assigned_exactly_once(kind):
    weights = [4.0, 3.0, 2.0, 1.0, 6.0]
    result = balancing.solve(kind=kind, weights=list(weights), workers=3)
    flat = [task for bucket in result.buckets for task in bucket]
    assert sorted(flat) == list(range(len(weights)))


@pytest.mark.parametrize("kind", ["lpt", "brute"])
def test_no_bucket_exceeds_the_reported_makespan(kind):
    weights = [4.0, 3.0, 2.0, 1.0, 6.0]
    result = balancing.solve(kind=kind, weights=list(weights), workers=3)
    for bucket in result.buckets:
        assert sum(weights[i] for i in bucket) <= result.makespan + 1e-9


def test_balancing_with_no_work_is_a_valid_empty_result():
    result = balancing.solve(kind="lpt", weights=[], workers=3)
    assert result.makespan == 0.0
    assert result.buckets == [[], [], []]


def test_an_unknown_kind_falls_back_instead_of_raising():
    result = balancing.solve(kind="does-not-exist", weights=[1.0, 2.0], workers=2)
    assert result.makespan == pytest.approx(2.0)
