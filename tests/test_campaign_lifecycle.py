"""Tests for the campaign lifecycle: planning, state, and orchestration.

The orchestrator is the "autonomous" claim in the README, and it was the least
covered of the three modules here. These tests concentrate on the properties
that make the claim meaningful rather than on line coverage:

* a step never runs before the steps it depends on;
* one module raising does not take the campaign down;
* what the state file claims must survive a round trip through disk.

The last one matters because recovery reads from disk. A state object that is
correct in memory but lossy on save would pass every in-process test and still
lose a campaign on restart.
"""

from __future__ import annotations

import json
import threading

import pytest

from core.orchestrator import Orchestrator
from core.planner import Planner, PlanStep
from core.state import CampaignState, StateStore


# --------------------------------------------------------------------------- #
# Planner
# --------------------------------------------------------------------------- #

def test_discovery_is_always_planned_even_with_no_intelligence():
    steps = Planner().plan([], "10.0.0.1")
    assert [s.module for s in steps].count("discovery") >= 1
    assert steps[0].module == "discovery"
    assert steps[0].priority == Planner.MODULE_PRIORITY["discovery"]


def test_step_ids_are_unique_and_json_round_trips():
    planner = Planner()
    steps = planner.plan([{"module": "recon", "action": "fingerprint"}], "10.0.0.1")
    ids = [s.step_id for s in steps]
    assert len(ids) == len(set(ids))

    restored = planner.from_json(planner.to_json(steps))
    assert [s.to_dict() for s in restored] == [s.to_dict() for s in steps]
    assert restored[0].depends_on == steps[0].depends_on or not restored[0].depends_on


def test_recon_and_collect_depend_on_everything_before_them():
    steps = Planner().plan(
        [
            {"module": "discovery", "action": "scan"},
            {"module": "recon", "action": "fingerprint"},
            {"module": "exfil"},
        ],
        "10.0.0.1",
    )
    by_id = {s.step_id: s for s in steps}
    recon = next(s for s in steps if s.action == "fingerprint")
    collect = next(s for s in steps if s.action == "collect")

    discovery_ids = {s.step_id for s in steps if s.module == "discovery"}
    assert set(recon.depends_on) == discovery_ids, (
        "recon must depend on exactly the discovery work"
    )
    assert set(collect.depends_on) == {s.step_id for s in steps if s is not collect}
    # A dependency must never point forward at a step that runs later.
    for step in steps:
        for dependency in step.depends_on:
            assert by_id[dependency].priority <= step.priority
            assert by_id[dependency].step_id != step.step_id, "a step cannot depend on itself"


def test_steps_are_ordered_by_priority():
    steps = Planner().plan(
        [
            {"module": "recon"},
            {"module": "discovery"},
            {"module": "stealth"},
            {"module": "plugin_thing", "priority": 5},
        ],
        "10.0.0.1",
    )
    priorities = [s.priority for s in steps]
    assert priorities == sorted(priorities)


def test_schedule_never_places_a_step_before_its_dependencies():
    planner = Planner(max_concurrency=4)
    steps = planner.plan(
        [
            {"module": "discovery", "action": "scan"},
            {"module": "discovery", "action": "scan"},
            {"module": "recon", "action": "fingerprint"},
            {"module": "recon", "action": "banner"},
            {"module": "exfil"},
        ],
        "10.0.0.1",
    )
    waves = planner.schedule(steps)

    completed: set[int] = set()
    seen: set[int] = set()
    for wave in waves:
        for step in wave:
            assert all(d in completed for d in step.depends_on), (
                f"{step.module}/{step.action} ran before its dependencies"
            )
            assert step.step_id not in seen, f"step {step.step_id} scheduled twice"
            seen.add(step.step_id)
        completed |= {s.step_id for s in wave}

    assert seen == {s.step_id for s in steps}, "every step must be scheduled exactly once"


def test_schedule_respects_the_concurrency_cap():
    planner = Planner(max_concurrency=2)
    steps = [
        PlanStep(step_id=i, module="discovery", action="scan", target="t")
        for i in range(1, 8)
    ]
    waves = planner.schedule(steps)
    assert all(len(wave) <= 2 for wave in waves), [len(w) for w in waves]
    assert sorted(s.step_id for w in waves for s in w) == list(range(1, 8))


def test_schedule_breaks_a_dependency_cycle_instead_of_hanging():
    """A cycle must not deadlock the scheduler.

    The steps here are built by hand to be unsatisfiable: a depends on b and b
    depends on a. No valid ordering exists, so the only correct behaviour is to
    break the cycle and still terminate with every step scheduled.
    """
    steps = [
        PlanStep(step_id=1, module="discovery", action="scan", target="t", depends_on=[2]),
        PlanStep(step_id=2, module="recon", action="fingerprint", target="t", depends_on=[1]),
    ]
    planner = Planner(max_concurrency=4)

    waves = planner.schedule(steps)          # must not hang
    scheduled = sorted(s.step_id for wave in waves for s in wave)
    assert scheduled == [1, 2]


def test_schedule_handles_an_empty_plan():
    assert Planner().schedule([]) == []


# --------------------------------------------------------------------------- #
# CampaignState
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", ["", "   ", None])
def test_empty_target_is_rejected(bad):
    with pytest.raises(ValueError):
        CampaignState(target=bad)


def test_transition_rejects_an_unknown_status():
    state = CampaignState(target="10.0.0.1")
    with pytest.raises(ValueError):
        state.transition("not-a-status")
    assert state.status == "idle", "a rejected transition must not change state"


def test_transition_to_the_same_status_is_a_no_op():
    state = CampaignState(target="10.0.0.1")
    state.transition("planning")
    stamp = state.updated_at
    state.transition("planning")
    assert state.updated_at == stamp


@pytest.mark.parametrize("terminal", ["done", "failed", "aborted"])
def test_terminal_statuses_stamp_completion(terminal):
    state = CampaignState(target="10.0.0.1")
    assert state.completed_at is None
    state.transition(terminal)
    assert state.completed_at is not None
    assert state.completed_at == pytest.approx(state.updated_at)


def test_non_terminal_status_does_not_stamp_completion():
    state = CampaignState(target="10.0.0.1")
    state.transition("scanning")
    assert state.completed_at is None


def test_state_survives_a_disk_round_trip(tmp_path):
    store = StateStore(tmp_path)
    state = CampaignState(target="  10.0.0.1  ")
    state.transition("scanning")
    state.meta["findings_count"] = 3
    state.meta["nested"] = {"a": [1, 2, {"b": True}]}
    store.save(state)

    loaded = store.load(state.campaign_id)
    assert loaded.target == "10.0.0.1", "target must be stripped, not stored padded"
    assert loaded.status == "scanning"
    assert loaded.meta == state.meta, "nested meta must survive serialisation"
    assert loaded.campaign_id == state.campaign_id
    assert loaded.created_at == pytest.approx(state.created_at)


def test_load_of_an_unknown_campaign_raises(tmp_path):
    store = StateStore(tmp_path)
    with pytest.raises(FileNotFoundError):
        store.load("does-not-exist")


def test_save_leaves_no_temporary_file_behind(tmp_path):
    store = StateStore(tmp_path)
    state = CampaignState(target="10.0.0.1")
    store.save(state)
    leftovers = [p.name for p in (store.campaigns_dir).iterdir() if p.suffix == ".tmp"]
    assert leftovers == [], f"temporary files left behind: {leftovers}"


def test_event_log_round_trips_in_order(tmp_path):
    store = StateStore(tmp_path)
    state = CampaignState(target="10.0.0.1")
    for index in range(5):
        store.log_event(state, "tick", index=index)
    events = store.read_log(state.campaign_id)
    assert [e["event"] for e in events] == ["tick"] * 5
    assert [e["index"] for e in events] == list(range(5))
    assert all(e["campaign_id"] == state.campaign_id for e in events)


def test_read_log_of_an_unknown_campaign_is_empty_not_an_error(tmp_path):
    assert StateStore(tmp_path).read_log("nope") == []


def test_corrupt_state_files_are_skipped_not_fatal(tmp_path):
    store = StateStore(tmp_path)
    good = CampaignState(target="10.0.0.1")
    store.save(good)
    (store.campaigns_dir / "broken.json").write_text("{not json", encoding="utf-8")
    (store.campaigns_dir / "wrongshape.json").write_text('{"nope": 1}', encoding="utf-8")

    loaded = store.load_all()
    assert [s.campaign_id for s in loaded] == [good.campaign_id]


def test_delete_removes_state_and_log(tmp_path):
    store = StateStore(tmp_path)
    state = CampaignState(target="10.0.0.1")
    store.save(state)
    store.log_event(state, "hello")

    store.delete(state.campaign_id)
    with pytest.raises(FileNotFoundError):
        store.load(state.campaign_id)
    assert store.read_log(state.campaign_id) == []


def test_concurrent_event_writers_do_not_interleave_lines(tmp_path):
    """The log is append-only JSONL, so a torn line would corrupt the timeline."""
    store = StateStore(tmp_path)
    state = CampaignState(target="10.0.0.1")
    store.save(state)

    def writer(tag: int) -> None:
        for i in range(40):
            store.log_event(state, "tick", tag=tag, i=i, filler="x" * 200)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    events = store.read_log(state.campaign_id)
    assert len(events) == 240, f"expected 240 intact records, got {len(events)}"
    assert {e["tag"] for e in events} == set(range(6))


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

def _ok_runner(name: str):
    def runner(step: PlanStep, ctx: dict) -> dict:
        ctx.setdefault("findings", []).append(
            {"module": name, "host": step.target, "port": 80, "service": "http"}
        )
        return {"module": name, "step": step.step_id}
    return runner


FULL_INTEL = [
    {"module": "discovery", "action": "scan"},
    {"module": "recon", "action": "fingerprint"},
    {"module": "stealth", "action": "pace"},
]


def test_campaign_runs_every_module_and_reaches_done(tmp_path):
    store = StateStore(tmp_path)
    orch = Orchestrator(store, max_workers=2)
    for name in ("discovery", "recon", "stealth", "exfil"):
        orch.register(name, _ok_runner(name))

    state = orch.run_campaign("10.0.0.1", FULL_INTEL)

    assert state.status == "done"
    assert state.completed_at is not None
    assert state.meta["plan"], "the plan hash must be recorded for auditing"
    assert state.meta["findings_count"] == 4
    assert state.meta["report_count"] == 4

    events = [e["event"] for e in store.read_log(state.campaign_id)]
    assert events[0] == "campaign_start"
    assert events[-1] == "campaign_done"
    assert "plan_built" in events
    assert "step_done" in events
    assert "step_failed" not in events


def test_recon_and_stealth_are_skipped_without_corresponding_intelligence(tmp_path):
    """Documented behaviour, pinned deliberately.

    The planner only emits a recon or stealth step when the intelligence
    actually contains an item for that module; only discovery is unconditional
    and exfil follows whatever steps exist. Without this, a caller that expects
    every registered module to run would silently get only two steps.
    """
    store = StateStore(tmp_path)
    orch = Orchestrator(store)
    for name in ("discovery", "recon", "stealth", "exfil"):
        orch.register(name, _ok_runner(name))

    state = orch.run_campaign("10.0.0.1")

    ran = {e["module"] for e in store.read_log(state.campaign_id)
           if e["event"] == "step_start"}
    assert ran == {"discovery", "exfil"}, ran
    assert state.meta["report_count"] == 2


def test_a_failing_module_is_isolated_and_does_not_sink_the_campaign(tmp_path):
    store = StateStore(tmp_path)
    orch = Orchestrator(store, max_workers=4)

    def explode(step: PlanStep, ctx: dict) -> dict:
        raise RuntimeError("module blew up")

    orch.register("discovery", _ok_runner("discovery"))
    orch.register("recon", explode)
    orch.register("stealth", _ok_runner("stealth"))
    orch.register("exfil", _ok_runner("exfil"))

    state = orch.run_campaign("10.0.0.1", FULL_INTEL)

    assert state.status == "done", "one bad module must not fail the campaign"
    events = store.read_log(state.campaign_id)
    failures = [e for e in events if e["event"] == "step_failed"]
    assert len(failures) == 1
    assert "module blew up" in failures[0]["error"]
    assert failures[0]["module"] == "recon"
    assert state.meta["report_count"] == 3, "the other three still reported"


def test_a_missing_module_is_logged_and_skipped(tmp_path):
    store = StateStore(tmp_path)
    orch = Orchestrator(store)
    orch.register("discovery", _ok_runner("discovery"))
    # recon is deliberately never registered.

    state = orch.run_campaign("10.0.0.1")
    assert state.status == "done"
    events = store.read_log(state.campaign_id)
    missing = [e for e in events if e["event"] == "module_missing"]
    assert missing, "an unregistered module must be recorded, not silently ignored"
    assert {e["module"] for e in missing} <= {"recon", "stealth", "exfil"}


def test_registering_a_non_callable_is_rejected(tmp_path):
    orch = Orchestrator(StateStore(tmp_path))
    with pytest.raises(TypeError):
        orch.register("bad", "not a function")     # type: ignore[arg-type]


def test_campaign_with_no_registered_modules_still_completes(tmp_path):
    state = Orchestrator(StateStore(tmp_path)).run_campaign("10.0.0.1")
    assert state.status == "done"
    assert state.meta["findings_count"] == 0


def test_an_aborted_state_stops_further_waves(tmp_path):
    """The abort check lives in _execute_waves, which nothing sets during a
    normal campaign, so it is driven directly here rather than pretended at.

    A ctx flag set by a runner would exercise nothing: the scheduler inspects
    state.status, not the shared context.
    """
    store = StateStore(tmp_path)
    orch = Orchestrator(store, max_workers=1)
    ran: list[str] = []

    def record(step: PlanStep, ctx: dict) -> dict:
        ran.append(step.action)
        return {"module": "discovery"}

    orch.register("discovery", record)

    planner = Planner(max_concurrency=1)
    steps = planner.plan(FULL_INTEL, "10.0.0.1")
    waves = planner.schedule(steps)
    assert len(waves) > 1, "this test needs a multi-wave plan to be meaningful"

    state = CampaignState(target="10.0.0.1")
    state.transition("aborted")
    orch._execute_waves(state, waves)
    assert ran == [], "no step may run once the campaign is aborted"


def test_graph_summary_is_recorded_from_findings(tmp_path):
    orch = Orchestrator(StateStore(tmp_path))
    for name in ("discovery", "recon", "stealth", "exfil"):
        orch.register(name, _ok_runner(name))

    state = orch.run_campaign("10.0.0.1")
    assert "graph_error" not in state.meta, state.meta.get("graph_error")
    assert state.meta["graph_nodes"] > 0
    assert "graph_edges" in state.meta
    assert isinstance(state.meta["top_targets"], list)


def test_report_reflects_the_stored_timeline(tmp_path):
    store = StateStore(tmp_path)
    orch = Orchestrator(store)
    orch.register("discovery", _ok_runner("discovery"))
    orch.register("recon", _ok_runner("recon"))
    orch.register("stealth", _ok_runner("stealth"))
    orch.register("exfil", _ok_runner("exfil"))

    state = orch.run_campaign("10.0.0.1", FULL_INTEL)
    report = orch.report(state)

    assert report["campaign_id"] == state.campaign_id
    assert report["target"] == "10.0.0.1"
    assert report["status"] == "done"
    assert report["summary"]["findings_count"] == 4
    assert report["summary"] == state.meta
    assert report["timeline"][0]["event"] == "campaign_start"
    assert all(isinstance(row, dict) for row in report["timeline"])
    json.dumps(report, default=str)      # must be serialisable for the HTML reporter


def test_recover_returns_the_state_that_was_persisted(tmp_path):
    store = StateStore(tmp_path)
    orch = Orchestrator(store)
    orch.register("discovery", _ok_runner("discovery"))
    orch.register("recon", _ok_runner("recon"))
    orch.register("stealth", _ok_runner("stealth"))
    orch.register("exfil", _ok_runner("exfil"))

    original = orch.run_campaign("10.0.0.1")
    fresh = Orchestrator(StateStore(tmp_path))
    recovered = fresh.recover(original.campaign_id)

    assert recovered.campaign_id == original.campaign_id
    assert recovered.target == original.target
    assert recovered.status == "done"
    assert recovered.meta == original.meta
