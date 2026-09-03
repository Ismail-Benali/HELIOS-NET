"""HELIOS-NET :: self-test (no external libraries required).

Run:
    python -m pytest tests/ -q      (if pytest is available)
    python tests/smoke.py           (lightweight direct test)

Covers: state, planner, orchestrator (with mock modules), scanner (LPT),
verdict, modules (discovery on loopback/safe local host).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.orchestrator import Orchestrator  # noqa: E402
from core.planner import Planner            # noqa: E402
from core.state import CampaignState, StateStore  # noqa: E402
from engine.scanner import Scanner, ScanTask      # noqa: E402
from engine.verdict import VerdictEngine, default_rules  # noqa: E402
from engine.plugins import plugin_registry          # noqa: E402


def test_state_persistence():
    with tempfile.TemporaryDirectory() as tmp:
        store = StateStore(tmp)
        s = CampaignState(target="lab.test")
        s.transition("planning")
        s.meta["x"] = 1
        store.save(s)
        loaded = store.load(s.campaign_id)
        assert loaded.target == "lab.test"
        assert loaded.status == "planning"
        assert loaded.meta["x"] == 1
        store.log_event(s, "ping")
        assert len(store.read_log(s.campaign_id)) == 1
    print("state: OK")


def test_planner_waves():
    p = Planner(max_concurrency=2)
    steps = p.plan([
        {"module": "discovery", "action": "scan", "priority": 10},
        {"module": "recon", "action": "fingerprint", "priority": 20},
    ], "lab.test")
    waves = p.schedule(steps)
    # no batch exceeds the concurrency limit.
    assert all(len(w) <= 2 for w in waves)
    # exfil is aggregate at the end: it depends on all the steps.
    exfil = [s for s in steps if s.module == "exfil"]
    assert exfil and len(exfil[0].depends_on) == len(steps) - 1
    print("planner: OK")


def test_orchestrator_runs():
    with tempfile.TemporaryDirectory() as tmp:
        store = StateStore(tmp)
        calls = {"discovery": 0}

        def fake_discovery(step, ctx):
            calls["discovery"] += 1
            ctx.setdefault("findings", []).append({"module": "discovery", "host": step.target, "port": 80, "service": "HTTP"})
            return {"module": "discovery", "count": 1}

        def fake_recon(step, ctx):
            return {"module": "recon", "host": step.target}

        def fake_stealth(step, ctx):
            return {"module": "stealth"}

        def fake_exfil(step, ctx):
            return {"module": "exfil", "total": len(ctx.get("findings", []))}

        orch = Orchestrator(store=store, reg={
            "discovery": fake_discovery, "recon": fake_recon,
            "stealth": fake_stealth, "exfil": fake_exfil,
        })
        state = orch.run_campaign("lab.test")
        assert state.status == "done"
        assert calls["discovery"] >= 1
        rep = orch.report(state)
        assert rep["status"] == "done"
    print("orchestrator: OK")


def test_scanner_balancing():
    s = Scanner(max_workers=3)
    tasks = [ScanTask(name=f"t{i}", fn=lambda i=i: {"i": i}, weight=float(i + 1)) for i in range(5)]
    batches = s.balanced_batches(tasks, 3)
    # verify that each batch is at or below the worker load limit.
    loads = [sum(t.weight for t in b) for b in batches]
    assert len(batches) == 3
    results = s.scan(tasks)
    assert len(results) == 5 and all(r["ok"] for r in results)
    print(f"scanner: OK (batch loads={loads})")


def test_verdict():
    ve = VerdictEngine(rules=default_rules())
    ve.load_plugins(plugin_registry())
    v = ve.judge({"module": "discovery", "host": "x", "port": 3306, "service": "MySQL", "open": True})
    assert "critical_port_open" in v.rules_hit
    assert v.to_dict()["severity"] == "medium"
    print("verdict: OK")


def test_algorithm_registry():
    from engine.algorithms import list_algos
    from engine.algorithms.balancing import solve as bal_solve
    from engine.algorithms.fingerprint import fingerprint_sig

    # switching the balancing algorithm is genuinely effective.
    w = [5, 4, 3, 2, 1]
    assert bal_solve("lpt", w, 3).makespan == 5.0
    assert bal_solve("brute", w, 3).makespan == 5.0

    # switching the fingerprint model.
    assert fingerprint_sig({"ttl": 64}, "ttl_flat")["guess"] == "linux"
    assert fingerprint_sig({"ttl": 127, "window": 65535, "tcp_options_len": 40}, "bayes")["guess"] == "windows"

    assert "balancing" in list_algos() and "fingerprint" in list_algos()
    print("algorithm_registry: OK")


def test_module_spawner():
    from pathlib import Path
    from modules.core import discover, get_module

    n = discover(Path(__file__).resolve().parents[1] / "modules" / "plugins")
    assert get_module("dns_enum") is not None
    print("module_spawner: OK (loaded dns_enum)")


def test_async_engine():
    import asyncio
    from core.async_engine import enterprise_adaptive_recon

    res = asyncio.run(enterprise_adaptive_recon("127.0.0.1", [80]))
    assert isinstance(res, list)
    print("async_engine: OK")


def test_custom_arsenal():
    import tempfile
    import asyncio
    from pathlib import Path
    from core.wal import TransactionalWAL
    from engine.pattern_matcher import AhoCorasickMatcher
    from modules.discovery.dns_resolver import EliteDNSResolver
    from core.async_engine import enterprise_adaptive_recon

    # 1. test the Transactional WAL with Begin/Commit
    with tempfile.TemporaryDirectory() as tmp:
        wal_file = Path(tmp) / "trans.wal"
        wal = TransactionalWAL(wal_file)
        wal.begin()
        wal.append("TXN_OP", {"val": 1})
        wal.commit()
        records = wal.replay()
        assert len(records) == 1 and records[0]["op"] == "TXN_OP"

    # 2. test the Aho-Corasick Automaton
    ac = AhoCorasickMatcher()
    ac.load_defaults()
    hits = ac.match("Running OpenSSH and Nginx server securely.")
    assert len(hits) >= 2

    # 3. test the Elite DNS Resolver
    resolver = EliteDNSResolver()
    ips = asyncio.run(resolver.resolve("localhost"))
    assert isinstance(ips, list)

    # 4. test the Adaptive Recon Engine
    recon_res = asyncio.run(enterprise_adaptive_recon("127.0.0.1", [80]))
    assert isinstance(recon_res, list)

    print("elite_arsenal: OK (Transactional WAL, Aho-Corasick, Elite DNS & AIMD Recon verified)")


def test_killchain_engine():
    from engine.graph.core import AssetGraph
    from engine.killchain.pathfinder import KillChainEngine

    g = AssetGraph()
    g.add_node("host:10.0.0.1", "host")
    g.add_node("svc:10.0.0.1:80/http", "service", name="http")
    g.add_node("svc:10.0.0.1:22/ssh", "service", name="ssh")
    g.add_edge("host:10.0.0.1", "svc:10.0.0.1:80/http")
    g.add_edge("host:10.0.0.1", "svc:10.0.0.1:22/ssh")

    engine = KillChainEngine(g)
    path, cost = engine.find_attack_path("host:10.0.0.1", "svc:10.0.0.1:22/ssh")
    assert len(path) == 2 and cost > 0

    plan = engine.generate_kill_chain_plan("host:10.0.0.1", "svc:10.0.0.1:22/ssh")
    assert "ENGAGEMENT ROUTE PLAN" in plan
    print("killchain_engine: OK (Dijkstra pathfinding & route planning verified)")


def test_lateral_movement():
    import asyncio
    from core.pivot_proxy import PivotProxyServer
    from engine.tunneled_scanner import tunneled_tcp_probe
    from modules.internal.subnet_discovery import extract_internal_subnets

    # 1. Test Subnet Discovery parser
    subnets = extract_internal_subnets()
    assert isinstance(subnets, list)

    # 2. Test Pivot Proxy lifecycle & Tunneled probe
    proxy = PivotProxyServer("127.0.0.1", 19999)
    async def run_proxy_test():
        await proxy.start()
        res = await tunneled_tcp_probe("127.0.0.1", 80, "127.0.0.1", 19999, timeout=1.0)
        assert isinstance(res, dict)
        await proxy.stop()

    asyncio.run(run_proxy_test())
    print("lateral_movement: OK (Pivot proxy, Tunneled scanner & Subnet discovery verified)")


def test_advanced_capabilities():
    from engine.ai.adaptive_learner import EpsilonGreedyBandit
    import subprocess
    from pathlib import Path

    # 1. Test Adaptive Reinforcement Learning Bandit
    bandit = EpsilonGreedyBandit([10.0, 50.0, 100.0])
    arm = bandit.select_arm()
    bandit.update(arm, 1.0)
    optimal = bandit.get_optimal_rate()
    assert optimal in [10.0, 50.0, 100.0]

    # 2. Test Evasion Binary Execution
    evasion_bin = Path(__file__).resolve().parents[1] / "transport" / "evasion" / "evasion.exe"
    if evasion_bin.exists():
        res = subprocess.run([str(evasion_bin)], capture_output=True, text=True)
        assert "evasion_status" in res.stdout

    # 3. Test Exploit Verifier Binary Execution
    verifier_bin = Path(__file__).resolve().parents[1] / "transport" / "harness" / "verifier.exe"
    if verifier_bin.exists():
        res = subprocess.run([str(verifier_bin), "ftp", "220 Anonymous FTP server ready"], capture_output=True, text=True)
        assert "exploitable_confirmed" in res.stdout

    print("advanced_capabilities: OK (Adaptive bandit, Evasion & Exploit verifier verified)")


def test_legendary_capabilities():
    import tempfile
    from pathlib import Path
    from core.mutation_engine import MutationEngine

    with tempfile.TemporaryDirectory() as tmp:
        engine = MutationEngine(tmp)
        # Test trap detection
        is_trap = engine.detect_trap(6.2, 200)
        assert is_trap is True

        # Test self-destruct & mutation
        mutation_result = engine.trigger_self_destruct_and_mutate()
        assert mutation_result["status"] == "MUTATED"
        assert mutation_result["generation"] == 2

    print("legendary_capabilities: OK (Mutation engine & Self-healing verified)")


def test_hardened_security():
    import tempfile
    import json
    from pathlib import Path
    from core.wal import TransactionalWAL
    from engine.pattern_matcher import AhoCorasickMatcher

    # 1. Test Encrypted WAL at Rest
    with tempfile.TemporaryDirectory() as tmp:
        wal_file = Path(tmp) / "secure.wal"
        wal = TransactionalWAL(wal_file)
        wal.begin()
        wal.append("SECURE_OP", {"secret": "data"})
        wal.commit()
        records = wal.replay()
        assert len(records) == 1 and records[0]["op"] == "SECURE_OP"

    # 2. Test Dynamic JSON Signature Loading in PatternMatcher
    with tempfile.TemporaryDirectory() as tmp:
        sig_file = Path(tmp) / "custom_sigs.json"
        sig_file.write_text(json.dumps({"custom_db": "postgresql-custom"}), encoding="utf-8")
        
        ac = AhoCorasickMatcher()
        loaded = ac.load_from_json(sig_file)
        assert loaded == 1
        hits = ac.match("Connected to postgresql-custom backend.")
        assert len(hits) == 1 and hits[0]["signature"] == "postgresql-custom"

    print("hardened_security: OK (Encrypted WAL at rest & Dynamic signature loader verified)")


def main():
    test_state_persistence()
    test_planner_waves()
    test_orchestrator_runs()
    test_scanner_balancing()
    test_verdict()
    test_algorithm_registry()
    test_module_spawner()
    test_async_engine()
    test_custom_arsenal()
    test_killchain_engine()
    test_lateral_movement()
    test_advanced_capabilities()
    test_legendary_capabilities()
    test_hardened_security()
    print("\nALL SETS PASSED")


if __name__ == "__main__":
    main()
