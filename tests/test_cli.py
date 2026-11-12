"""Tests for the command line interface.

The CLI is the only part of the system a user touches directly, so a broken
subcommand or a wrong exit code is immediately visible. Each command is driven
with the network and the long-running pieces replaced, so the tests cover the
argument contract, the output, and the return code rather than the scanning
itself.
"""

from __future__ import annotations

import argparse
import json

import pytest

import cli.main as cli
from core.state import StateStore


@pytest.fixture()
def data_dir(tmp_path):
    return str(tmp_path / "campaigns-data")


@pytest.fixture(autouse=True)
def _permissive_scope(monkeypatch):
    """These tests cover the CLI contract, not authorization.

    The real default scope file is an allowlist for example.test/lab.test, so
    commands would legitimately refuse 10.0.0.x. Stub the loader with an
    explicit lab range and leave scope enforcement to tests/test_scope.py.
    """
    from core.scope import ScopeEnforcer

    monkeypatch.setattr(
        cli,
        "_load_scope",
        lambda _path=None: ScopeEnforcer(
            allowed_cidrs=["10.0.0.0/8"],
            allowed_domains=["app.test"],
            ports=[22, 80, 443],
        ),
    )


def _stub_orchestrator(monkeypatch, registry: dict | None = None):
    """Replaces the real registry so no test reaches the network."""
    from core.orchestrator import Orchestrator

    def fake_build(path: str, scope=None) -> Orchestrator:
        reg = (
            registry
            if registry is not None
            else {
                name: (lambda step, ctx, n=name: {"module": n, "step": step.step_id})
                for name in ("discovery", "recon", "stealth", "collector")
            }
        )
        return Orchestrator(StateStore(path), reg=reg, max_workers=2, scope=scope)

    monkeypatch.setattr(cli, "_build_orchestrator", fake_build)
    return fake_build


def _args(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(data=str(kwargs.pop("data", "unused")), **kwargs)


# --------------------------------------------------------------------------- #
# parser contract
# --------------------------------------------------------------------------- #


def test_every_documented_subcommand_is_registered():
    parser = cli.build_parser()
    actions = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    assert actions, "the parser must define subcommands"
    names = set(actions[0].choices)
    assert {
        "recon",
        "judge",
        "probe",
        "assets",
        "recover",
        "info",
        "status",
        "daemon",
        "sim",
        "version",
        "doctor",
        "init",
    } <= names


def test_recon_and_daemon_require_a_target():
    parser = cli.build_parser()
    for command in ("recon", "daemon"):
        with pytest.raises(SystemExit):
            parser.parse_args([command])
        assert parser.parse_args([command, "--target", "10.0.0.1"]).target == "10.0.0.1"


def test_recover_requires_a_campaign_id():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["recover"])
    assert parser.parse_args(["recover", "abc123"]).campaign_id == "abc123"


def test_data_directory_is_overridable_and_has_a_default():
    parser = cli.build_parser()
    assert parser.parse_args(["info"]).data == str(cli.DEFAULT_DATA)
    assert parser.parse_args(["--data", "/tmp/x", "info"]).data == "/tmp/x"


def test_daemon_interval_is_a_positive_number():
    parser = cli.build_parser()
    args = parser.parse_args(["daemon", "--target", "t", "--interval", "30"])
    assert args.interval == 30.0 or args.interval == 30


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def test_recon_runs_a_campaign_and_reports_zero(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    code = cli.cmd_recon(_args(target="10.0.0.1", data=data_dir))

    out = capsys.readouterr().out
    assert code == 0
    assert "[HELIOS] campaign" in out
    assert "-> done" in out
    assert "findings collected:" in out


def test_recon_writes_a_recoverable_campaign(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    cli.cmd_recon(_args(target="10.0.0.1", data=data_dir))

    states = StateStore(data_dir).load_all()
    assert len(states) == 1
    assert states[0].target == "10.0.0.1"
    assert states[0].status == "done"


def test_recover_reports_a_missing_campaign_and_fails(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    code = cli.cmd_recover(_args(campaign_id="nope", data=data_dir))

    assert code == 1, "a missing campaign is an error the caller can branch on"
    assert "nope" in capsys.readouterr().out


def test_recover_round_trips_a_campaign(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    cli.cmd_recon(_args(target="10.0.0.9", data=data_dir))
    campaign_id = StateStore(data_dir).load_all()[0].campaign_id

    assert cli.cmd_recover(_args(campaign_id=campaign_id, data=data_dir)) == 0
    out = capsys.readouterr().out
    assert "recovered" in out
    assert "10.0.0.9" in out


def test_status_with_no_campaigns_is_not_an_error(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    assert cli.cmd_status(_args(data=data_dir)) == 0
    assert "no campaigns recorded" in capsys.readouterr().out


def test_status_lists_campaigns_newest_first(capsys, monkeypatch, data_dir):
    _stub_orchestrator(monkeypatch)
    cli.cmd_recon(_args(target="10.0.0.1", data=data_dir))
    cli.cmd_recon(_args(target="10.0.0.2", data=data_dir))

    assert cli.cmd_status(_args(data=data_dir)) == 0
    out = capsys.readouterr().out
    assert "10.0.0.1" in out and "10.0.0.2" in out
    assert "done" in out
    positions = [out.index("10.0.0.1"), out.index("10.0.0.2")]
    assert positions[0] < positions[1], "the most recent campaign must be listed first"


def test_info_prints_a_parseable_inventory(capsys):
    assert cli.cmd_info(_args()) == 0
    payload = json.loads(capsys.readouterr().out)

    for key in ("algorithms", "modules", "rule_plugins", "core_rules"):
        assert key in payload, f"{key} missing from the info output"
    assert isinstance(payload["modules"], list)
    assert all({"name", "kind"} <= set(m) for m in payload["modules"])
    assert payload["algorithms"], "the algorithm registry should not be empty"


def test_judge_classifies_findings(capsys, monkeypatch):
    def fake_discovery(step, ctx):
        finding = {
            "module": "discovery",
            "host": step.target,
            "port": 22,
            "service": "ssh",
            "open": True,
            "banner": "SSH-2.0-OpenSSH_9.6",
        }
        ctx.setdefault("findings", []).append(finding)
        return {
            "module": "discovery",
            "host": step.target,
            "open_ports": [22],
            "count": 1,
            "engine": "go-native",
            "reason": "ok",
        }

    monkeypatch.setattr(cli, "discovery_runner", fake_discovery)

    assert cli.cmd_judge(_args(target="10.0.0.1")) == 0
    out = capsys.readouterr().out
    assert "10.0.0.1:22" in out
    assert "ssh" in out
    assert "severity=" in out
    assert "engine=go-native" in out


def test_assets_command_prints_hosts_assets_and_blocked_entries(capsys, monkeypatch):
    import modules.registry as registry

    def fake_runner(step, ctx):
        ctx.setdefault("findings", []).append(
            {
                "host": "app.test",
                "ip": "127.0.0.1",
                "port": 80,
                "status": 200,
                "title": "App",
                "vhost": True,
            }
        )
        return {
            "module": "asset",
            "host": step.target,
            "hosts": ["app.test"],
            "assets": 1,
            "requests": 2,
            "blocked": [{"host": "x.test", "reason": "name-outside-scope"}],
        }

    monkeypatch.setattr(registry, "asset_runner", fake_runner)

    code = cli.cmd_assets(
        _args(
            target="app.test",
            ct=False,
            depth=1,
            max_hosts=5,
            max_requests=10,
            web_ports=None,
        )
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "app.test -> 127.0.0.1:80 [200] App vhost" in out
    assert "blocked x.test: name-outside-scope" in out
    assert "assets=1" in out


def test_assets_command_refuses_web_ports_outside_the_scope(capsys):
    code = cli.cmd_assets(
        _args(
            target="10.0.0.1",
            ct=False,
            depth=1,
            max_hosts=5,
            max_requests=10,
            web_ports="3306",
        )
    )

    assert code == 2
    assert "outside the authorized scope" in capsys.readouterr().out


def test_assets_defaults_are_bounded():
    args = cli.build_parser().parse_args(["assets", "--target", "app.test"])

    assert args.ct is False
    assert args.depth == 1
    assert args.max_hosts == 50
    assert args.max_requests == 200
    assert args.web_ports is None


def test_daemon_starts_and_stops_cleanly(capsys, monkeypatch, data_dir):

    started: list[str] = []

    class FakeDaemon:
        def __init__(self, target, state_dir, interval_seconds):
            started.append(target)

        async def start(self):
            return None

    monkeypatch.setattr("core.daemon.AutonomousDaemon", FakeDaemon)

    assert cli.cmd_daemon(_args(target="10.0.0.1", data=data_dir, interval=1)) == 0
    assert started == ["10.0.0.1"]
    assert "DEMIURG-DAEMON" in capsys.readouterr().out


def test_daemon_reports_a_keyboard_interrupt(capsys, monkeypatch, data_dir):
    class Interrupting:
        def __init__(self, target, state_dir, interval_seconds):
            pass

        async def start(self):
            raise KeyboardInterrupt

    monkeypatch.setattr("core.daemon.AutonomousDaemon", Interrupting)
    assert cli.cmd_daemon(_args(target="10.0.0.1", data=data_dir, interval=1)) == 0
    assert "deactivated" in capsys.readouterr().out


def test_sim_runs_the_simulation(monkeypatch):
    import run_simulation

    ran: list[bool] = []

    async def fake_simulation() -> None:
        ran.append(True)

    monkeypatch.setattr(run_simulation, "simulate_engagement", fake_simulation)
    assert cli.cmd_sim(_args()) == 0
    assert ran == [True]


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #


def test_main_dispatches_and_returns_an_int(monkeypatch, data_dir):
    seen: list[argparse.Namespace] = []

    def fake_recon(args: argparse.Namespace) -> int:
        seen.append(args)
        return 0

    real_build = cli.build_parser

    def patched_build() -> argparse.ArgumentParser:
        parser = real_build()
        subparsers = [
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        ][0]
        subparsers.choices["recon"].set_defaults(fn=fake_recon)
        return parser

    monkeypatch.setattr(cli, "build_parser", patched_build)
    # --data is a top-level option, so it precedes the subcommand.
    result = cli.main(["--data", data_dir, "recon", "--target", "10.0.0.5"])

    assert result == 0
    assert isinstance(result, int), "main must return an exit code, not a truthy value"
    assert seen[0].target == "10.0.0.5"
    assert seen[0].data == data_dir


def test_shared_path_options_work_before_and_after_subcommands():
    parser = cli.build_parser()
    before = parser.parse_args(["--data", "before", "--scope", "before.yml", "info"])
    after = parser.parse_args(["info", "--data", "after", "--scope", "after.yml"])
    assert before.data == "before" and before.scope == "before.yml"
    assert after.data == "after" and after.scope == "after.yml"


def test_port_parser_rejects_malformed_and_out_of_range_values():
    assert cli._parse_port_list("80,443,80") == [80, 443]
    for value in ("abc", "0", "65536", ",,"):
        with pytest.raises(ValueError):
            cli._parse_port_list(value)


def test_probe_invalid_ports_returns_usage_error(capsys):
    code = cli.cmd_probe(_args(target="10.0.0.1", ports="80,nope"))
    assert code == 2
    assert "invalid ports" in capsys.readouterr().out


def test_init_creates_data_and_scope_without_overwriting(tmp_path):
    data = tmp_path / "campaigns"
    scope = tmp_path / "custom" / "scope.yaml"
    args = _args(data=str(data), scope=str(scope))
    assert cli.cmd_init(args) == 0
    original = scope.read_text(encoding="utf-8")
    assert data.is_dir() and "127.0.0.0/24" in original
    assert cli.cmd_init(args) == 0
    assert scope.read_text(encoding="utf-8") == original


def test_doctor_is_read_only_and_reports_scope(capsys, tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(cli._SCOPE_TEMPLATE, encoding="utf-8")
    data = tmp_path / "not-created"
    code = cli.cmd_doctor(_args(data=str(data), scope=str(scope)))
    output = capsys.readouterr().out
    assert code in (0, 1)
    assert "[OK] Scope configuration" in output
    assert not data.exists()


def test_version_command_reports_runtime(capsys):
    assert cli.cmd_version(_args()) == 0
    output = capsys.readouterr().out
    assert "HELIOS-NET revision:" in output
    assert "Python runtime:" in output


def test_a_command_returning_a_nonzero_code_reaches_the_caller(monkeypatch):
    def failing(args: argparse.Namespace) -> int:
        return 3

    real_build = cli.build_parser

    def patched_build() -> argparse.ArgumentParser:
        parser = real_build()
        status = [
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        ][0].choices["status"]
        status.set_defaults(fn=failing)
        return parser

    monkeypatch.setattr(cli, "build_parser", patched_build)
    assert cli.main(["status"]) == 3


def test_assets_command_exports_the_typed_graph(tmp_path, capsys, monkeypatch):
    import json

    import modules.registry as registry
    from engine.graph.model import AssetType, Evidence, TypedAssetGraph

    graph = TypedAssetGraph()
    graph.add_asset(
        AssetType.HOST,
        "app.test",
        evidence=Evidence(
            source="test",
            observed_at="2026-11-10T20:00:00+00:00",
        ),
    )
    graph_payload = graph.to_dict()

    def fake_runner(step, ctx):
        return {
            "module": "asset",
            "host": step.target,
            "hosts": ["app.test"],
            "assets": 1,
            "requests": 1,
            "blocked": [],
            "graph": graph_payload,
        }

    monkeypatch.setattr(registry, "asset_runner", fake_runner)
    destination = tmp_path / "graphs" / "app.json"
    code = cli.cmd_assets(
        _args(
            target="app.test",
            ct=False,
            depth=1,
            max_hosts=5,
            max_requests=10,
            web_ports=None,
            graph_output=str(destination),
        )
    )

    assert code == 0
    assert json.loads(destination.read_text(encoding="utf-8")) == graph_payload
    assert "typed graph exported" in capsys.readouterr().out


def test_graph_parser_accepts_terminal_analysis_arguments():
    args = cli.build_parser().parse_args(
        [
            "graph",
            "analyze",
            "--input",
            "graph.json",
            "--backend",
            "python",
            "--source-asset",
            "host:abc",
            "--target-asset",
            "ip:def",
        ]
    )

    assert args.cmd == "graph"
    assert args.action == "analyze"
    assert args.backend == "python"
    assert args.source_asset == "host:abc"
    assert args.target_asset == "ip:def"
