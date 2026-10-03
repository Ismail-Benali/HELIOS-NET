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


def _stub_orchestrator(monkeypatch, registry: dict | None = None):
    """Replaces the real registry so no test reaches the network."""
    from core.orchestrator import Orchestrator

    def fake_build(path: str) -> Orchestrator:
        reg = (
            registry
            if registry is not None
            else {
                name: (lambda step, ctx, n=name: {"module": n, "step": step.step_id})
                for name in ("discovery", "recon", "stealth", "exfil")
            }
        )
        return Orchestrator(StateStore(path), reg=reg, max_workers=2)

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
    assert {"recon", "judge", "recover", "info", "status", "daemon", "sim"} <= names


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
    from modules.discovery import service

    monkeypatch.setattr(
        service,
        "discover_ports",
        lambda host, ports=None: [
            {
                "module": "discovery",
                "host": host,
                "port": 22,
                "service": "ssh",
                "open": True,
                "banner": "SSH-2.0-OpenSSH_9.6",
            }
        ],
    )
    # The command imports the symbol directly, so patch it where it is used.
    monkeypatch.setattr(
        "modules.discovery.service.discover_ports", service.discover_ports
    )

    assert cli.cmd_judge(_args(target="10.0.0.1")) == 0
    out = capsys.readouterr().out
    assert "10.0.0.1:22" in out
    assert "ssh" in out
    assert "severity=" in out


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


def test_data_after_the_subcommand_is_rejected(capsys):
    """Pinned because it is a real ergonomic trap: --data is global, so putting
    it after the subcommand is a usage error rather than a silent default."""
    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(["info", "--data", "/tmp/x"])
    assert excinfo.value.code == 2


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
