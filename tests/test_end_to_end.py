"""End-to-end tests against a real local socket.

Every other suite stubs either the network or a core. These two tests do
neither: a threaded TCP server speaks a real banner, and the campaign runs
through the CLI, the scope enforcer, the orchestrator, the registry, and
whichever native accelerator is available. They are deliberately narrow - one
authorized target and one refusal - because the point is to prove the pieces
are wired together, not to re-test each piece.
"""

from __future__ import annotations

import json
import socket
import threading

import pytest

import cli.main as cli
from core.orchestrator import Orchestrator
from core.scope import ScopeEnforcer, ScopeError
from core.state import StateStore
from modules.registry import default_registry

BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"


class _BannerServer:
    """Accepts connections, writes one banner, and counts the connections."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            self.connections += 1
            try:
                conn.sendall(BANNER)
                conn.settimeout(0.2)
                try:
                    conn.recv(256)
                except OSError:
                    pass
            finally:
                conn.close()

    def __enter__(self) -> _BannerServer:
        self.thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def _write_scope(path, port: int) -> str:
    path.write_text(
        json.dumps({"scope": {"cidrs": ["127.0.0.1/32"], "ports": [port]}}),
        encoding="utf-8",
    )
    return str(path)


def test_cli_campaign_end_to_end_against_a_local_service(tmp_path, capsys):
    with _BannerServer() as server:
        scope_file = _write_scope(tmp_path / "scope.json", server.port)
        data_dir = str(tmp_path / "campaigns")

        code = cli.main(
            [
                "--scope",
                scope_file,
                "--data",
                data_dir,
                "recon",
                "--target",
                "127.0.0.1",
            ]
        )

        out = capsys.readouterr().out
        assert code == 0, out
        assert "-> done" in out
        assert server.connections >= 1, "the campaign never reached the service"

        states = StateStore(data_dir).load_all()
        assert len(states) == 1
        assert states[0].status == "done"
        assert states[0].meta["findings_count"] >= 1

        events = [
            e["event"] for e in StateStore(data_dir).read_log(states[0].campaign_id)
        ]
        assert "step_done" in events
        assert "step_failed" not in events


def test_the_registry_identifies_the_local_banner_through_the_real_cores(tmp_path):
    with _BannerServer() as server:
        scope = ScopeEnforcer(allowed_cidrs=["127.0.0.1/32"], ports=[server.port])
        orch = Orchestrator(
            StateStore(tmp_path / "campaigns"),
            reg=default_registry(),
            scope=scope,
            max_workers=1,
        )

        state = orch.run_campaign(
            "127.0.0.1",
            [{"module": "discovery"}, {"module": "recon"}],
        )

        assert state.status == "done"
        recon = next(f for f in orch._context["findings"] if f.get("module") == "recon")
        assert recon["probes"], "recon collected no probe"
        assert recon["signature_matches"] >= 1
        names = {
            match["signature"]
            for probe in recon["probes"]
            for match in probe["matches"]
        }
        assert "openssh" in names, names


def test_an_out_of_scope_target_never_reaches_the_network(tmp_path, capsys):
    with _BannerServer() as server:
        scope_file = _write_scope(tmp_path / "scope.json", server.port)
        before = server.connections

        code = cli.main(
            [
                "--scope",
                scope_file,
                "--data",
                str(tmp_path / "campaigns"),
                "probe",
                "--target",
                "10.9.9.9",
            ]
        )

        out = capsys.readouterr().out
        assert code == 2
        assert "outside the authorized scope" in out
        assert server.connections == before


def test_the_orchestrator_refuses_a_target_the_scope_does_not_cover(tmp_path):
    scope = ScopeEnforcer(allowed_cidrs=["127.0.0.1/32"])
    orch = Orchestrator(
        StateStore(tmp_path / "campaigns"), reg=default_registry(), scope=scope
    )

    with pytest.raises(ScopeError):
        orch.run_campaign("10.9.9.9", [{"module": "discovery"}])
