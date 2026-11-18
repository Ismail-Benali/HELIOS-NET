"""Bundling the native cores into the wheel package.

The bundler is the step that turns "built on this runner" into "inside the
artifact". These tests use a fake checkout so they never read or delete the
real build output.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_bundler():
    spec = importlib.util.spec_from_file_location(
        "helios_bundle_cores", ROOT / "tools" / "bundle_cores.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["helios_bundle_cores"] = module
    spec.loader.exec_module(module)
    return module


bundler = _load_bundler()


def _fake_checkout(root: Path) -> None:
    exe = bundler._EXE
    (root / "transport" / "c_core" / "build").mkdir(parents=True)
    (root / "transport" / "c_core" / "build" / f"helios_core{exe}").write_bytes(b"c")
    (root / "transport" / "c_core" / "build" / "helios_core.dll").write_bytes(b"dll")
    rust = root / "rust-core" / "target" / "release"
    rust.mkdir(parents=True)
    (rust / "helios_rust_core.dll").write_bytes(b"rust")
    goscan = root / "transport" / "goscan"
    goscan.mkdir(parents=True)
    (goscan / f"goscan{exe}").write_bytes(b"go")


def test_candidate_artifacts_ignore_missing_files(tmp_path):
    _fake_checkout(tmp_path)
    found = bundler.candidate_artifacts(tmp_path)
    assert [path.name for path in found.c] == [
        f"helios_core{bundler._EXE}",
        "helios_core.dll",
    ]
    assert [path.name for path in found.rust] == ["helios_rust_core.dll"]
    assert [path.name for path in found.go] == [f"goscan{bundler._EXE}"]


def test_bundle_replaces_stale_artifacts_and_keeps_other_files(tmp_path):
    _fake_checkout(tmp_path)
    destination = tmp_path / "core" / "native"
    destination.mkdir(parents=True)
    (destination / "old.so").write_bytes(b"stale")
    (destination / "notes.txt").write_text("keep", encoding="utf-8")

    copied = bundler.bundle(tmp_path, destination)

    assert {path.name for path in copied} == {
        f"helios_core{bundler._EXE}",
        "helios_core.dll",
        "helios_rust_core.dll",
        f"goscan{bundler._EXE}",
    }
    assert not (destination / "old.so").exists()
    assert (destination / "notes.txt").exists()
    assert (destination / f"goscan{bundler._EXE}").read_bytes() == b"go"


def test_main_reports_a_missing_core(tmp_path, capsys):
    (tmp_path / "transport" / "goscan").mkdir(parents=True)
    (tmp_path / "transport" / "goscan" / f"goscan{bundler._EXE}").write_bytes(b"go")

    assert bundler.main(["--root", str(tmp_path), "--require", "go"]) == 0
    assert bundler.main(["--root", str(tmp_path), "--require", "c"]) == 1
    assert "missing built artifacts" in capsys.readouterr().err


def test_bridges_look_in_the_bundled_package_last():
    from core import c_core_bridge, rust_bridge
    from modules.discovery import goscan_bridge

    native = ROOT / "core" / "native"
    assert native == c_core_bridge._BUNDLED_DIR
    assert c_core_bridge._BINARY_CANDIDATES[-1].parent == native
    assert rust_bridge._CANDIDATE_DIRS[-1] == native
    assert goscan_bridge._BUNDLED_BIN.parent == native
    assert goscan_bridge.GOSCAN_BIN in {
        goscan_bridge._CHECKOUT_BIN,
        goscan_bridge._BUNDLED_BIN,
    }
