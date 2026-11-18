"""Packaging contract: installable metadata, console entry point, data paths.

`pipx install .` is the advertised one-command install, so the metadata that
makes it work has to be pinned: the script target must exist, the version must
be PEP 440, the license must match LICENSE, and the modules that hold runtime
data must be declared as packages.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import core.paths as paths
import core.reporter_interactive as reporter
import modules.ingest.nmap as nmap

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_metadata_matches_the_repository():
    project = PYPROJECT["project"]
    assert project["name"] == "helios-net"
    assert project["requires-python"].startswith(">=3.12")
    assert project["version"].startswith("2.0.0")
    assert project["license"] == {"file": "LICENSE"}
    assert (ROOT / "pyproject.toml").is_file()
    assert (
        (ROOT / "LICENSE")
        .read_text(encoding="utf-8")
        .startswith("                    GNU AFFERO GENERAL PUBLIC LICENSE")
    )


def test_console_script_target_imports():
    script = PYPROJECT["project"]["scripts"]["helios"]
    module_name, _, attribute = script.partition(":")
    module = __import__(module_name, fromlist=[attribute])
    assert callable(getattr(module, attribute))


def test_runtime_data_is_declared_as_package_data():
    find = PYPROJECT["tool"]["setuptools"]["packages"]["find"]
    for package in ("core", "cli", "engine", "modules", "config"):
        assert f"{package}*" in find["include"]
    assert find["namespaces"] is True
    assert PYPROJECT["tool"]["setuptools"]["package-data"]["config"] == [
        "*.yaml",
        "*.txt",
    ]


def test_data_dir_honours_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.DATA_ENV_VAR, str(tmp_path / "custom"))
    assert paths.default_data_dir() == tmp_path / "custom"


def test_checkout_uses_its_own_data_directory(monkeypatch):
    monkeypatch.delenv(paths.DATA_ENV_VAR, raising=False)
    monkeypatch.setattr(paths, "running_from_source", lambda: True)
    assert paths.default_data_dir() == paths.repo_root() / "data"


def test_installed_layout_stays_out_of_site_packages(monkeypatch, tmp_path):
    monkeypatch.delenv(paths.DATA_ENV_VAR, raising=False)
    monkeypatch.setattr(paths, "running_from_source", lambda: False)
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda cls: tmp_path))
    assert paths.default_data_dir() == tmp_path / ".helios-net"


def test_new_modules_are_reachable_from_the_documented_entry_points():
    assert callable(nmap.parse_nmap_xml)
    assert callable(reporter.generate_interactive_report)
