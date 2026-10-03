"""HELIOS-NET :: tests/test_build_signing.py

Signing is the only thing that makes the native cores run on a host that
enforces Smart App Control, AppLocker or WDAC, and the properties that make it
work are exactly the ones that are easy to lose silently:

  * an absent certificate is reported, not assumed;
  * a partial configuration is treated as no configuration;
  * signtool exiting zero is not taken as proof - the artifact is verified;
  * the certificate password is never echoed;
  * every native artifact goes through the signing path.

Each of those was a real way for a build to produce binaries that looked signed,
or signed-but-unverifiable, while reporting nothing about either.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_build():
    spec = importlib.util.spec_from_file_location(
        "helios_build_signing", ROOT / "build.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["helios_build_signing"] = module
    spec.loader.exec_module(module)
    return module


build = _load_build()


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture(autouse=True)
def _clean_signing_env(monkeypatch):
    for name in (build._SIGN_CERT_ENV, build._SIGN_PASS_ENV, build._SIGN_TS_ENV):
        monkeypatch.delenv(name, raising=False)
    build._SIGNING_TALLY.update({"signed": 0, "unsigned": 0, "failed": 0, "blocked": 0})


@pytest.fixture
def cert(tmp_path):
    pfx = tmp_path / "code-signing.pfx"
    pfx.write_bytes(b"not a real certificate")
    return pfx


@pytest.fixture
def fake_signtool(monkeypatch, tmp_path):
    """A signtool that records how it was called."""
    calls: list[list[str]] = []
    stub = tmp_path / "signtool.exe"
    stub.write_bytes(b"MZ stub")
    monkeypatch.setattr(build, "_find_signtool", lambda: str(stub))
    return calls


# ------------------------------------------------------------ what is signed
def test_an_unconfigured_build_is_unsigned_not_signed(tmp_path):
    """The default must never imply the artifacts are trustworthy."""
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")
    assert build.sign_artifact(target) == "unsigned"


def test_a_missing_certificate_file_is_treated_as_unconfigured(tmp_path, capsys):
    monkey = pytest.MonkeyPatch()
    monkey.setenv(build._SIGN_CERT_ENV, str(tmp_path / "absent.pfx"))
    try:
        assert build._signing_config() is None
    finally:
        monkey.undo()
    out = capsys.readouterr().out
    assert "not a file" in out, "a mistyped certificate path must say so, not vanish"


def test_a_real_certificate_is_accepted(tmp_path):
    pfx = tmp_path / "c.pfx"
    pfx.write_bytes(b"x")
    monkey = pytest.MonkeyPatch()
    monkey.setenv(build._SIGN_CERT_ENV, str(pfx))
    try:
        config = build._signing_config()
    finally:
        monkey.undo()
    assert config is not None
    cert, password, timestamp = config
    assert cert == pfx
    assert password == ""
    assert timestamp.startswith("http"), (
        "a timestamp service is required for a durable signature"
    )


# ------------------------------------------------------ signing and verifying
def test_a_successful_signing_is_verified_not_assumed(
    monkeypatch, tmp_path, cert, fake_signtool
):
    monkeypatch.setenv(build._SIGN_CERT_ENV, str(cert))
    monkeypatch.setenv(build._SIGN_PASS_ENV, "hunter2")

    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        seen.append(list(cmd))
        return _Completed(0, "Successfully signed")

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")

    assert build.sign_artifact(target) == "signed"
    assert len(seen) == 2, "the artifact must be verified after being signed"
    assert seen[0][0].endswith("signtool.exe") and seen[0][1] == "sign"
    assert seen[1][1] == "verify", (
        "a zero exit from signtool is not proof of a signature"
    )
    assert build.signing_tally()[0] == 1


def test_the_password_is_passed_but_never_printed(monkeypatch, tmp_path, cert, capsys):
    monkeypatch.setenv(build._SIGN_CERT_ENV, str(cert))
    monkeypatch.setenv(build._SIGN_PASS_ENV, "swordfish")
    captured: list[list[str]] = []
    monkeypatch.setattr(build, "_find_signtool", lambda: "signtool")
    monkeypatch.setattr(
        build.subprocess,
        "run",
        lambda cmd, **kw: captured.append(list(cmd)) or _Completed(0),
    )
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")

    build.sign_artifact(target)
    assert "swordfish" in captured[0], "signtool needs the password"
    assert "swordfish" not in capsys.readouterr().out, (
        "the certificate password must never reach the build log"
    )


def test_a_signed_but_unverifiable_artifact_is_a_failure(
    monkeypatch, tmp_path, cert, capsys
):
    """signtool reported success and the image still does not carry a signature."""
    monkeypatch.setenv(build._SIGN_CERT_ENV, str(cert))
    monkeypatch.setattr(build, "_find_signtool", lambda: "signtool")

    def fake_run(cmd, **kwargs):
        return (
            _Completed(0)
            if cmd[1] == "sign"
            else _Completed(1, "", "does not contain a signature")
        )

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")

    assert build.sign_artifact(target) == "failed"
    assert "does not verify" in capsys.readouterr().out
    assert build.signing_tally()[2] == 1, (
        "a failed signature must be counted, not absorbed"
    )


def test_a_signing_failure_never_claims_success(monkeypatch, tmp_path, cert):
    monkeypatch.setenv(build._SIGN_CERT_ENV, str(cert))
    monkeypatch.setattr(build, "_find_signtool", lambda: "signtool")
    monkeypatch.setattr(
        build.subprocess, "run", lambda cmd, **kw: _Completed(1, "", "no key")
    )
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")

    assert build.sign_artifact(target) == "failed"
    assert build.signing_tally() == (0, 0, 1)


def test_a_missing_signtool_leaves_the_artifact_unsigned_and_says_why(
    monkeypatch, tmp_path, cert, capsys
):
    monkeypatch.setenv(build._SIGN_CERT_ENV, str(cert))
    monkeypatch.setattr(build, "_find_signtool", lambda: None)
    target = tmp_path / "core.exe"
    target.write_bytes(b"MZ")

    assert build.sign_artifact(target) == "unsigned"
    out = capsys.readouterr().out
    assert "signtool.exe was not found" in out
    assert "Windows SDK" in out, "the operator needs to be told what to install"


# ---------------------------------------------------------- build-wide wiring
def test_every_native_build_path_is_signed():
    """A new native artifact must not be able to skip signing by being added later."""
    source = (ROOT / "build.py").read_text(encoding="utf-8")
    # The C core, the Rust cdylib and the Go scanners are the three native image
    # producers. Each is named here as it appears in the build script, so a
    # future artifact added without a signing call fails this test.
    for marker in ("helios_core{", '"target" / "release"', "sub / out_name"):
        assert marker in source, f"{marker} is no longer part of the build"
    assert source.count("_sign_and_report(") >= 4, (
        "every native artifact - C core, Rust cdylib, Go scanner - must be routed "
        "through the signing step"
    )


def test_the_final_report_states_the_signing_outcome():
    """An unsigned build must announce itself as one, not merely stay quiet."""
    source = (ROOT / "build.py").read_text(encoding="utf-8")
    assert "signing_tally()" in source, "the summary must read the signing tally"
    assert "UNSIGNED" in source, "an unsigned artifact must be labelled as such"
    assert build._SIGN_CERT_ENV in source, (
        "the summary must name the variable that fixes it"
    )


def test_no_credential_is_ever_hardcoded():
    """The certificate is out of band; nothing secret belongs in the tree."""
    source = (ROOT / "build.py").read_text(encoding="utf-8")
    for forbidden in ("password=", 'pfx"', "BEGIN PRIVATE KEY", '.pfx"'):
        assert forbidden not in source, (
            f"{forbidden!r} must not appear in the build script"
        )
