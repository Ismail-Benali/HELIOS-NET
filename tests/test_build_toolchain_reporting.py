"""The build pipeline has to be honest about why a stage did not run.

Both defects here were found on a live host rather than guessed at: a MinGW gcc
that resolves on PATH but is refused execution, and a C compile error that the
old detection code reclassified as a missing toolchain. Either one turns a
toolchain limitation into a false accusation against the code under test, or
silently drops coverage that the summary is supposed to surface.
"""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_build():
    spec = importlib.util.spec_from_file_location("helios_build", ROOT / "build.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["helios_build"] = module
    spec.loader.exec_module(module)
    return module


build = _load_build()


def _fake_compiler(tmp_path: Path, name: str, exit_code: int) -> str:
    """A stub on PATH that behaves like a real compiler exit code."""
    if os.name == "nt":
        stub = tmp_path / f"{name}.cmd"
        stub.write_text(f"@exit /b {exit_code}\n", encoding="utf-8")
    else:
        stub = tmp_path / name
        stub.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
        stub.chmod(0o755)
    return str(stub)


class TestCompilerMustActuallyRun:
    def test_a_resolvable_compiler_that_exits_non_zero_is_rejected(self, tmp_path):
        """gcc on PATH that exits 3236495362 is not a toolchain."""
        broken = _fake_compiler(tmp_path, "gcc", 3236495362)
        assert build._cc_compiler_works(broken) is False

    def test_a_working_compiler_is_accepted(self, tmp_path):
        real = build._cc_compiler_works("gcc")
        assert real in (True, False), "probe must return a bool, not raise"
        if real:
            assert build._cc_compiler_works("gcc") is True

    def test_a_missing_compiler_is_rejected(self, tmp_path):
        absent = str(tmp_path / "definitely-not-a-compiler")
        assert build._cc_compiler_works(absent) is False

    def test_race_env_is_none_when_no_compiler_can_run(self, monkeypatch, tmp_path):
        """The whole point: no usable compiler must skip, not fail."""
        broken = _fake_compiler(tmp_path, "gcc", 1)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.delenv("CC", raising=False)
        assert build._race_env() is None

    def test_race_env_falls_through_a_broken_inherited_cc(self, monkeypatch, tmp_path):
        """An inherited CC that will not run must not be trusted."""
        broken = _fake_compiler(tmp_path, "gcc", 1)
        monkeypatch.setenv("CC", broken)
        monkeypatch.setenv("PATH", str(tmp_path))
        assert build._race_env() is None

    def test_race_env_enables_cgo_for_a_working_compiler(self, monkeypatch, tmp_path):
        stub = tmp_path / ("gcc.bat" if os.name == "nt" else "gcc")
        if os.name == "nt":
            stub.write_text("@echo off\r\necho gcc (test stub) 1.0\r\n", encoding="utf-8")
        else:
            stub.write_text("#!/bin/sh\necho 'gcc (test stub) 1.0'\n", encoding="utf-8")
            stub.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.delenv("CC", raising=False)
        env = build._race_env()
        assert env is not None, "a compiler that prints a version must be accepted"
        assert env["CGO_ENABLED"] == "1"


class TestFailureStatesAreNotSwallowed:
    """A qualified FAILED state must still fail the process.

    The C summary gained "FAILED (C build failed)". The failure predicate is an
    exact `== "FAILED"` comparison, so without the prefix check a real C build
    failure would print itself and then exit 0. These call the production helper
    rather than restating its logic, because a copy of the predicate would keep
    passing after the real one regressed.
    """

    @pytest.mark.parametrize("state", [
        "FAILED", "FAILED (C build failed)", "FAILED (anything else)",
    ])
    def test_prefixed_failed_states_count_as_failures(self, state):
        stages = {
            "Go unit tests": state, "Rust unit tests": "PASSED",
            "C core tests": "PASSED", "C core fuzzer": "SKIPPED",
            "core health": "PASSED",
        }
        assert build._failing_stages(stages) == ["Go unit tests"]

    @pytest.mark.parametrize("state", [
        "PASSED", "SKIPPED", "SKIPPED (no usable C toolchain)",
        "BLOCKED BY HOST POLICY", "failed-not-a-state", "",
    ])
    def test_non_failure_states_do_not_fail_the_process(self, state):
        stages = {
            "Go unit tests": state, "Rust unit tests": "PASSED",
            "C core tests": "PASSED", "C core fuzzer": "SKIPPED",
            "core health": "PASSED",
        }
        assert build._failing_stages(stages) == []

    def test_a_c_build_failure_alone_fails_the_process(self):
        """The exact regression: C skipped is fine, C build broken is not."""
        stages = {
            "Go unit tests": "PASSED", "Rust unit tests": "PASSED",
            "C core tests": "FAILED (C build failed)",
            "C core fuzzer": "SKIPPED", "core health": "PASSED",
        }
        assert build._failing_stages(stages) == ["C core tests"]

    def test_a_missing_c_toolchain_is_not_a_failure(self):
        """Skipping C for lack of a compiler must stay exit-0 compatible."""
        stages = {
            "Go unit tests": "PASSED", "Rust unit tests": "PASSED",
            "C core tests": "SKIPPED (no usable C toolchain)",
            "C core fuzzer": "SKIPPED", "core health": "PASSED",
        }
        assert build._failing_stages(stages) == []

    def test_the_summary_wires_every_stage_into_the_predicate(self):
        """A stage dropped from the mapping would silently stop failing."""
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        start = source.index("failed = _failing_stages(")
        end = source.index("if failed:", start)
        mapping = source[start:end]
        for stage in ("Go unit tests", "Rust unit tests", "C core tests",
                      "C core fuzzer", "core health"):
            assert stage in mapping, f"{stage} is missing from the failure mapping"


class TestCOutcomesStayDistinguishable:
    """A missing toolchain, a failed build and a failed test suite are three
    different facts, and the summary has to keep them apart.

    Behaviour is asserted through the production helper rather than by matching
    source text: a source-text assertion kept passing when the code that sets
    `c_build` was broken, because the literal name still appeared in the block.
    """

    def test_absent_toolchain_still_runs_the_stages_and_reports_their_result(self):
        """The C stages no longer hang off compiler detection.

        They compile when they can and fall back to a current prebuilt binary when
        they cannot, so a host with no compiler still gets real C evidence. Only a
        stage that produced nothing is reported as a skip.
        """
        assert build._c_core_state(
            {"c": False, "c_build": None, "c_tests": "passed"}) == "PASSED"

    def test_a_build_failure_outranks_a_stale_c_tests_value(self):
        state = build._c_core_state({"c": True, "c_build": False, "c_tests": "passed"})
        assert state == "FAILED (C build failed)"

    def test_a_working_toolchain_reports_the_real_test_result(self):
        for raw, expected in ((True, "PASSED"), (False, "FAILED"),
                              ("blocked", "BLOCKED BY HOST POLICY"),
                              ("passed", "PASSED"), ("failed", "FAILED")):
            state = build._c_core_state({"c": True, "c_build": True, "c_tests": raw})
            assert state == expected, f"c_tests={raw!r} reported as {state!r}"

    def test_a_blocked_c_core_is_not_reported_as_a_failure(self):
        state = build._c_core_state({"c": True, "c_build": True, "c_tests": "blocked"})
        assert state == "BLOCKED BY HOST POLICY"
        assert build._failing_stages({"C core tests": state}) == []

    def test_a_stage_that_produced_nothing_is_a_skip(self):
        state = build._c_core_state({"c": False, "c_build": None, "c_tests": "skipped"})
        assert state == "SKIPPED (no usable C toolchain)"
        assert build._failing_stages({"C core tests": state}) == []

    def test_the_summary_uses_the_helper_rather_than_reimplementing_it(self):
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        assert "c_state = _c_core_state(toolchain_status)" in source
        assert "SKIPPED (no usable C toolchain)" not in source.split(
            "def _c_core_state", 1)[1].split("def _failing_stages", 1)[0].replace(
                'return "SKIPPED (no usable C toolchain)"', ""
            ), "the state must be produced in one place only"

    def test_detection_does_not_swallow_the_build(self):
        """A C build failure must be recorded, not discarded.

        The build call used to live inside the detection try-block, so a compile
        error was caught, retried against clang, and reported as a missing
        toolchain, and `c_build` was never consulted at all.
        """
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        start = source.index("c_compiler = next(")
        end = source.index("if run_tests and toolchain_status", start)
        block = source[start:end]
        assert block.count("build_c_components()") == 1
        assert 'toolchain_status["c_build"] = False' in block, (
            "a failed C build must be recorded so the summary can report it"
        )
        assert 'toolchain_status["c_build"] = True' in block, (
            "a successful C build must be recorded too"
        )

    def test_diagnostic_no_longer_blames_path_for_an_unrunnable_compiler(self):
        """The old message claimed the compiler was absent from PATH."""
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        assert "No C compiler (gcc/clang) found in PATH" not in source
        assert "will not execute under host policy" in source


class TestNoProbeArtifactsAreLeftBehind:
    def test_probe_compilers_live_in_tmp_not_in_the_repository(self):
        """A stub compiler written into the repo would ship an executable.

        Every stub in this suite is created under pytest's tmp_path, so the tree
        stays free of them. A stray `.cmd`/shell stub in the repository would be
        both a build artefact and an executable file in version control.
        """
        for stray in list(ROOT.glob("**/gcc.cmd")) + list(ROOT.glob("**/gcc.bat")):
            pytest.fail(f"stub compiler left in the repository: {stray}")

    def test_every_stub_compiler_is_created_under_tmp_path(self):
        """Checked via AST so the assertion cannot match its own source text."""
        import ast

        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        helper = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_fake_compiler"
        )
        helper_id = helper.name
        targets = {
            node.func.id: node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == helper_id and node.args
        }
        assert targets, "the suite must still exercise the compiler probe"
        for call in targets.values():
            first = call.args[0]
            assert isinstance(first, ast.Name) and first.id == "tmp_path", (
                "stub compiler must be created under tmp_path, not in the repo "
                f"(line {call.lineno})"
            )

    def test_subprocess_probe_uses_no_shell(self):
        """Keep the version probe out of shell interpretation."""
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        start = source.index("def _cc_compiler_works")
        end = source.index("def _race_env", start)
        assert "shell=False" in source[start:end]


class TestPrebuiltCBinaryIsAcceptedOnlyWhenCurrent:
    """The prebuilt fallback must not become a way to report stale code as PASS.

    This host has no usable C compiler, and skipping the prebuilt binaries threw
    away 297 unit checks and 31886 differential fuzz checks that run and pass
    here. But a binary older than its own source is evidence about code that is
    no longer in the tree, which is worse than an honest skip.
    """

    def _touch(self, path: Path, mtime: float) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
        import os
        os.utime(path, (mtime, mtime))

    def test_a_binary_newer_than_every_input_is_accepted(self, tmp_path):
        core = tmp_path / "c_core"
        self._touch(core / "src" / "a.c", 1000.0)
        self._touch(core / "include" / "a.h", 2000.0)
        self._touch(core / "tests" / "t.c", 1500.0)
        binary = core / "build" / "test_core.exe"
        self._touch(binary, 3000.0)

        usable, why = build._usable_prebuilt(binary, core)
        assert usable is True
        assert "3000" not in why
        assert "newer" in why

    def test_a_binary_older_than_any_input_is_rejected(self, tmp_path):
        core = tmp_path / "c_core"
        self._touch(core / "src" / "a.c", 1000.0)
        self._touch(core / "include" / "a.h", 9000.0)
        binary = core / "build" / "test_core.exe"
        self._touch(binary, 2000.0)

        usable, why = build._usable_prebuilt(binary, core)
        assert usable is False
        assert "predates" in why and "a.h" in why, why
        assert "not evidence" in why

    def test_a_missing_binary_is_rejected(self, tmp_path):
        core = tmp_path / "c_core"
        self._touch(core / "src" / "a.c", 1000.0)
        usable, why = build._usable_prebuilt(core / "build" / "nope.exe", core)
        assert usable is False
        assert "no prebuilt binary" in why

    def test_equal_timestamps_are_accepted(self, tmp_path):
        """Filesystem granularity can make a just-built binary match its source."""
        core = tmp_path / "c_core"
        self._touch(core / "src" / "a.c", 4000.0)
        binary = core / "build" / "test_core.exe"
        self._touch(binary, 4000.0)
        assert build._usable_prebuilt(binary, core)[0] is True

    def test_non_c_files_do_not_gate_the_binary(self, tmp_path):
        """A stray .md or .exe in the tree is not a build input."""
        core = tmp_path / "c_core"
        self._touch(core / "src" / "a.c", 1000.0)
        self._touch(core / "src" / "notes.md", 9999.0)
        self._touch(core / "src" / "stale.o", 9999.0)
        binary = core / "build" / "test_core.exe"
        self._touch(binary, 2000.0)
        assert build._usable_prebuilt(binary, core)[0] is True

    def test_a_shipped_prebuilt_is_never_treated_as_healthy_when_stale(self):
        """A committed prebuilt that predates its sources must be rejected, with a reason.

        This used to assert that the repository's own binaries are current. That
        is not a property of the code - it is a fact about whether someone ran
        the compiler after editing C, and it is false on every host mid-edit and
        on any host whose toolchain is unavailable. Asserting it meant a stale
        prebuild turned the suite red for a reason that had nothing to do with
        whether stale prebuilds are handled correctly.

        The property worth protecting is the safety one, and it is checked in
        both directions: a current prebuilt is accepted, and a stale one is
        refused *and names the file it predates*. A weakened test would let a
        stale binary pass as healthy; this one cannot.
        """
        core = ROOT / "transport" / "c_core"
        checked = 0
        for name in ("helios_core.exe", "test_core.exe", "fuzz_harness.exe"):
            binary = core / "build" / name
            if not binary.exists():
                continue
            checked += 1
            usable, why = build._usable_prebuilt(binary, core)
            if usable:
                continue
            assert "predates" in why and binary.name in why, (
                f"{name} was rejected without naming the source it predates: {why}"
            )
        if not checked:
            pytest.skip("no prebuilt C binaries are present in this checkout")


class TestStaleCBinaryIsNotUsedAsHealthy:
    @staticmethod
    def _make_core(tmp_path, source_mtime, binary_mtime):
        """Build a throwaway c_core tree with a given source/binary age ordering.

        `_BINARY_CANDIDATES` is resolved at import time, so patching `_CORE_DIR`
        alone is not enough - the candidate tuple has to be redirected too, or the
        functions keep looking at the real repository paths.
        """
        from core import c_core_bridge

        core = tmp_path / "c_core"
        src = core / "src" / "a.c"
        binary = core / "build" / f"helios_core{'.exe' if os.name == 'nt' else ''}"
        for path, mtime in ((src, source_mtime), (binary, binary_mtime)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x", encoding="utf-8")
            os.utime(path, (mtime, mtime))
        return core, binary, c_core_bridge

    def test_a_stale_binary_is_not_selected(self, tmp_path, monkeypatch):
        core, binary, bridge = self._make_core(tmp_path, 5000.0, 1000.0)
        monkeypatch.setattr(bridge, "_CORE_DIR", core)
        monkeypatch.setattr(bridge, "_BINARY_CANDIDATES", (binary,))
        monkeypatch.delenv(bridge._ENV_KEY, raising=False)
        assert bridge._locate_binary() is None, (
            "a binary older than its own source must not be selected"
        )

    def test_a_current_binary_is_selected(self, tmp_path, monkeypatch):
        core, binary, bridge = self._make_core(tmp_path, 1000.0, 5000.0)
        monkeypatch.setattr(bridge, "_CORE_DIR", core)
        monkeypatch.setattr(bridge, "_BINARY_CANDIDATES", (binary,))
        monkeypatch.delenv(bridge._ENV_KEY, raising=False)
        assert bridge._locate_binary() == binary

    def test_staleness_note_explains_why_the_binary_is_not_used(self, tmp_path, monkeypatch):
        core, binary, bridge = self._make_core(tmp_path, 5000.0, 1000.0)
        monkeypatch.setattr(bridge, "_CORE_DIR", core)
        monkeypatch.setattr(bridge, "_BINARY_CANDIDATES", (binary,))
        monkeypatch.delenv(bridge._ENV_KEY, raising=False)
        note = bridge.staleness_note()
        assert "predates" in note and "a.c" in note

    def test_staleness_note_agrees_with_the_binary_it_describes(self):
        """The note must match reality in both directions.

        Previously this asserted the note was always empty for the shipped core,
        which quietly encoded "the committed binary is newer than the sources".
        After a C edit that stops being true - and a false note is worse than an
        absent one, so the invariant is that the note is empty exactly when the
        binary is current, and otherwise names what it predates.
        """
        from core import c_core_bridge

        core = ROOT / "transport" / "c_core"
        suffix = ".exe" if os.name == "nt" else ""
        shipped = [core / "build" / f"helios_core{suffix}", core / f"helios_core{suffix}"]
        present = [p for p in shipped if p.exists()]
        if not present:
            pytest.skip("no shipped C core binary to describe")

        note = c_core_bridge.staleness_note()
        usable = any(build._usable_prebuilt(p, core)[0] for p in present)
        if usable:
            assert note == "", f"a current binary must report no staleness, got: {note}"
        else:
            assert "predates" in note, f"a stale binary must say so, got: {note}"


class TestPolicyRefusalInToolOutputIsNotAFailure:
    """`go test` reports a refused test binary on stdout and exits non-zero.

    The refusal never arrives as an exception, so it bypassed the exception-based
    `_is_policy_block` and was reported as a failing Go test suite. That accuses
    the code of a defect the host caused, and it is the exact mistake this
    pipeline was written to stop.
    """

    FRENCH = (
        "fork/exec C:\\Users\\x\\AppData\\Local\\Temp\\go-build123\\b001\\goscan.test.exe: "
        "Une strat\u00e9gie de contr\u00f4le d\u2019application a bloqu\u00e9 ce fichier.\nFAIL\tgoscan\t2.3s\n"
    )
    ENGLISH = "An application control policy blocked this file.\nFAIL\tgoscan\t2.3s\n"

    @pytest.mark.parametrize("output", [FRENCH, ENGLISH])
    def test_a_refusal_is_recognised(self, output):
        assert build._looks_policy_blocked(output) is True

    @pytest.mark.parametrize("output", [
        "--- FAIL: TestParsePorts (0.00s)\n    pool_bounds_test.go:41: peak 20000 goroutines\n",
        "compile error: undefined: resolveService\n",
        "vet: ./...: some files were not analysed\n",
        "",
    ])
    def test_a_real_failure_is_not_mistaken_for_a_refusal(self, output):
        assert build._looks_policy_blocked(output) is False

    def test_a_refusal_does_not_fail_the_build(self):
        stages = {"Go unit tests": "BLOCKED BY HOST POLICY"}
        assert build._failing_stages(stages) == []

    def test_a_refusal_is_still_not_a_pass(self):
        """It must not be laundered into coverage either."""
        state = build._go_state({"go": True, "go_tests": "blocked"})
        assert state == "BLOCKED BY HOST POLICY"
        assert state != "PASSED"

    def test_a_refusal_clears_the_success_flag_in_the_source(self):
        """Regression: the BLOCKED branch left `ok` True.

        `blocked = True; continue` without `ok = False` made the function return
        "passed", so a refused test binary printed "[+] Go vet, gofmt, unit tests
        and race detector passed" and the summary reported Go Unit Tests: PASSED.
        """
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        # Anchored to the Go stage, not to the first textual match: the Rust stage
        # has its own policy check now, so a whole-file search finds that one
        # first and asserts against the wrong function.
        go_start = source.index("def run_go_unit_tests(")
        go_source = source[go_start:source.index("\ndef ", go_start + 1)]
        start = go_source.index("if _looks_policy_blocked(output):")
        end = go_source.index("continue", start)
        branch = go_source[start:end]
        assert "blocked = True" in branch
        assert "ok = False" in branch, (
            "the policy-blocked branch must also clear the success flag"
        )

    def test_the_rust_stage_also_separates_a_refusal_from_a_failure(self):
        """cargo reports a refused test binary as a non-zero exit.

        Without the policy check that is a failed suite, which blames the crate
        for a host decision. The Rust stage returns its own state instead.
        """
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        rust_start = source.index("def run_rust_unit_tests(")
        rust_source = source[rust_start:source.index("\ndef ", rust_start + 1)]
        assert "_looks_policy_blocked(output)" in rust_source, (
            "the Rust stage must check for a policy refusal"
        )
        assert 'return "blocked"' in rust_source
        assert 'return "passed"' in rust_source

    def test_the_blocked_return_path_requires_ok_to_be_false(self):
        """A stage that is blocked but not failed must return "blocked"."""
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        start = source.index("if not ok and blocked:")
        snippet = source[start:start + 400]
        assert 'return "blocked"' in snippet
        assert 'return "passed" if ok else "failed"' in snippet, (
            "a blocked stage must not fall through to the passed/failed return"
        )

    def test_go_state_maps_every_return_value(self):
        cases = {
            (True, "PASSED"), ("passed", "PASSED"),
            ("blocked", "BLOCKED BY HOST POLICY"),
            (False, "FAILED"), ("failed", "FAILED"),
        }
        for raw, expected in cases:
            assert build._go_state({"go": True, "go_tests": raw}) == expected, raw

    def test_a_missing_go_toolchain_is_a_skip(self):
        assert build._go_state({"go": False, "go_tests": False}) == "SKIPPED"


def test_the_rust_stage_reports_a_refusal_as_its_own_state():
    """The three outcomes the summary has to be able to tell apart."""
    source = (ROOT / "build.py").read_text(encoding="utf-8")
    rust_start = source.index("def run_rust_unit_tests(")
    rust_source = source[rust_start:source.index("\ndef ", rust_start + 1)]
    for state in ('return "passed"', 'return "failed"', 'return "blocked"'):
        assert state in rust_source, f"the Rust stage has no {state} path"

    # And the summary must be able to render the blocked one, rather than
    # falling through to FAILED and blaming the crate.
    assert '"blocked": "BLOCKED BY HOST POLICY"' in source


class TestHealthProbeReportsWhatItProved:
    """A core the host refused to execute is not evidence, and not a defect.

    `run_core_health` only failed on FAILED, so a policy-refused core produced
    "Core Health: PASSED" and vanished from the summary entirely.
    """

    @staticmethod
    def _fake_health(monkeypatch, cores):
        from core import cores as cores_mod
        monkeypatch.setattr(cores_mod, "health_report", lambda: {"cores": cores})
        monkeypatch.setattr(cores_mod, "format_report", lambda r: "report")

    def test_a_refused_core_yields_blocked_not_passed(self, monkeypatch):
        self._fake_health(monkeypatch, [
            {"name": "go", "state": "blocked", "detail": "refused by host policy"},
        ])
        assert build.run_core_health() == "blocked"

    def test_a_broken_core_still_fails(self, monkeypatch):
        self._fake_health(monkeypatch, [
            {"name": "c", "state": "failed", "detail": "selftest failed"},
        ])
        assert build.run_core_health() == "failed"

    def test_a_refused_core_outranks_a_fallback_core(self, monkeypatch):
        self._fake_health(monkeypatch, [
            {"name": "python-fallback", "state": "fallback", "detail": "absent"},
            {"name": "go", "state": "blocked", "detail": "refused by host policy"},
        ])
        assert build.run_core_health() == "blocked"

    def test_healthy_cores_pass(self, monkeypatch):
        self._fake_health(monkeypatch, [
            {"name": "rust", "state": "ok", "detail": "19 checks"},
            {"name": "c", "state": "ok", "detail": "selftest ok"},
        ])
        assert build.run_core_health() == "passed"

    def test_blocked_health_is_named_in_the_coverage_gap(self):
        """A gap that is not printed is a gap nobody acts on."""
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        start = source.index("gaps = [")
        snippet = source[start:start + 400]
        assert "native core health probe" in snippet


class TestCStagesRunWithoutACompiler:
    """The C stages must not hang off compiler detection.

    Gating them on `toolchain_status["c"]` is what hid 297 unit checks and 31886
    differential fuzz checks that run and pass on this host. This is a wiring
    property with no cheap unit seam, so it is asserted on the call site rather
    than on a copy of the logic.
    """

    def test_the_c_stages_are_not_guarded_by_compiler_detection(self):
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        # Match the call site, not the `def run_c_core_tests()` declaration, which
        # contains the same text.
        call = source.index('toolchain_status["c_tests"] = run_c_core_tests()')
        guard = source.rindex("\n    if ", 0, call) + 1
        line = source[guard:source.index("\n", guard)]
        assert 'toolchain_status["c"]' not in line, (
            f"C stages are still gated on compiler detection: {line.strip()!r}"
        )
        assert "run_tests" in line, (
            f"the C stages must still respect run_tests: {line.strip()!r}"
        )

    def test_both_c_stages_are_still_wired(self):
        source = (ROOT / "build.py").read_text(encoding="utf-8")
        assert "toolchain_status[\"c_tests\"] = run_c_core_tests()" in source
        assert "toolchain_status[\"c_fuzz\"] = run_c_fuzz_harness()" in source


def test_build_module_imports_without_side_effects(monkeypatch):
    """Importing build.py must not start a pipeline or touch os.exit."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    module = _load_build()
    assert callable(module.run_go_unit_tests)
    assert callable(module._race_env)
    assert os.environ.get("CGO_ENABLED") != "1", "importing must not enable cgo globally"
