"""Suite-wide policy: a skipped test fails the run unless it is allowed.

Almost every skip in this suite means a native core was not built on the host
(``C core binary not built``, ``Rust core not built``, ``Go binary not built``).
A run that reports ``799 passed, 108 skipped`` therefore claims coverage it
never executed: the parity, FFI and golden tests that keep the C, Rust and Go
cores honest simply did not run.

Run ``python build.py`` first. If a skip is genuinely intentional, pass
``--allow-skips`` and the summary will show it as skipped again.
"""

from __future__ import annotations

import pytest

_ALLOW_SKIPS = "allow_skips"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--allow-skips",
        action="store_true",
        default=False,
        help="report skipped tests as skipped instead of failing the run",
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[no-untyped-def]
    outcome = yield
    report = outcome.get_result()
    if not report.skipped or item.config.getoption(_ALLOW_SKIPS):
        return
    if getattr(report, "wasxfail", None) is not None:
        return
    reason = (
        str(report.longrepr[2])
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3
        else str(report.longrepr)
    )
    report.outcome = "failed"
    report.longrepr = (
        "this run treats skips as failures so coverage cannot be claimed "
        "without executing it; run `python build.py` first, or pass "
        f"--allow-skips to accept the skip ({reason})"
    )
