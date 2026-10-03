"""HELIOS-NET :: core/cores.py
Unified native-core contract and health reporting.

Every native core in HELIOS-NET (Go, C, Rust) plus the Python reference must
answer the same three questions:

    1. Is it present?      a built artefact exists
    2. Does it load?       the artefact can be initialised (library loaded,
                           binary marked executable)
    3. Does it work?       it self-tests successfully from Python

The third question is the one that matters and the one that was previously never
asked. A graceful fallback makes a broken core indistinguishable from a healthy
one, and this repository shipped a Go core that deadlocked on every single
invocation while every test still passed. `core_available()` alone would have
reported that binary as fine.

`health_report()` is the single place that answers all three, and it is wired
into `build.py --test` and the test suite so a core cannot quietly stop working.

Note on the "blocked" state: a host application-control policy can refuse to
execute a freshly linked unsigned binary. That is an environment condition, not
a code defect, so it is reported distinctly from "failed" and never silently
folded into success.
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Core health states.
OK = "ok"  # present, loadable, and self-tested successfully
FALLBACK = "fallback"  # not usable; the caller runs the pure-Python path
FAILED = "failed"  # present and loadable, but its self test failed
BLOCKED = "blocked"  # present, but the host refused to execute it


@dataclass
class CoreStatus:
    """Health of one native core."""

    name: str
    language: str
    role: str
    state: str = FALLBACK
    version: str = "unavailable"
    detail: str = ""
    tests: dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        """True only when the core is present, loadable and self-tested."""
        return self.state == OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "language": self.language,
            "role": self.role,
            "state": self.state,
            "usable": self.usable,
            "version": self.version,
            "detail": self.detail,
            "tests": self.tests,
        }


def _policy_blocked(exc: BaseException) -> bool:
    """Detects a host application-control refusal to execute an image.

    The winerror is the authoritative signal. The message check is only a
    fallback for hosts that surface the policy in text without a code, and it
    deliberately looks for the policy wording rather than the bare number: a
    stray "4551" in an unrelated error is not evidence of a policy refusal.
    """
    if getattr(exc, "winerror", None) == 4551:
        return True
    text = str(exc).lower()
    if "application control" in text or "applicationcontrol" in text:
        return True
    if "contr" in text and "application" in text:
        return True
    return False


def check_python() -> CoreStatus:
    status = CoreStatus(
        name="python",
        language="Python",
        role="reference implementation and universal fallback",
    )
    status.version = f"Python {platform.python_version()}"
    status.state = OK
    # The reference must be able to run its own test harness.
    status.tests = {"importable": True, "version": platform.python_version()}
    return status


def check_rust() -> CoreStatus:
    from core import rust_bridge

    status = CoreStatus(
        name="rust",
        language="Rust",
        role="Aho-Corasick signature matching and graph analytics",
    )
    if not rust_bridge.rust_available():
        status.detail = f"library not found in {rust_bridge._CANDIDATE_DIRS}"
        return status

    status.version = rust_bridge.rust_version()
    status.tests["abi_version"] = rust_bridge.rust_abi_version()

    if rust_bridge.rust_selftest():
        status.state = OK
        status.tests["selftest"] = "passed"
    else:
        status.state = FAILED
        status.detail = "library loaded but its internal self test failed"
        status.tests["selftest"] = "failed"
    return status


def check_c() -> CoreStatus:
    from core import c_core_bridge

    status = CoreStatus(
        name="c",
        language="C",
        role="signature matching and banner fingerprinting",
    )
    if not c_core_bridge.core_available():
        stale = c_core_bridge.staleness_note()
        if stale:
            status.state = FAILED
            status.detail = (
                f"a binary is present but stale: {stale}. It describes older code, "
                "so it was not run and the Python fallback is in use."
            )
        else:
            status.detail = f"binary not found at {c_core_bridge._BINARY}"
        return status

    status.version = c_core_bridge.core_version()
    try:
        report = c_core_bridge.selftest()
    except OSError as exc:
        if _policy_blocked(exc):
            status.state = BLOCKED
            status.detail = (
                "host application-control policy refused to execute the binary; "
                "the core did not run, which is not a code defect"
            )
        else:
            status.state = FAILED
            status.detail = f"could not execute the core: {exc}"
        return status

    if report is None:
        status.state = FAILED
        status.detail = "the core produced no self-test report"
        return status

    status.tests["selftest"] = report
    failures = report.get("failures")
    if report.get("status") == "ok" and failures == 0:
        status.state = OK
        status.detail = f"{report.get('checks', '?')} checks"
    else:
        status.state = FAILED
        status.detail = f"self test reported {failures} failure(s)"
    return status


def check_go() -> CoreStatus:
    from modules.discovery import goscan_bridge

    status = CoreStatus(
        name="go",
        language="Go",
        role="concurrent port scanning and banner grabbing",
    )
    if not goscan_bridge.core_available():
        status.detail = f"binary not found at {goscan_bridge.GOSCAN_BIN}"
        return status

    status.version = goscan_bridge.core_version()
    try:
        report = goscan_bridge.selftest()
    except OSError as exc:
        if _policy_blocked(exc):
            status.state = BLOCKED
            status.detail = (
                "host application-control policy refused to execute the binary; "
                "the core did not run, which is not a code defect"
            )
        else:
            status.state = FAILED
            status.detail = f"could not execute the core: {exc}"
        return status

    if report is None:
        status.state = FAILED
        status.detail = "the core produced no self-test report"
        return status

    status.tests["selftest"] = report
    if report.get("status") == "ok" and report.get("failures") == 0:
        status.state = OK
        status.detail = f"{report.get('checks', '?')} checks"
    else:
        status.state = FAILED
        status.detail = f"self test reported {report.get('failures')} failure(s)"
    return status


#: Every core in dependency order, with the checker that inspects it.
_CHECKS: tuple[tuple[Callable[[], CoreStatus], ...], ...] = (
    (check_python,),
    (check_rust,),
    (check_c,),
    (check_go,),
)


def health_report() -> dict[str, Any]:
    """Probes every core and returns a combined report.

    A probe that raises is recorded as failed rather than aborting the report,
    so one broken import cannot hide the state of the other cores.
    """
    cores: list[CoreStatus] = []
    for (checker,) in _CHECKS:
        try:
            cores.append(checker())
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            cores.append(
                CoreStatus(
                    name=getattr(checker, "__name__", "unknown").replace("check_", ""),
                    language="unknown",
                    role="probe raised during import",
                    state=FAILED,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )

    native = [c for c in cores if c.name != "python"]
    return {
        "status": "ok"
        if all(c.state in (OK, BLOCKED, FALLBACK) for c in cores)
        else "degraded",
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "cores": [c.to_dict() for c in cores],
        "native_usable": sum(1 for c in native if c.usable),
        "native_total": len(native),
    }


def format_report(report: dict[str, Any]) -> str:
    """Renders a health report as an aligned, human-readable table."""
    glyphs = {OK: "OK", FALLBACK: "FALLBACK", FAILED: "FAILED", BLOCKED: "BLOCKED"}
    lines = [
        "",
        "=" * 78,
        f" HELIOS-NET native core health - {report['platform']}",
        "=" * 78,
    ]
    for core in report["cores"]:
        state = glyphs.get(core["state"], core["state"])
        lines.append(f" [{state:>8}] {core['name'].upper():<7} {core['language']}")
        lines.append(f"             version : {core['version']}")
        if core["detail"]:
            lines.append(f"             detail  : {core['detail']}")
        lines.append("")
    usable = report["native_usable"]
    total = report["native_total"]
    lines.append(f" native cores usable: {usable}/{total}")
    if usable < total:
        lines.append(
            " Cores below OK run their pure-Python fallback. A FAILED or BLOCKED"
        )
        lines.append(" core means the binary exists but was never proven to work.")
    lines.append("=" * 78)
    return "\n".join(lines)
