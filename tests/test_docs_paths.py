"""Documentation guard: documented links and paths must exist in the tree.

README and the root ARCHITECTURE.md previously described transport components
that had been removed, and two architecture documents disagreed with each
other. These tests fail when the documentation drifts from the repository
again, so the fix cannot silently rot.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]

MARKDOWN_DOCUMENTS = (
    ROOT / "README.md",
    ROOT / "ARCHITECTURE.md",
    ROOT / "ROADMAP.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "CHANGELOG.md",
    *sorted((ROOT / "docs").glob("*.md")),
    *sorted((ROOT / ".github").glob("*.md")),
)

# CHANGELOG.md must name the components it removed, so it is excluded from the
# stale-reference scan while still checked for links.
CURRENT_STATE_DOCUMENTS = tuple(
    document for document in MARKDOWN_DOCUMENTS if document.name != "CHANGELOG.md"
)

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "#", "/")

DOCUMENTED_PATHS = (
    "run.py",
    "run_simulation.py",
    "build.py",
    "helios.cmd",
    "requirements-dev.txt",
    "config/scope.yaml",
    "core/scope.py",
    "core/wal.py",
    "core/accel.py",
    "core/native_contract.py",
    "core/cores.py",
    "core/reporter_html.py",
    "core/reporter_interactive.py",
    "core/paths.py",
    "pyproject.toml",
    "install.sh",
    "install.ps1",
    "engine/graph",
    "engine/killchain/pathfinder.py",
    "engine/risk.py",
    "engine/verdict.py",
    "modules/discovery",
    "modules/recon",
    "modules/ingest/nmap.py",
    "modules/stealth/pacer.py",
    "modules/exfil/collector.py",
    "transport/goscan",
    "transport/c_core",
    "rust-core",
    "tools/bench.py",
    "tools/bench_scan.py",
    "tools/gen_c_reference.py",
    "tests/test_end_to_end.py",
    "tests/smoke.py",
    "docs/QUICKSTART.md",
    "docs/Architecture.md",
    "docs/API.md",
    "docs/SCOPE-ENFORCEMENT.md",
    "docs/IPC-CONTRACT.md",
    "docs/ASSET-GRAPH.md",
    "docs/RISK-SCORING.md",
    "docs/BENCHMARKS.md",
    "CHANGELOG.md",
    ".github/workflows/build.yml",
    ".github/workflows/lint.yml",
    ".github/workflows/docker.yml",
)

REMOVED_COMPONENT_TOKENS = (
    "rawsync",
    "rawsocket",
    "covert.go",
    "raft.go",
    "evasion.exe",
    "direct_syscalls",
    "memory_loader",
    "mutation_engine",
    "c_loader",
)


def _relative_links(document: Path) -> list[str]:
    text = document.read_text(encoding="utf-8")
    targets: list[str] = []
    for raw in LINK.findall(text):
        target = raw.strip()
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        target = target.split('"', 1)[0].strip()
        if not target or target.startswith(EXTERNAL_PREFIXES):
            continue
        target = unquote(target.split("#", 1)[0]).split("?", 1)[0]
        if target:
            targets.append(target)
    return targets


@pytest.mark.parametrize(
    "document", MARKDOWN_DOCUMENTS, ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_relative_markdown_links_exist(document: Path) -> None:
    missing = [
        target
        for target in _relative_links(document)
        if not (document.parent / target).exists()
    ]
    assert missing == [], (
        f"{document.relative_to(ROOT).as_posix()} links to missing paths: {missing}"
    )


@pytest.mark.parametrize("relative", DOCUMENTED_PATHS)
def test_documented_component_paths_exist(relative: str) -> None:
    assert (ROOT / relative).exists(), (
        f"documentation references missing path: {relative}"
    )


@pytest.mark.parametrize("token", REMOVED_COMPONENT_TOKENS)
def test_removed_components_are_not_documented(token: str) -> None:
    offenders = [
        document.relative_to(ROOT).as_posix()
        for document in CURRENT_STATE_DOCUMENTS
        if token in document.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"{token!r} belongs to removed code but is still advertised in {offenders}"
    )


def test_root_architecture_points_to_the_canonical_document() -> None:
    text = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "docs/Architecture.md" in text
    assert len(text.splitlines()) <= 30, "keep one canonical architecture document"
