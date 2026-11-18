"""Marks a wheel that carries native cores as platform-specific.

Everything else lives in ``pyproject.toml``. This file exists for two reasons:

* A package without extension modules is tagged ``py3-none-any`` even when
  ``core/native/`` contains a Windows DLL or a Linux shared object. Such a
  wheel installs everywhere and lies about what it contains.
* Building a wheel from a checkout that already contains built cores should not
  require a second command, so ``build_py`` copies them into the package.

When native artifacts exist the wheel keeps the ``py3``/``none`` pair, because
the Python code is version-independent, and takes the platform tag of the
machine that built it. A checkout with no cores still produces a pure wheel that
reports the Python fallback.
"""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

try:
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:  # pragma: no cover - older setuptools
    try:
        from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
    except ImportError:
        _bdist_wheel = None

_ROOT = Path(__file__).resolve().parent
_NATIVE_DIR = _ROOT / "core" / "native"
_NATIVE_SUFFIXES = {".dll", ".exe", ".so", ".dylib"}


def _bundler() -> ModuleType | None:
    script = _ROOT / "tools" / "bundle_cores.py"
    if not script.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("helios_bundle_cores", script)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        # dataclasses resolves annotations through sys.modules, so the module
        # must be registered before it executes.
        sys.modules["helios_bundle_cores"] = module
        spec.loader.exec_module(module)
        return module
    except Exception:  # pragma: no cover - packaging must not fail here
        return None


def _has_native_artifacts() -> bool:
    if _NATIVE_DIR.is_dir() and any(
        path.is_file() and path.suffix.lower() in _NATIVE_SUFFIXES
        for path in _NATIVE_DIR.iterdir()
    ):
        return True
    module = _bundler()
    if module is None:
        return False
    try:
        return any(module.candidate_artifacts(_ROOT).as_dict().values())
    except Exception:  # pragma: no cover
        return False


def _synchronize_bundled_cores(destination: Path) -> None:
    """Copies cores already built in this checkout into the build tree."""
    module = _bundler()
    if module is None:
        return
    try:
        if not any(module.candidate_artifacts(_ROOT).as_dict().values()):
            return
        copied = module.bundle(_ROOT, destination)
        print(
            f"[helios] bundled {len(copied)} native core artifact(s) into the wheel",
            file=sys.stderr,
        )
    except Exception as exc:  # pragma: no cover - packaging must not fail here
        print(f"[helios] native cores were not bundled: {exc}", file=sys.stderr)


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        _synchronize_bundled_cores(Path(self.build_lib) / "core" / "native")


def _cmdclass() -> dict[str, type]:
    commands: dict[str, type] = {"build_py": build_py}
    if _bdist_wheel is None:
        return commands

    class bdist_wheel(_bdist_wheel):
        def finalize_options(self) -> None:
            super().finalize_options()
            self.root_is_pure = not _has_native_artifacts()

        def get_tag(self) -> tuple[str, str, str]:
            python, abi, platform = super().get_tag()
            if _has_native_artifacts():
                return "py3", "none", platform
            return python, abi, platform

    commands["bdist_wheel"] = bdist_wheel
    return commands


setup(cmdclass=_cmdclass())
