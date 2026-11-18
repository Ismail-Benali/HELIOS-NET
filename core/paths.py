"""Where HELIOS-NET keeps its data, inside a checkout or after installation.

The repository root is the directory that contains ``run.py``. A wheel install
has no ``run.py``, so it must not write campaign state into site-packages:
installed runs use ``~/.helios-net`` unless ``HELIOS_DATA`` names another
directory.
"""

from __future__ import annotations

import os
from pathlib import Path

DATA_ENV_VAR = "HELIOS_DATA"


def repo_root() -> Path:
    """The checkout root, derived from this module's location."""
    return Path(__file__).resolve().parents[1]


def running_from_source() -> bool:
    """True when the CLI runs from a checkout rather than an installed wheel."""
    return (repo_root() / "run.py").is_file()


def default_data_dir() -> Path:
    """Writable campaign-data directory for this run."""
    override = os.environ.get(DATA_ENV_VAR)
    if override:
        return Path(override).expanduser()
    root = repo_root()
    if running_from_source():
        return root / "data"
    return Path.home() / ".helios-net"
