"""HELIOS-NET :: main entry point.

Run from the project root:
    python run.py recon --target example.test
    python run.py judge --target example.test
    python run.py recover <campaign_id>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
