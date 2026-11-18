#!/usr/bin/env sh
# One-command install for HELIOS-NET from a checkout.
#
#   sh install.sh
#
# Prefers pipx so the CLI lives in its own environment and does not leak into
# your global site-packages. Falls back to a user install. Run it from the
# repository root; it installs the current checkout, not PyPI.
set -eu

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: $PYTHON was not found; install Python 3.12 or newer" >&2
    exit 1
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
    echo "error: Python 3.12 or newer is required" >&2
    exit 1
fi

if command -v pipx >/dev/null 2>&1; then
    echo "installing with pipx..."
    pipx install --force .
else
    echo "pipx was not found; installing into the user site with pip..."
    "$PYTHON" -m pip install --user --upgrade . || {
        echo "error: pip refused the install." >&2
        echo "Install pipx (https://pipx.pypa.io) or use a virtual environment:" >&2
        echo "  $PYTHON -m venv .venv && . .venv/bin/activate && pip install ." >&2
        exit 1
    }
fi

echo
echo "installed. Next:"
echo "  helios version"
echo "  helios init"
echo "  helios doctor"
echo
echo "Installed runs keep campaign state in ~/.helios-net (override with HELIOS_DATA)."
