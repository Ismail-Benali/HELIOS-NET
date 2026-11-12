@echo off
setlocal
set "HELIOS_ROOT=%~dp0"
set "HELIOS_PYTHON="

rem Prefer the python command only when it is Python 3.12 or newer.
where python >nul 2>&1
if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
    if not errorlevel 1 set "HELIOS_PYTHON=python"
)

rem Fall back to the Windows Python Launcher and request Python 3.12 explicitly.
if not defined HELIOS_PYTHON (
    where py >nul 2>&1
    if not errorlevel 1 (
        py -3.12 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1
        if not errorlevel 1 set "HELIOS_PYTHON=py -3.12"
    )
)

if not defined HELIOS_PYTHON (
    echo [HELIOS] Python 3.12 or newer was not found.
    echo [HELIOS] Install Python 3.12+ and enable the Python Launcher or add Python to PATH.
    exit /b 9009
)

%HELIOS_PYTHON% "%HELIOS_ROOT%run.py" %*
exit /b %ERRORLEVEL%
