@echo off
setlocal
set "HELIOS_ROOT=%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo [HELIOS] Python was not found on PATH. Install Python 3.12 or add it to PATH.
    exit /b 9009
)

python "%HELIOS_ROOT%run.py" %*
exit /b %ERRORLEVEL%
