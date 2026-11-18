# One-command install for HELIOS-NET from a checkout.
#
#   .\install.ps1
#
# Prefers pipx so the CLI lives in its own environment. Falls back to a user
# install. Run it from the repository root; it installs the current checkout.
[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

$launcher = Get-Command $Python -ErrorAction SilentlyContinue
if (-not $launcher) {
    Write-Error "$Python was not found; install Python 3.12 or newer (py -3.12 -m pip ...)."
    exit 1
}

& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python 3.12 or newer is required."
    exit 1
}

$pipx = Get-Command pipx -ErrorAction SilentlyContinue
if ($pipx) {
    Write-Host "installing with pipx..."
    & pipx install --force .
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pipx install failed."
        exit $LASTEXITCODE
    }
}
else {
    Write-Host "pipx was not found; installing into the user site with pip..."
    & $Python -m pip install --user --upgrade .
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pip install failed. Install pipx or use: $Python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install ."
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "installed. Next:"
Write-Host "  helios version"
Write-Host "  helios init"
Write-Host "  helios doctor"
Write-Host ""
Write-Host "Installed runs keep campaign state in $HOME\.helios-net (override with HELIOS_DATA)."
