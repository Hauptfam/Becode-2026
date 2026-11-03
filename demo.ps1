<#
.SYNOPSIS
    Interview demo: the Paper Lantern incident through ioc-enricher, mini-siem and mini-soar.

.DESCRIPTION
    First run: creates a .venv folder and installs the three projects (about a minute).
    Then plays the five demo steps from WALKTHROUGH.md, pausing between steps so you can talk.

.EXAMPLE
    .\demo.ps1
    .\demo.ps1 -Name mateo
    .\demo.ps1 -NoPause            # rehearsal: run straight through
    .\demo.ps1 -Setup              # reinstall the projects (after a git pull)

.NOTES
    If PowerShell refuses to run scripts:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
    or run it once with:
        powershell -ExecutionPolicy Bypass -File .\demo.ps1
#>
param(
    [string]$Name = "analyst",
    [int]$Port = 5000,
    [switch]$NoPause,
    [switch]$NoBrowser,
    [switch]$SkipTests,
    [switch]$Setup
)

Set-Location -Path $PSScriptRoot
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

# 1. Virtual environment
if (-not (Test-Path $python)) {
    Write-Host "Creating the virtual environment (.venv)..." -ForegroundColor Cyan
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv .venv
    } else {
        & python -m venv .venv
    }
    if (-not (Test-Path $python)) {
        Write-Host "Could not create .venv. Is Python 3.10+ installed and on PATH?" -ForegroundColor Red
        exit 1
    }
    $Setup = $true
}

# 2. Install the projects (first run, -Setup, or when something is missing)
if (-not $Setup) {
    & $python -c "import ioc_enricher, mini_siem, mini_soar, pytest" *> $null
    if ($LASTEXITCODE -ne 0) { $Setup = $true }
}
if ($Setup) {
    Write-Host "Installing ioc-enricher, mini-siem and mini-soar (about a minute)..." -ForegroundColor Cyan
    & $python -m pip install --disable-pip-version-check --quiet -e .\ioc-enricher -e .\mini-siem -e ".\mini-soar[dev]"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installation failed: see the messages above." -ForegroundColor Red
        exit 1
    }
}

# 3. Run the demo
$demoArgs = @("--name", $Name, "--port", "$Port")
if ($NoPause)   { $demoArgs += "--no-pause" }
if ($NoBrowser) { $demoArgs += "--no-browser" }
if ($SkipTests) { $demoArgs += "--skip-tests" }

& $python (Join-Path $PSScriptRoot "demo.py") @demoArgs
exit $LASTEXITCODE
