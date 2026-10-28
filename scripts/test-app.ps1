<#
.SYNOPSIS
    One-command application testing workflow for NetControl-Rust.

.DESCRIPTION
    Runs formatting checks, the full workspace test suite, Clippy (warnings as
    errors) and the build. If every stage passes, it launches the GUI in
    Demonstration mode for manual testing. Diagnostic logs are written to a
    gitignored directory on D:.

    This script never starts live packet capture or any network operation on its
    own. Use -Live to build/launch the opt-in live-capture binary; even then it
    only *launches* the GUI (which starts in Demonstration mode) and never begins
    capture automatically.

.PARAMETER NoLaunch
    Run all checks but do not launch the GUI.

.PARAMETER Live
    Build/launch the opt-in live-capture binary (requires Npcap). The GUI still
    starts in Demonstration mode; live capture must be started manually.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\test-app.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\test-app.ps1 -NoLaunch
#>
[CmdletBinding()]
param(
    [switch]$NoLaunch,
    [switch]$Live
)

# Resolve the workspace root (parent of this script's directory).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root

# Diagnostics directory on D: (gitignored).
$DiagDir = Join-Path $Root 'diagnostics'
New-Item -ItemType Directory -Force -Path $DiagDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $DiagDir "test-app-$Stamp.log"

function Write-Log($text) {
    Write-Host $text
    Add-Content -Path $LogFile -Value $text
}

# Runs a native command line via cmd.exe so that tool stderr (which cargo uses
# for normal progress output) is merged as plain text and only the exit code
# determines success/failure.
function Invoke-Stage($name, $cmdline) {
    Write-Host "`n=== $name ===" -ForegroundColor Cyan
    Add-Content -Path $LogFile -Value "`n=== $name ==="
    Add-Content -Path $LogFile -Value "`$ $cmdline"
    $output = cmd /c "$cmdline 2>&1"
    $output | ForEach-Object { Write-Host $_ }
    Add-Content -Path $LogFile -Value ($output -join "`r`n")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $name (exit $LASTEXITCODE). See $LogFile" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "OK: $name" -ForegroundColor Green
}

Write-Host 'NetControl-Rust application test workflow' -ForegroundColor White
Write-Host "Log: $LogFile"
Add-Content -Path $LogFile -Value "NetControl-Rust test-app run $Stamp"

Invoke-Stage '1/4 Formatting' 'cargo fmt --all --check'
Invoke-Stage '2/4 Unit tests' 'cargo test --workspace'
Invoke-Stage '3/4 Clippy (warnings as errors)' 'cargo clippy --workspace --all-targets -- -D warnings'

if ($Live) {
    Invoke-Stage '4/4 Build (live-capture)' 'cargo build --release -p netcontrol-gui --features live-capture'
} else {
    Invoke-Stage '4/4 Build' 'cargo build --release -p netcontrol-gui'
}

Write-Host "`nAll checks passed." -ForegroundColor Green
Add-Content -Path $LogFile -Value 'All checks passed.'

if ($NoLaunch) {
    Write-Host 'Skipping GUI launch (-NoLaunch).'
    exit 0
}

$Exe = Join-Path $Root 'target\release\netcontrol-gui.exe'
if (-not (Test-Path $Exe)) {
    Write-Host "GUI executable not found at $Exe" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Launching GUI (Demonstration mode) for MANUAL testing ===" -ForegroundColor Cyan
Write-Host 'The app starts in Demonstration mode. Live capture is never started automatically.'
if ($Live) {
    Write-Host 'Live-capture build: to test Live mode, switch to Live and press Start yourself (needs Npcap + admin).' -ForegroundColor Yellow
}
Write-Host 'NOTE: GUI interactions are performed manually and are NOT automatically verified by this script.' -ForegroundColor Yellow

# Keep app config/diagnostics on D:.
$env:NETCONTROL_DATA_DIR = Join-Path $Root '.appdata'
& $Exe
exit $LASTEXITCODE
