<#
.SYNOPSIS
    Removes a per-user NetControl installation created by install.ps1.

.DESCRIPTION
    Deletes the Start Menu shortcuts, the "Installed apps" registration, and the
    install folder. Settings/diagnostics are kept unless -RemoveData is given.
#>
[CmdletBinding()]
param(
    [switch]$Quiet,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$AppName = 'NetControl'
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"

if (-not $Quiet) {
    $answer = Read-Host "Uninstall NetControl from $InstallDir ? [y/N]"
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; exit 1 }
}

$running = Get-Process -Name 'NetControl', 'NetControl-Demo' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
if ($running) { throw 'NetControl is running. Close it and try again.' }

# Resolve the data folder before the marker is deleted.
$Marker = Join-Path $InstallDir 'netcontrol.portable'
$DataDir = Join-Path $env:LOCALAPPDATA $AppName
if (Test-Path $Marker) {
    $line = (Get-Content $Marker | Select-Object -First 1)
    $DataDir = if ($line -and $line.Trim()) {
        if ([IO.Path]::IsPathRooted($line.Trim())) { $line.Trim() } else { Join-Path $InstallDir $line.Trim() }
    } else { Join-Path $InstallDir 'data' }
}

$StartMenu = Join-Path ([Environment]::GetFolderPath('Programs')) $AppName
if (Test-Path $StartMenu) { Remove-Item -Recurse -Force $StartMenu }
if (Test-Path $Key) { Remove-Item -Recurse -Force $Key }

if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host "Removed settings in $DataDir"
} else {
    Write-Host "Settings kept in $DataDir (use -RemoveData to delete them)."
}

# Only remove files this installer placed, then the folder if it is empty.
$Payload = @(
    'NetControl.exe', 'NetControl-Demo.exe', 'VERSION', 'LICENSE.txt', 'NOTICE.txt',
    'README.txt', 'INSTALL.md', 'CHANGELOG.md', 'app_icon.ico', 'netcontrol.portable'
)
foreach ($f in $Payload) {
    $p = Join-Path $InstallDir $f
    if (Test-Path $p) { Remove-Item -Force $p }
}

# This script is still running from the folder; remove it (and the folder, if
# empty) from a short-lived helper once this process exits.
$self = Join-Path $InstallDir 'uninstall.ps1'
$cleanup = "Start-Sleep -Seconds 2; Remove-Item -Force -LiteralPath '$self' -ErrorAction SilentlyContinue; " +
    "if (-not (Get-ChildItem -Force -LiteralPath '$InstallDir' -ErrorAction SilentlyContinue)) { Remove-Item -Force -LiteralPath '$InstallDir' }"
Start-Process -WindowStyle Hidden powershell.exe -ArgumentList '-NoProfile', '-Command', $cleanup

Write-Host 'NetControl was uninstalled.' -ForegroundColor Green
