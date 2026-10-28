<#
.SYNOPSIS
    Installs NetControl for the current user (no administrator rights needed).

.DESCRIPTION
    Copies the application from this folder to the install directory, creates
    Start Menu shortcuts, and registers an uninstaller under
    "Apps > Installed apps" (HKCU). Used by NetControl-<ver>-setup.exe and can
    also be run directly from an extracted release folder.

    NetControl itself does not need administrator rights in Demonstration mode.
    Live capture needs the Npcap runtime and, if Npcap was installed in
    "administrator-only" mode, running NetControl as Administrator (a Start Menu
    shortcut for that is created).

.PARAMETER InstallDir
    Where to install. Default: %LOCALAPPDATA%\Programs\NetControl.

.PARAMETER DataDir
    Where settings and diagnostics are stored. Default: %LOCALAPPDATA%\NetControl.
    When set, a netcontrol.portable marker pointing at it is written next to the
    executable.

.PARAMETER Quiet
    Do not prompt; use defaults/parameters.

.PARAMETER NoShortcuts
    Skip Start Menu shortcuts (used for testing).
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$DataDir,
    [switch]$Quiet,
    [switch]$NoShortcuts
)

$ErrorActionPreference = 'Stop'
$AppName = 'NetControl'
$Source = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version = (Get-Content (Join-Path $Source 'VERSION') -ErrorAction SilentlyContinue | Select-Object -First 1)
if (-not $Version) { $Version = '0.0.0' }

$DefaultInstall = Join-Path $env:LOCALAPPDATA "Programs\$AppName"
$DefaultData = Join-Path $env:LOCALAPPDATA $AppName

Write-Host "NetControl $Version - per-user installer" -ForegroundColor Cyan

if (-not $InstallDir) {
    $InstallDir = $DefaultInstall
    if (-not $Quiet) {
        $answer = Read-Host "Install folder [$DefaultInstall]"
        if ($answer.Trim()) { $InstallDir = $answer.Trim() }
    }
}
if (-not $DataDir -and -not $Quiet) {
    $answer = Read-Host "Settings/diagnostics folder [$DefaultData]"
    if ($answer.Trim()) { $DataDir = $answer.Trim() }
}

$Payload = @(
    'NetControl.exe', 'NetControl-Demo.exe', 'uninstall.ps1', 'VERSION',
    'LICENSE.txt', 'NOTICE.txt', 'README.txt', 'INSTALL.md', 'CHANGELOG.md', 'app_icon.ico'
)
foreach ($f in $Payload) {
    if (-not (Test-Path (Join-Path $Source $f))) { throw "Installer payload is incomplete: missing $f" }
}

# Refuse to install over a running copy.
$running = Get-Process -Name 'NetControl', 'NetControl-Demo' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) }
if ($running) { throw "NetControl is running from $InstallDir. Close it and run the installer again." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($f in $Payload) { Copy-Item -Force (Join-Path $Source $f) (Join-Path $InstallDir $f) }

$Marker = Join-Path $InstallDir 'netcontrol.portable'
if ($DataDir) {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    Set-Content -Path $Marker -Value $DataDir -Encoding ASCII
} elseif (Test-Path $Marker) {
    Remove-Item -Force $Marker
}
$EffectiveData = if ($DataDir) { $DataDir } else { $DefaultData }

$Exe = Join-Path $InstallDir 'NetControl.exe'
$Icon = Join-Path $InstallDir 'app_icon.ico'
$StartMenu = Join-Path ([Environment]::GetFolderPath('Programs')) $AppName

function New-Shortcut($path, $target, $arguments, $description, [switch]$RunAsAdmin) {
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($path)
    $lnk.TargetPath = $target
    if ($arguments) { $lnk.Arguments = $arguments }
    $lnk.WorkingDirectory = $InstallDir
    $lnk.IconLocation = "$Icon,0"
    $lnk.Description = $description
    $lnk.Save()
    if ($RunAsAdmin) {
        # Set SLDF_RUNAS_USER (byte 0x15, bit 0x20) in the .lnk header.
        $bytes = [IO.File]::ReadAllBytes($path)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [IO.File]::WriteAllBytes($path, $bytes)
    }
}

if (-not $NoShortcuts) {
    New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
    New-Shortcut (Join-Path $StartMenu 'NetControl.lnk') $Exe '' 'NetControl - Network Traffic Management'
    New-Shortcut (Join-Path $StartMenu 'NetControl (Administrator).lnk') $Exe '' 'NetControl with administrator rights (for Live capture)' -RunAsAdmin
    New-Shortcut (Join-Path $StartMenu 'NetControl Demo (no capture).lnk') (Join-Path $InstallDir 'NetControl-Demo.exe') '' 'NetControl demonstration-only build'
    New-Shortcut (Join-Path $StartMenu 'Uninstall NetControl.lnk') 'powershell.exe' "-NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`"" 'Uninstall NetControl'
}

# Register in Apps > Installed apps (per-user).
$Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"
New-Item -Force -Path $Key | Out-Null
$size = [int]((Get-ChildItem $InstallDir -File | Measure-Object Length -Sum).Sum / 1KB)
$props = @{
    DisplayName          = $AppName
    DisplayVersion       = $Version
    Publisher            = 'NetControl Rust rebuild contributors'
    InstallLocation      = $InstallDir
    DisplayIcon          = $Icon
    UninstallString      = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
    QuietUninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`" -Quiet"
    URLInfoAbout         = 'https://npcap.com/'
}
foreach ($k in $props.Keys) { Set-ItemProperty -Path $Key -Name $k -Value $props[$k] }
Set-ItemProperty -Path $Key -Name NoModify -Value 1 -Type DWord
Set-ItemProperty -Path $Key -Name NoRepair -Value 1 -Type DWord
Set-ItemProperty -Path $Key -Name EstimatedSize -Value $size -Type DWord

Write-Host "Installed to   $InstallDir" -ForegroundColor Green
Write-Host "Settings in    $EffectiveData"

# Npcap runtime check (needed only for Live capture).
$sys = Join-Path $env:SystemRoot 'System32'
if (Test-Path (Join-Path $sys 'Npcap\Packet.dll')) {
    Write-Host 'Npcap runtime: found.' -ForegroundColor Green
} elseif (Test-Path (Join-Path $sys 'Packet.dll')) {
    Write-Host 'Capture runtime: a WinPcap-compatible Packet.dll was found. Npcap (https://npcap.com/) is recommended.' -ForegroundColor Yellow
} else {
    Write-Host 'Npcap runtime: NOT found. Demonstration mode works; for Live capture install Npcap from https://npcap.com/' -ForegroundColor Yellow
}

if (-not $Quiet) { Read-Host 'Press Enter to close' | Out-Null }
