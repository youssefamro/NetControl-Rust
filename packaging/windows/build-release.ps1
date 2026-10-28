<#
.SYNOPSIS
    Builds the NetControl Windows release: executables, portable ZIP, installer.

.DESCRIPTION
    1. Builds two optimized x64 executables with cargo:
         NetControl.exe       - Live-capable (passive capture via Npcap)
         NetControl-Demo.exe  - demonstration-only (no capture code, no Npcap)
    2. Stages them with the icon, license, notice, docs, and installer scripts
       in dist\NetControl-<ver>-windows-x64\.
    3. Creates dist\NetControl-<ver>-windows-x64-portable.zip (settings stored
       next to the executable via netcontrol.portable).
    4. Creates an installer:
         - Inno Setup 6 (ISCC.exe) if installed  -> ...-setup.exe
         - otherwise Windows' built-in IExpress   -> ...-user-setup.exe
           (wraps install.ps1: per-user install, Start Menu, uninstaller)
    5. Verifies the package contents and writes SHA256SUMS.txt.

    Building requires Rust (MSVC) and the Npcap SDK (Packet.lib; set
    NPCAP_SDK_DIR if it is not in a standard location). End users need neither.

.PARAMETER SkipBuild
    Reuse existing target\release binaries (must already match both editions).

.PARAMETER NoInstaller
    Skip the installer step.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$NoInstaller
)

$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
Set-Location $Root

$Version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$Name = "NetControl-$Version-windows-x64"
$Dist = Join-Path $Root 'dist'
$Stage = Join-Path $Dist $Name
$Zip = Join-Path $Dist "$Name-portable.zip"
$Exe = Join-Path $Root 'target\release\netcontrol-gui.exe'

function Invoke-Cargo([string]$cmdline) {
    Write-Host "`n> cargo $cmdline" -ForegroundColor Cyan
    $p = Start-Process -FilePath cargo -ArgumentList $cmdline -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "cargo $cmdline failed (exit $($p.ExitCode))" }
}

Write-Host "NetControl $Version - Windows release build" -ForegroundColor White
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

# ── 1. Executables ───────────────────────────────────────────────────
if (-not $SkipBuild) {
    Invoke-Cargo 'build --release -p netcontrol-gui'
}
Copy-Item $Exe (Join-Path $Stage 'NetControl-Demo.exe')
if (-not $SkipBuild) {
    Invoke-Cargo 'build --release -p netcontrol-gui --features live-capture'
}
Copy-Item $Exe (Join-Path $Stage 'NetControl.exe')

# ── 2. Assets and documents ─────────────────────────────────────────
Copy-Item 'crates\netcontrol-gui\assets\app_icon.ico' $Stage
Copy-Item 'LICENSE' (Join-Path $Stage 'LICENSE.txt')
Copy-Item 'NOTICE' (Join-Path $Stage 'NOTICE.txt')
Copy-Item 'docs\INSTALL.md' $Stage
Copy-Item 'CHANGELOG.md' $Stage
Copy-Item 'packaging\windows\README.txt' $Stage
Copy-Item 'packaging\windows\install.ps1' $Stage
Copy-Item 'packaging\windows\uninstall.ps1' $Stage
Set-Content -Path (Join-Path $Stage 'VERSION') -Value $Version -Encoding ASCII
# Portable mode: settings in .\data next to the executable.
Set-Content -Path (Join-Path $Stage 'netcontrol.portable') -Value '' -Encoding ASCII -NoNewline

# ── 3. Verify staged contents ───────────────────────────────────────
$Required = @(
    'NetControl.exe', 'NetControl-Demo.exe', 'app_icon.ico', 'LICENSE.txt', 'NOTICE.txt',
    'README.txt', 'INSTALL.md', 'CHANGELOG.md', 'VERSION', 'install.ps1', 'uninstall.ps1',
    'netcontrol.portable'
)
$missing = $Required | Where-Object { -not (Test-Path (Join-Path $Stage $_)) }
if ($missing) { throw "Staging incomplete, missing: $($missing -join ', ')" }

foreach ($bin in 'NetControl.exe', 'NetControl-Demo.exe') {
    $vi = (Get-Item (Join-Path $Stage $bin)).VersionInfo
    if ($vi.ProductName -ne 'NetControl' -or $vi.FileVersion -ne $Version) {
        Write-Warning "$bin version metadata is '$($vi.ProductName) $($vi.FileVersion)' (expected 'NetControl $Version'); was rc.exe found?"
    }
}

# ── 4. Portable ZIP ─────────────────────────────────────────────────
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $Zip -CompressionLevel Optimal
Add-Type -AssemblyName System.IO.Compression.FileSystem
$entries = [IO.Compression.ZipFile]::OpenRead($Zip)
try { $zipNames = $entries.Entries | ForEach-Object { $_.FullName } } finally { $entries.Dispose() }
$zipMissing = $Required | Where-Object { $zipNames -notcontains $_ }
if ($zipMissing) { throw "ZIP is missing: $($zipMissing -join ', ')" }
Write-Host "Portable ZIP: $Zip" -ForegroundColor Green

# ── 5. Installer ────────────────────────────────────────────────────
$Installer = $null
if (-not $NoInstaller) {
    $iscc = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | ForEach-Object Source),
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

    if ($iscc) {
        & $iscc "/DAppVersion=$Version" "/DStageDir=$Stage" "/O$Dist" 'packaging\windows\netcontrol.iss'
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed (exit $LASTEXITCODE)" }
        $Installer = Join-Path $Dist "$Name-setup.exe"
    } else {
        Write-Host 'Inno Setup not found; building the IExpress per-user installer instead.' -ForegroundColor Yellow
        $Installer = Join-Path $Dist "$Name-user-setup.exe"
        $Payload = @(
            'NetControl.exe', 'NetControl-Demo.exe', 'app_icon.ico', 'LICENSE.txt', 'NOTICE.txt',
            'README.txt', 'INSTALL.md', 'CHANGELOG.md', 'VERSION', 'install.ps1', 'uninstall.ps1'
        )
        $files = for ($i = 0; $i -lt $Payload.Count; $i++) { "FILE$i=`"$($Payload[$i])`"" }
        $refs = for ($i = 0; $i -lt $Payload.Count; $i++) { "%FILE$i%=" }
        $sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=Install NetControl $Version for the current user?
DisplayLicense=$Stage\LICENSE.txt
FinishMessage=
TargetName=$Installer
FriendlyName=NetControl $Version Setup
AppLaunched=cmd /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=cmd /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Quiet
UserQuietInstCmd=cmd /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Quiet
$($files -join "`r`n")
[SourceFiles]
SourceFiles0=$Stage\
[SourceFiles0]
$($refs -join "`r`n")
"@
        $sedPath = Join-Path $Root 'target\netcontrol-iexpress.sed'
        Set-Content -Path $sedPath -Value $sed -Encoding ASCII
        if (Test-Path $Installer) { Remove-Item -Force $Installer }
        $p = Start-Process -FilePath "$env:SystemRoot\System32\iexpress.exe" -ArgumentList '/N', '/Q', $sedPath -Wait -PassThru
        if ($p.ExitCode -ne 0 -or -not (Test-Path $Installer)) { throw "IExpress failed (exit $($p.ExitCode))" }
    }
    Write-Host "Installer:    $Installer" -ForegroundColor Green
}

# ── 6. Checksums ────────────────────────────────────────────────────
$artifacts = @($Zip) + @($Installer | Where-Object { $_ })
$sums = foreach ($a in $artifacts) {
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $a).Hash.ToLower(), (Split-Path -Leaf $a)
}
Set-Content -Path (Join-Path $Dist 'SHA256SUMS.txt') -Value $sums -Encoding ASCII

Write-Host "`nRelease artifacts in $Dist" -ForegroundColor White
Get-ChildItem $Dist -File | Format-Table Name, Length -AutoSize
