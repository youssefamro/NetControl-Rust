; Inno Setup 6 script for NetControl.
;
; Built by packaging\windows\build-release.ps1 when ISCC.exe (Inno Setup 6) is
; installed; that script passes /DAppVersion and /DStageDir. Manual build:
;   ISCC.exe /DAppVersion=0.1.0 /DStageDir=..\..\dist\NetControl-0.1.0-windows-x64 /O..\..\dist packaging\windows\netcontrol.iss
;
; Installs per-user by default (no UAC prompt); the user may choose an
; all-users install. NetControl itself runs as the invoking user; a Start Menu
; shortcut runs it as Administrator for Live capture with admin-only Npcap.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef StageDir
  #define StageDir "..\..\dist\NetControl-" + AppVersion + "-windows-x64"
#endif

[Setup]
AppId={{6E1C9B47-4F0B-4C55-9C1E-7A9D2E3B5F10}
AppName=NetControl
AppVersion={#AppVersion}
AppVerName=NetControl {#AppVersion}
AppPublisher=NetControl Rust rebuild contributors
AppSupportURL=https://npcap.com/
DefaultDirName={autopf}\NetControl
DefaultGroupName=NetControl
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=NetControl-{#AppVersion}-windows-x64-setup
SetupIconFile={#StageDir}\app_icon.ico
UninstallDisplayIcon={app}\NetControl.exe
LicenseFile={#StageDir}\LICENSE.txt
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#StageDir}\NetControl.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\NetControl-Demo.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\app_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\NOTICE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "{#StageDir}\INSTALL.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\VERSION"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NetControl"; Filename: "{app}\NetControl.exe"; IconFilename: "{app}\app_icon.ico"
Name: "{group}\NetControl Demo (no capture)"; Filename: "{app}\NetControl-Demo.exe"; IconFilename: "{app}\app_icon.ico"
Name: "{group}\Uninstall NetControl"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\NetControl.exe"; Description: "Launch NetControl"; Flags: nowait postinstall skipifsilent unchecked

[Code]
var
  DataPage: TInputDirWizardPage;

function NpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\Packet.dll'))
    or RegKeyExists(HKLM, 'SOFTWARE\Npcap');
end;

procedure InitializeWizard;
begin
  DataPage := CreateInputDirPage(wpSelectDir,
    'Settings location', 'Where should NetControl keep its settings and diagnostics?',
    'NetControl stores a small config.ini and netcontrol.log here. Click Next to accept.',
    False, '');
  DataPage.Add('');
  DataPage.Values[0] := ExpandConstant('{localappdata}\NetControl');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { Only write a marker when the user moved the data folder. }
    if CompareText(DataPage.Values[0], ExpandConstant('{localappdata}\NetControl')) <> 0 then
    begin
      ForceDirectories(DataPage.Values[0]);
      SaveStringToFile(ExpandConstant('{app}\netcontrol.portable'), DataPage.Values[0], False);
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and not NpcapInstalled then
    MsgBox('Npcap was not detected.' #13#10#13#10 +
      'Demonstration mode works without it. To use Live capture, install Npcap from ' +
      'https://npcap.com/ and restart NetControl.', mbInformation, MB_OK);
end;

[UninstallDelete]
Type: files; Name: "{app}\netcontrol.portable"
