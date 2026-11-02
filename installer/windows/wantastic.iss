; Wantastic setup wizard (Inno Setup 6). Built in CI per architecture:
;   iscc /DAppVersion=1.0.61 /DArch=amd64 /DSourceDir=<folder with wantasticd.exe> wantastic.iss
; It installs to the same place as install.ps1 (Program Files\Wantastic), so
; either can upgrade or remove the other's install, and the agent's
; self-update keeps working.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Arch
  #define Arch "amd64"
#endif
#ifndef SourceDir
  #define SourceDir "dist"
#endif

#if Arch == "arm64"
  #define ArchAllowed "arm64"
#else
  #define ArchAllowed "x64compatible"
#endif

[Setup]
AppId={{8C1B2F64-5A3E-4D2B-9C1E-7A6F0E3D9B21}
AppName=Wantastic
AppVersion={#AppVersion}
AppVerName=Wantastic {#AppVersion}
AppPublisher=Wantastic LLC
AppPublisherURL=https://wantastic.app
AppSupportURL=https://wantastic.app
AppCopyright=Copyright (c) Wantastic LLC
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\Wantastic
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed={#ArchAllowed}
ArchitecturesInstallIn64BitMode={#ArchAllowed}
MinVersion=10.0
WizardStyle=modern
WizardSizePercent=110
WizardImageFile=wizard.bmp,wizard-2x.bmp
WizardSmallImageFile=wizard-small.bmp,wizard-small-2x.bmp
SetupIconFile=wantastic.ico
UninstallDisplayIcon={app}\wantasticd.exe
UninstallDisplayName=Wantastic
LicenseFile=license.txt
ChangesEnvironment=yes
CloseApplications=no
Compression=lzma2/max
SolidCompression=yes
OutputDir=output
OutputBaseFilename=wantastic-setup-windows-{#Arch}

[Messages]
WelcomeLabel1=Welcome to Wantastic
WelcomeLabel2=This installs Wantastic {#AppVersion}, the secure overlay network agent, as a Windows service with a tray app.%n%nAfter setup, click Log in in the tray (or on the last page) to add this PC to your account. No password or code is needed here.
FinishedHeadingLabel=Wantastic is installed
FinishedLabelNoIcons=The Wantastic service is running and starts with Windows. Its icon is in the notification area.
FinishedLabel=The Wantastic service is running and starts with Windows. Its icon is in the notification area.

[Files]
Source: "{#SourceDir}\wantasticd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Registers or repairs the service, firewall rules, recovery and tray, then
; starts it; it returns once `wantasticd status` can reach the agent.
Filename: "{app}\wantasticd.exe"; Parameters: "service install --config ""{commonappdata}\Wantastic\config.conf"""; \
  StatusMsg: "Starting the Wantastic service..."; Flags: runhidden waituntilterminated
Filename: "{app}\wantasticd.exe"; Parameters: "open-login"; Description: "Log in to Wantastic now (opens your browser)"; \
  Flags: postinstall runasoriginaluser runhidden nowait skipifsilent; Check: NotSignedIn

[UninstallRun]
Filename: "{app}\wantasticd.exe"; Parameters: "service uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM wantasticd.exe"; Flags: runhidden waituntilterminated; RunOnceId: "StopTray"

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function NotSignedIn: Boolean;
begin
  Result := not FileExists(ExpandConstant('{commonappdata}\Wantastic\config.conf'));
end;

// Stop the running service and tray apps so their files can be replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Exe: String;
begin
  Result := '';
  Exe := ExpandConstant('{app}\wantasticd.exe');
  if FileExists(Exe) then
    Exec(Exe, 'service stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM wantasticd.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PathHasDir(Path, Dir: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Path, Dir: String;
begin
  if CurStep <> ssPostInstall then
    exit;
  Dir := ExpandConstant('{app}');
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Path) then
    Path := '';
  if not PathHasDir(Path, Dir) and not PathHasDir(Path, Dir + '\') then
  begin
    if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then
      Path := Path + ';';
    RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Path + Dir);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path, Dir: String;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  Dir := ExpandConstant('{app}');
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', Path) then
    exit;
  Path := ';' + Path + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Path));
  if P = 0 then
    P := Pos(';' + Uppercase(Dir) + '\;', Uppercase(Path));
  if P = 0 then
    exit;
  Delete(Path, P, Length(Dir) + 1);
  if Copy(Path, P, 1) = '\' then
    Delete(Path, P, 1);
  Path := Copy(Path, 2, Length(Path) - 2);
  RegWriteExpandStringValue(HKLM, EnvKey, 'Path', Path);
end;
