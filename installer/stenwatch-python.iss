; Build with build.bat (needs Inno Setup 6). Per-user install: no admin rights.
[Setup]
AppId={{054F2F7D-953D-4259-BA02-7657BA7ECB83}
AppName=Stenwatch
AppVersion=0.1.0-beta
AppPublisher=Diljot Singh Johal
AppPublisherURL=https://github.com/idiljot-singh/Stenwatch
AppCopyright=Copyright (c) 2026 Diljot Singh Johal
DefaultDirName={autopf}\Stenwatch
DefaultGroupName=Stenwatch
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=Stenwatch-Setup-0.1.0-beta
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=Stenwatch

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"

[Files]
Source: "..\dist\Stenwatch\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Stenwatch"; Filename: "{app}\Stenwatch.exe"
Name: "{autodesktop}\Stenwatch"; Filename: "{app}\Stenwatch.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Stenwatch.exe"; Description: "Start Stenwatch"; Flags: nowait postinstall skipifsilent

[Code]
// Updating or uninstalling never touches the user's data unless they agree.
procedure CurUninstallStepChanged(Step: TUninstallStep);
begin
  if (Step = usPostUninstall) and not UninstallSilent() and
     (MsgBox('Also delete your Stenwatch data (profile, asset lists, downloaded feeds and reports)?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
    DelTree(ExpandConstant('{userappdata}\Stenwatch'), True, True, True);
end;
