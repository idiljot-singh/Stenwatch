; Stenwatch 0.2 (C# edition) installer. Build with build-cs.bat (needs the .NET 8 SDK and Inno Setup 6).
; Per-user install: no admin rights. Self-contained: the .NET runtime is included, nothing else to install.
[Setup]
AppId={{6C2D9B6E-3F0A-4B7D-9A51-2E8C1D7F4A90}
AppName=Stenwatch 0.2 (C# edition)
AppVersion=0.2.0-beta
AppVerName=Stenwatch 0.2.0 beta
AppPublisher=Diljot Singh Johal
AppPublisherURL=https://github.com/idiljot-singh/Stenwatch
AppCopyright=Copyright (c) 2026 Diljot Singh Johal
VersionInfoVersion=0.2.0.0
DefaultDirName={autopf}\Stenwatch2
DefaultGroupName=Stenwatch
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=Stenwatch-Setup-0.2.0-beta
SetupIconFile=..\src\Stenwatch.App\stenwatch.ico
UninstallDisplayIcon={app}\Stenwatch.exe
UninstallDisplayName=Stenwatch 0.2 (C# edition)
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
InfoBeforeFile=readme-before.txt

[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"

[Files]
Source: "..\dist\StenwatchCS\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Stenwatch"; Filename: "{app}\Stenwatch.exe"
Name: "{group}\Stenwatch documentation"; Filename: "{app}\docs"
Name: "{group}\Stenwatch data folder"; Filename: "{userappdata}\Stenwatch"
Name: "{autodesktop}\Stenwatch"; Filename: "{app}\Stenwatch.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Stenwatch.exe"; Description: "Start Stenwatch"; Flags: nowait postinstall skipifsilent

[Dirs]
Name: "{userappdata}\Stenwatch"

[Code]
// Updating or uninstalling never touches your data unless you agree. The data folder is shared with the Python version.
procedure CurUninstallStepChanged(Step: TUninstallStep);
begin
  if (Step = usPostUninstall) and not UninstallSilent() and
     (MsgBox('Also delete your Stenwatch data (profile, asset lists, downloaded feeds, history and reports)?' + #13#10 + 'The folder is shared with the Python version of Stenwatch.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
    DelTree(ExpandConstant('{userappdata}\Stenwatch'), True, True, True);
end;
