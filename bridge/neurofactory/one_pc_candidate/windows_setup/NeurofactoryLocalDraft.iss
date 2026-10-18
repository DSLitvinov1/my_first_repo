#ifndef SourceRoot
  #error SourceRoot must point to staged immutable distribution
#endif

[Setup]
AppId={{2C664E61-DB8F-49B8-BA00-9DAB9E7B2675}
AppName=НЕЙРОЗАВОД — Локальная база (предрелиз)
AppVersion=0.1.0
AppPublisher=Neurofactory Local Candidate
DefaultDirName={localappdata}\Programs\NeurofactoryLocal
DefaultGroupName=НЕЙРОЗАВОД
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
DisableProgramGroupPage=yes
Compression=lzma2
SolidCompression=yes
OutputDir=output
OutputBaseFilename=Neurofactory-Local-Draft-Setup
UninstallDisplayName=НЕЙРОЗАВОД — Локальная база (без реального запуска ИИ)
UsePreviousAppDir=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\runtime\python.exe

[Files]
Source: "{#SourceRoot}\runtime\*"; DestDir: "{app}\runtime"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\app\local_workspace.py"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "{#SourceRoot}\ui\*"; DestDir: "{app}\ui"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\components\*"; DestDir: "{app}\components"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\start_neurofactory.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userdesktop}\НЕЙРОЗАВОД — Локальная база"; Filename: "{app}\start_neurofactory.cmd"
Name: "{userprograms}\НЕЙРОЗАВОД — Локальная база"; Filename: "{app}\start_neurofactory.cmd"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := IsWin64;
  if not Result then
    MsgBox('Нужна 64-битная Windows.', mbError, MB_OK);
end;
