#ifndef SourceRoot
  #error SourceRoot is required: verified pinned application distribution
#endif
#ifndef HostSourceRoot
  #error HostSourceRoot is required: independently pinned protected service sources
#endif

; MACHINE-WIDE REVISION CANDIDATE, NEVER CLAIMED TO BE A SIGNED RELEASE.
; All installed CORE/HOST source remains inert. No SCM installation.
; A production release needs an independently signed, authorized service
; installer / owner key / reviewer key / external witness, none are here.

[Setup]
AppId={{5C7A0177-18A5-4BF5-9C47-B1DE5B81EF13}
AppName=НЕЙРОЗАВОД — Машинный пакет для независимой проверки
AppVersion=0.1.0-review
AppPublisher=Neurofactory Review Candidate (unverified)
DefaultDirName={autopf}\NeurofactoryReview
DefaultGroupName=НЕЙРОЗАВОД — Проверка
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
Compression=lzma2
SolidCompression=yes
OutputDir=output
OutputBaseFilename=Neurofactory-Machine-Review-UNSIGNED
UninstallDisplayName=НЕЙРОЗАВОД — Пакет для проверки (без службы)
UsePreviousAppDir=no
WizardStyle=modern
SetupLogging=yes
CloseApplications=yes
RestartApplications=no
UninstallDisplayIcon={app}\runtime\python.exe
DisableDirPage=no
AllowNoIcons=yes

[Files]
Source: "{#SourceRoot}\runtime\*"; DestDir: "{app}\runtime"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\ui\*"; DestDir: "{app}\ui"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\components\*"; DestDir: "{app}\components"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\start_neurofactory.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#HostSourceRoot}\neurofactory_dormant_service.py"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#HostSourceRoot}\audit_protected_host_readonly.ps1"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#HostSourceRoot}\audit_windows_operator_public_pins.ps1"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#HostSourceRoot}\inspect_dormant_review_bundle.py"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#HostSourceRoot}\PROTECTED_HOST_OPERATOR_ACCEPTANCE_RU.txt"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#SourceRoot}\review-host\resident_host_audit_journal.py"; DestDir: "{app}\review-host"; Flags: ignoreversion
Source: "{#SourceRoot}\release-manifest.json"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\НЕЙРОЗАВОД — Черновики (без исполнения)"; Filename: "{app}\start_neurofactory.cmd"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := IsWin64;
  if not Result then
  begin
    MsgBox('Нужна 64-битная Windows.', mbCriticalError, MB_OK);
    Exit;
  end;
  Result := True;
end;
