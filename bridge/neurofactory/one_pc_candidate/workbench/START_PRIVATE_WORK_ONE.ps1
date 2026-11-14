# Work ONE personal portable pilot: does not install or elevate.
[CmdletBinding()]
param([switch]$NotepadTest)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::UserInteractive) {throw 'PERSONAL_INTERACTIVE_SESSION_REQUIRED'}
$principal=[Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'PERSONAL_ELEVATED_SESSION_REFUSED'
}
if (!$env:LOCALAPPDATA) {throw 'PERSONAL_PROFILE_NOT_FOUND'}
$python=Get-Command python.exe -ErrorAction SilentlyContinue
if (!$python) {throw 'PERSONAL_PYTHON_311_REQUIRED'}
& $python.Source -c "import sys; assert sys.version_info >= (3, 11)"
if ($LASTEXITCODE -ne 0) {throw 'PERSONAL_PYTHON_TOO_OLD'}
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path -LiteralPath (Join-Path $root 'work_server.py') -PathType Leaf)) {
    throw 'PERSONAL_WORK_SERVER_MISSING'
}
# Validate exactly the reviewed source package before starting the pilot.
& $python.Source (Join-Path $root 'private_preflight_one.py')
if ($LASTEXITCODE -ne 0) {throw 'PERSONAL_PACKAGE_INTEGRITY_FAILED'}
$data=Join-Path $env:LOCALAPPDATA 'NeirozavodWorkONEPrivatePilot'
if (Test-Path -LiteralPath $data) {
    $dir=Get-Item -LiteralPath $data -Force
    if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'PERSONAL_STATE_LINK_REFUSED'
    }
} else {
    New-Item -ItemType Directory -Path $data | Out-Null
}
foreach ($name in @('projects','data')) {
    $dir=Join-Path $data $name
    if (Test-Path -LiteralPath $dir) {
        $entry=Get-Item -LiteralPath $dir -Force
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'PERSONAL_PROJECT_LINK_REFUSED'
        }
    } else {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
$extra=@()
if ($NotepadTest) {
    # Only a synthetic local text document, never an existing user's note.
    $sample=Join-Path $data 'ONE-SYNTHETIC-NOTEPAD-TEST.txt'
    if (-not (Test-Path -LiteralPath $sample)) {
        [IO.File]::WriteAllText($sample,
          'Work ONE private test file. Only synthetic text; no passwords or client data.',
          [Text.Encoding]::UTF8)
    }
    $editor=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') `
        -ArgumentList ('"' + $sample + '"') -PassThru
    Write-Host ('SYNTHETIC_NOTEPAD_PID='+$editor.Id)
    Write-Host 'Only select this exact Notepad process in Work ONE. Do not select existing notes.'
    $extra=@('--desktop-enable','--desktop-allow-apps','notepad.exe')
}
Write-Host 'Work ONE — personal local pilot, port 18770'
Write-Host 'Google, Bitrix and public network access are disabled by default.'
Write-Host 'No CORE9/HOST changes. Close the window to stop.'
& $python.Source (Join-Path $root 'work_server.py') --root (
    Join-Path $data 'projects') --data (Join-Path $data 'data') --port 18770 @extra
if ($LASTEXITCODE -ne 0) {throw 'PERSONAL_WORK_EXITED_WITH_ERROR'}
