# Work ONE private portable. Ordinary interactive Windows user only.
[CmdletBinding()]
param(
  [switch]$NotepadTest,
  [ValidateLength(0,500)][string]$AllowedHosts='example.org,www.wikipedia.org,wikipedia.org',
  [ValidateLength(0,500)][string]$AllowApps='',
  [switch]$NoLocalQwen
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::UserInteractive) { throw 'PERSONAL_INTERACTIVE_SESSION_REQUIRED' }
$who=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'PERSONAL_ELEVATED_SESSION_REFUSED'
}
if (-not $env:LOCALAPPDATA) { throw 'PERSONAL_PROFILE_MISSING' }
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$runtime=Join-Path $root 'runtime\python\python.exe'
$pythonExe=$null
if (Test-Path -LiteralPath $runtime -PathType Leaf) {
  $pythonExe=$runtime
} else {
  $found=Get-Command 'python.exe' -ErrorAction SilentlyContinue
  if ($found) { $pythonExe=$found.Source }
}
if (-not $pythonExe) { throw 'PERSONAL_PYTHON_311_REQUIRED' }
& $pythonExe -c "import sys; assert sys.version_info >= (3, 11)"
if ($LASTEXITCODE -ne 0) { throw 'PERSONAL_PYTHON_TOO_OLD' }
& $pythonExe (Join-Path $root 'private_preflight_one.py')
if ($LASTEXITCODE -ne 0) { throw 'PERSONAL_PACKAGE_INTEGRITY_FAILED' }
if (-not (Test-Path -LiteralPath (Join-Path $root 'work_server.py') -PathType Leaf)) {
  throw 'PERSONAL_WORK_SERVER_MISSING'
}
$state=Join-Path $env:LOCALAPPDATA 'NeirozavodWorkONEPrivatePilot'
foreach($dir in @($state,(Join-Path $state 'projects'),(Join-Path $state 'data'))) {
  if (Test-Path -LiteralPath $dir) {
    $item=Get-Item -LiteralPath $dir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'PERSONAL_DATA_DIRECTORY_UNTRUSTED'
    }
  } else {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }
}
$extra=@()
$hosts=@($AllowedHosts.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' })
if ($hosts.Count -gt 8) { throw 'PERSONAL_TOO_MANY_BROWSER_HOSTS' }
foreach ($hostName in $hosts) {
  if ($hostName.Length -gt 190 -or $hostName -cnotmatch '^[a-z0-9](?:[a-z0-9.-]{0,188}[a-z0-9])?$' -or $hostName -match '\.\.' -or $hostName -notmatch '\.') {
    throw 'PERSONAL_BROWSER_HOST_INVALID'
  }
}
if ($hosts.Count -gt 0) { $extra+=@('--browser-allow-hosts',($hosts -join ',')) }
if (-not $NoLocalQwen) {
  try {
    $modelReply=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2
    $installed=@($modelReply.models | ForEach-Object { $_.name })
    $approved=@('qwen3.5:9b','qwen3.5:4b','qwen3.5:2b','qwen3.5:0.8b')
    if (@($approved | Where-Object { $installed -contains $_ }).Count -gt 0) {
      $extra+=@('--qwen-local')
      Write-Host 'Local Qwen detected. Work ONE will select an approved installed model.'
    }
  } catch {
    Write-Host 'Local Qwen not detected; trying the existing pinned private provider.'
  }
}
$apps=@()
if ($AllowApps.Trim()) {
  $apps=@($AllowApps.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' })
}
if ($NotepadTest) {
  $sample=Join-Path $state 'ONE-SYNTHETIC-NOTEPAD-TEST.txt'
  if (-not (Test-Path -LiteralPath $sample)) {
    [IO.File]::WriteAllText($sample,'Work ONE synthetic private test. No passwords or client information.',[Text.Encoding]::UTF8)
  }
  $editor=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') -ArgumentList ('"' + $sample + '"') -PassThru
  Write-Host ('SYNTHETIC_NOTEPAD_PID='+$editor.Id)
  $apps+=@('notepad.exe')
}
if ($apps.Count -gt 0) {
  $apps=@($apps | Select-Object -Unique)
  if ($apps.Count -gt 12) { throw 'PERSONAL_TOO_MANY_ALLOWED_APPS' }
  foreach($app in $apps) {
    if ($app -cnotmatch '^[a-z0-9_.-]{2,70}\.exe$') { throw 'PERSONAL_APP_NOT_APPROVED' }
  }
  $extra+=@('--desktop-enable','--desktop-allow-apps',($apps -join ','))
}
Write-Host 'NEIROZAVOD WORK ONE / PRIVATE / LOCAL'
Write-Host 'Local address: http://127.0.0.1:18770/'
Write-Host 'No CORE9/HOST changes; service actions require explicit separate approval.'
& $pythonExe (Join-Path $root 'work_server.py') --root (Join-Path $state 'projects') --data (Join-Path $state 'data') --port 18770 --open-ui @extra
if ($LASTEXITCODE -ne 0) { throw 'PERSONAL_WORK_SERVER_STOPPED_WITH_ERROR' }
