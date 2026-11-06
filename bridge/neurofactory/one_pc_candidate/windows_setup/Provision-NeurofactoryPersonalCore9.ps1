#requires -RunAsAdministrator
# One-time provisioning, never automatically reset during protected SCM boot.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExactSourceSha40,
 [Parameter(Mandatory=$true)][string]$GitBranch
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root='C:\ProgramData\NeurofactoryPersonalHost'
$core=Join-Path $root 'core9'
$installed='C:\Program Files\NeurofactoryPersonalHost'
$manifest=Join-Path $installed 'bundle-manifest.json'
$operator=Join-Path $root 'operator-config.json'
$gitExe='C:\Program Files\Git\cmd\git.exe'
$py=Join-Path $installed 'runtime\python.exe'
if (-not (Test-Path -LiteralPath $gitExe -PathType Leaf)) {throw 'GIT_NOT_PRESENT'}
if (Test-Path -LiteralPath $core) {throw 'CORE9_EXISTS_NO_RECREATE'}
$cfg=Get-Content -LiteralPath $operator -Raw|ConvertFrom-Json
$man=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json
if ($cfg.source_sha40 -cne $ExactSourceSha40 -or
    $man.source_sha40 -cne $ExactSourceSha40 -or
    $cfg.package_sha256 -cne
    (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'RELEASE_SOURCE_NOT_PINNED'
}
$svc=Get-CimInstance Win32_Service -Filter "Name='NeurofactoryPersonalHost'"
if (!$svc -or $svc.StartName -cne 'NT AUTHORITY\LocalService') {
    throw 'RESTRICTED_PERSONAL_SERVICE_REQUIRED'
}
New-Item -Path $core -ItemType Directory -ErrorAction Stop|Out-Null
$system='*S-1-5-18'
$admins='*S-1-5-32-544'
$service='NT SERVICE\NeurofactoryPersonalHost'
& icacls.exe $core /inheritance:r /grant:r ($system+':(OI)(CI)F') ($admins+':(OI)(CI)F')
if ($LASTEXITCODE) {throw 'CORE_ROOT_ACL_DENIED'}
& $gitExe clone --quiet --depth 1 --single-branch --branch $GitBranch https://github.com/DSLitvinov1/my_first_repo.git (Join-Path $core 'git')
if ($LASTEXITCODE) {throw 'PROTECTED_GIT_CLONE_FAILED_REFUSE_QUEUE'}
$repo=Join-Path $core 'git'
$actual=(& $gitExe -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actual -cne $ExactSourceSha40) {
    throw 'GIT_HEAD_NOT_PINNED_REFUSE_QUEUE'
}
& icacls.exe $repo /inheritance:r /grant:r ($system+':(OI)(CI)F') ($admins+':(OI)(CI)F') ($service+':(OI)(CI)RX') /T|Out-Null
if ($LASTEXITCODE) {throw 'CORE_GIT_RX_ACL_FAILED'}
& icacls.exe $core /grant ($service+':(RX)')|Out-Null
if ($LASTEXITCODE) {throw 'CORE_SERVICE_ROOT_READ_FAILED'}
& $py -B -c 'import sys;from pathlib import Path;from one_task_core import provision_empty_core_queue_offline;print(provision_empty_core_queue_offline(Path(sys.argv[1])))' $core
if ($LASTEXITCODE) {throw 'CORE9_OFFLINE_PROVISION_FAILED_NO_RESET'}
$state=Join-Path $core 'state'
$sandbox=Join-Path $core 'sandbox'
& icacls.exe $state /inheritance:r /grant:r ($system+':(OI)(CI)F') ($admins+':(OI)(CI)F') ($service+':(OI)(CI)M') /T|Out-Null
if ($LASTEXITCODE) {throw 'CORE9_STATE_ACL_DENIED'}
& icacls.exe $sandbox /inheritance:r /grant:r ($system+':(OI)(CI)F') ($admins+':(OI)(CI)F') ($service+':(OI)(CI)M') /T|Out-Null
if ($LASTEXITCODE) {throw 'CORE9_SANDBOX_ACL_DENIED'}
Write-Output 'CORE9_EXISTING_ONE_TASK_SQLITE_PROVISIONED_EMPTY'
Write-Output ('CORE9_PINNED_GIT_SHA40='+$actual)
Write-Output 'CORE9_NO_EFFECT_ALLOWED_WITHOUT_OWNER_SIGNED_QUEUE'
