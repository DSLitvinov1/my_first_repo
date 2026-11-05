#requires -RunAsAdministrator
# Prepare-only: install immutable runtime and user signing identity. No SCM.
# A Linux witness must be enrolled separately before Start-*.ps1 is invoked.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$BundleDirectory,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceSha40,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$PackageSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Join-Path $env:ProgramData 'NeurofactoryPersonalHost'
$target=Join-Path $env:ProgramFiles 'NeurofactoryPersonalHost'
$ownerFolder=Join-Path $env:LOCALAPPDATA 'NeurofactoryData\owner-signing'
$manifestFile=Join-Path $BundleDirectory 'bundle-manifest.json'
$me=[Security.Principal.WindowsIdentity]::GetCurrent()
if (!$me.IsAuthenticated -or $me.User.Value -eq 'S-1-5-18') {throw 'OWNER_INTERACTIVE_IDENTITY_REQUIRED'}
if (!$env:ProgramFiles -or !$env:ProgramData -or !(Test-Path -LiteralPath $manifestFile)) {throw 'WINDOWS_HOST_BUNDLE_MISSING'}
if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $target) -or
    (Get-Service 'NeurofactoryPersonalHost' -ErrorAction SilentlyContinue)) {
  throw 'EXISTING_PERSONAL_HOST: NO RESET OR INSTALL OVER EXISTING SERVICE'
}
$man=Get-Content -LiteralPath $manifestFile -Raw -Encoding utf8 | ConvertFrom-Json
if ($man.schema -cne 'nf.personal.scoped_host_unsigned_bundle.v1' -or
    $man.source_sha40 -cne $ExpectedSourceSha40 -or
    $man.scope -cne 'SELF_MANAGED_OWNER_ONLY_SAFE_NOTES' -or
    $man.publisher_signed -or $man.independent_operator_verified -or
    $man.protected_service_installed) {throw 'PERSONAL_BUNDLE_MANIFEST_SCOPE_INVALID'}
if (@($man.entries).Count -lt 10) {throw 'BUNDLE_TRUNCATED'}
$manifestSha=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash
if ($manifestSha -cne $PackageSha256.ToUpperInvariant()) {
  throw 'PINNED_PERSONAL_PACKAGE_MANIFEST_SHA256_MISMATCH'
}
$base=(Resolve-Path -LiteralPath $BundleDirectory).Path
foreach($entry in @($man.entries)) {
  if ($entry.path -notmatch '^(runtime|service|installer)/[A-Za-z0-9_.+/-]+$' -or
      $entry.path.Contains('..') -or $entry.path.StartsWith('/')) {
    throw 'PACKAGE_PATH_TRAVERSAL_OR_UNEXPECTED_ENTRY'
  }
  $file=Join-Path $base ($entry.path.Replace('/','\'))
  if (!(Test-Path -LiteralPath $file -PathType Leaf) -or
      (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256 -or
      (Get-Item -LiteralPath $file).Length -ne [long]$entry.bytes) {
    throw 'PERSONAL_HOST_PACKAGE_FILE_HASH_MISMATCH'
  }
}
$admin='*S-1-5-32-544'
$system='*S-1-5-18'
$user='*'+$me.User.Value
function RunNative([string]$exe,[string[]]$args) {
  & $exe @args | Out-Null
  if ($LASTEXITCODE -ne 0) {throw "NATIVE_INSTALL_OPERATION_FAILED: $exe"}
}
New-Item -ItemType Directory -Path $target,$root -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $base 'runtime') -Destination (Join-Path $target 'runtime') -Recurse -Force
Copy-Item -LiteralPath (Join-Path $base 'service') -Destination (Join-Path $target 'service') -Recurse -Force
Copy-Item -LiteralPath $manifestFile -Destination (Join-Path $target 'bundle-manifest.json')
RunNative icacls.exe @($target,'/inheritance:r','/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F")
RunNative icacls.exe @($root,'/inheritance:r','/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F")
New-Item -ItemType Directory -Path $ownerFolder -Force | Out-Null
RunNative icacls.exe @($ownerFolder,'/inheritance:r','/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F","${user}:(OI)(CI)M")
$py=Join-Path $target 'runtime\python.exe'
$serviceSource=Join-Path $target 'service\personal_approve_safe_note.py'
& $py -B $serviceSource provision-owner --owner-folder $ownerFolder
if ($LASTEXITCODE -ne 0) {throw 'OWNER_ED25519_PROVISIONING_REFUSED'}
# Dedicated credential, not the Qwen key, for this service's ONLY SSH
# highwater forced-command. Windows LocalService has no SSH shell privilege.
$sshFile=Join-Path $root 'remote-client-id_ed25519'
if (Test-Path -LiteralPath $sshFile) {throw 'REMOTE_HOST_KEY_PREEXISTS'}
RunNative (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe') @(
  '-q','-t','ed25519','-a','32','-N','','-f',$sshFile,
  '-C','nf-personal-highwater')
RunNative icacls.exe @($sshFile,'/inheritance:r','/grant:r',"${system}:F","${admin}:F")
$hostPin='157.228.118.199 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkpprqPMxHxDcqY0048vPwxYfXPfbrLWPbKtVmnoo7A'
[IO.File]::WriteAllText((Join-Path $root 'known_hosts'),
    ($hostPin+[Environment]::NewLine),[Text.Encoding]::ASCII)
RunNative icacls.exe @((Join-Path $root 'known_hosts'),'/inheritance:r',
    '/grant:r',"${system}:F","${admin}:F")
# Identifies this machine without publishing a device serial. It is a scope
# fingerprint, not a TPM hardware attestation.
$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
if ([string]::IsNullOrWhiteSpace($uuid)) {throw 'MACHINE_IDENTITY_MISSING'}
$material=[Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME+'|'+$uuid)
$hasher=[Security.Cryptography.SHA256]::Create()
try {
  $machineHash=([BitConverter]::ToString(
      $hasher.ComputeHash($material))).Replace('-','').ToLowerInvariant()
} finally { $hasher.Dispose() }
$ownerKey=Join-Path $ownerFolder 'personal-owner-private.key'
$pub=& $py -B -c 'import base64,sys;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;from cryptography.hazmat.primitives import serialization;k=Ed25519PrivateKey.from_private_bytes(open(sys.argv[1],"rb").read());print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())' $ownerKey
if ($LASTEXITCODE -ne 0) {throw 'PUBLIC_OWNER_IDENTITY_NOT_AVAILABLE'}
$report=[ordered]@{
  schema='nf.personal.host.prepare.v1'
  source_sha40=$ExpectedSourceSha40
  package_sha256=$PackageSha256.ToLowerInvariant()
  machine_sha256=$machineHash
  owner_public_base64=$pub.Trim()
  windows_ssh_public=(Get-Content -LiteralPath ($sshFile+'.pub') -Raw).Trim()
  phase='PREPARED_ONLY_SERVICE_NOT_REGISTERED'
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'prepare-report.json') -Encoding ascii
RunNative icacls.exe @((Join-Path $root 'prepare-report.json'),'/inheritance:r',
  '/grant:r',"${system}:F","${admin}:F")
Write-Output 'NF_PERSONAL_WINDOWS_RUNTIME_AND_OWNER_CREDENTIAL_PREPARED=YES'
Write-Output 'NF_LINUX_HIGHWATER_WITNESS_MUST_USE_THE_EXACT_PREPARE_REPORT_PINS'
Write-Output ('NF_WINDOWS_REMOTE_WITNESS_SSH_PUBLIC='+$report.windows_ssh_public)
Write-Output ('NF_WINDOWS_MACHINE_SHA256='+$report.machine_sha256)
Write-Output ('NF_WINDOWS_PACKAGE_SHA256='+$report.package_sha256)
Write-Output ('NF_WINDOWS_SOURCE_SHA40='+$report.source_sha40)
Write-Output ('NF_OWNER_APPROVAL_PUBLIC='+$report.owner_public_base64)
Write-Output 'NF_SYSTEM_SERVICE_REGISTERED=NO_REQUIRE_LINUX_EXTERNAL_WITNESS_FIRST'
