#requires -RunAsAdministrator
# Resume only the interrupted non-destructive preparation when owner+SSH
# private keys already exist. Never change or reissue them; never register SCM.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$BundleDirectory,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceSha40,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Join-Path $env:ProgramData 'NeurofactoryPersonalHost'
$bin=Join-Path $env:ProgramFiles 'NeurofactoryPersonalHost'
$ownerFolder=Join-Path $env:LOCALAPPDATA 'NeurofactoryData\owner-signing'
$ownerPrivate=Join-Path $ownerFolder 'personal-owner-private.key'
$sshKey=Join-Path $root 'remote-client-id_ed25519'
$manifest=Join-Path $bin 'bundle-manifest.json'
$expected=Join-Path $BundleDirectory 'bundle-manifest.json'
$prepareReport=Join-Path $root 'prepare-report.json'
if ((Get-Service 'NeurofactoryPersonalHost' -ErrorAction SilentlyContinue) -or
    (Test-Path $prepareReport) -or
    (Test-Path (Join-Path $root 'operator-config.json')) -or
    (Test-Path (Join-Path $root 'state\intent-fence.sqlite3')) -or
    !(Test-Path $sshKey) -or
    !(Test-Path ($sshKey+'.pub')) -or
    !(Test-Path $ownerPrivate) -or
    !(Test-Path $manifest) -or
    !(Test-Path $expected) -or
    !(Test-Path (Join-Path $root 'known_hosts'))) {
  throw 'RESUME_EXACT_SAFE_PREPARATION_STATE_NOT_PRESENT'
}
if ((Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256 -or
    (Get-FileHash $expected -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256) {
  throw 'INTERRUPTED_PACKAGE_MANIFEST_HASH_MISMATCH'
}
$source=(Get-Content $manifest -Raw -Encoding utf8 | ConvertFrom-Json).source_sha40
if ($source -cne $ExpectedSourceSha40) {throw 'CANNOT_RESUME_WRONG_SOURCE_COMMIT'}
$paths=@(
 @{p=$ownerPrivate; max=64},
 @{p=$sshKey; max=5000},
 @{p=($sshKey+'.pub'); max=400},
 @{p=(Join-Path $root 'known_hosts'); max=500}
)
foreach($value in $paths) {
 $f=Get-Item -LiteralPath $value.p -ErrorAction Stop
 if ($f.PSIsContainer -or $f.Length -le 0 -or $f.Length -gt [int]$value.max -or
     $f.Attributes -band [IO.FileAttributes]::ReparsePoint) {
   throw 'SENSITIVE_PREPARED_FILE_IS_INVALID_OR_REDIRECTED'
 }
}
$pin='157.228.118.199 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkpprqPMxHxDcqY0048vPwxYfXPfbrLWPbKtVmnoo7A'
if ((Get-Content (Join-Path $root 'known_hosts') -Raw).Trim() -cne $pin) {
  throw 'CLOUD_SSH_SERVER_KEY_PIN_MISMATCH'
}
$py=Join-Path $bin 'runtime\python.exe'
$sourceFolder=Join-Path $bin 'service'
if (!(Test-Path $py) -or !(Test-Path (Join-Path $sourceFolder 'personal_approve_safe_note.py'))) {
  throw 'PERSONAL_RUNTIME_MISSING'
}
$pub=& $py -B -c 'import base64,sys;from pathlib import Path;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;from cryptography.hazmat.primitives import serialization;k=Ed25519PrivateKey.from_private_bytes(Path(sys.argv[1]).read_bytes());print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())' $ownerPrivate
if ($LASTEXITCODE -ne 0 -or !($pub -match '^[a-zA-Z0-9+/]{43}=$')) {
  throw 'OWNER_SECRET_CANNOT_RESTORE_PUBLIC_KEY'
}
$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
if ([string]::IsNullOrWhiteSpace($uuid)) {throw 'OWNER_MACHINE_UUID_MISSING'}
$material=[Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME+'|'+$uuid)
$h=[Security.Cryptography.SHA256]::Create()
try {$machineHash=([BitConverter]::ToString($h.ComputeHash($material))).Replace('-','').ToLowerInvariant()}
finally {$h.Dispose()}
$report=[ordered]@{
 schema='nf.personal.host.prepare.v1'
 source_sha40=$ExpectedSourceSha40
 package_sha256=$ExpectedManifestSha256
 machine_sha256=$machineHash
 owner_public_base64=$pub.Trim()
 windows_ssh_public=(Get-Content -LiteralPath ($sshKey+'.pub') -Raw).Trim()
 phase='PREPARED_ONLY_SERVICE_NOT_REGISTERED'
}
$report|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $prepareReport -Encoding ascii
$system='*S-1-5-18';$admins='*S-1-5-32-544'
& icacls.exe $prepareReport '/inheritance:r' '/grant:r' "${system}:F" "${admins}:F" | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'PREPARED_REPORT_ACL_FAILED'}
Write-Output 'NF_WINDOWS_EXISTING_OWNER_KEY_PRESERVED=YES'
Write-Output 'NF_WINDOWS_EXISTING_SSH_KEY_PRESERVED=YES'
Write-Output ('NF_PERSONAL_WINDOWS_SOURCE='+$report.source_sha40)
Write-Output ('NF_PERSONAL_WINDOWS_PACKAGE_SHA256='+$report.package_sha256)
Write-Output ('NF_PERSONAL_WINDOWS_MACHINE_SHA256='+$report.machine_sha256)
Write-Output ('NF_PERSONAL_WINDOWS_SSH_PUBLIC='+$report.windows_ssh_public)
Write-Output ('NF_PERSONAL_OWNER_PUBLIC='+$report.owner_public_base64)
Write-Output 'NF_PERSONAL_WINDOWS_PREPARED_NO_SERVICE=YES'
