<#
  НЕЙРОЗАВОД. REAL Windows security boundary preflight (READ ONLY).
  There is no --approve, --install, --enroll or --activate path.
  Real owner, reviewer and witness public roots are provisioned by separate
  OS-authorized principals. This script does not generate keys, modify ACLs,
  execute HOST/CORE or download Qwen models. Refuses CI-hosted fixtures.

  Passing local public-key and OS checks cannot prove private signer custody,
  remote monotonic witness physical independence, publisher trust/revocation,
  owner consent to a specific task, or human review. Never return PRODUCTION.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ExpectedHostBinarySha256,
  [Parameter(Mandatory=$true)][string]$ExpectedHostSourceSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedOwnerPublicSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedReviewerPublicSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedWitnessPublicSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedHostPublicSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedOperatorPublicSha256,
  [Parameter(Mandatory=$true)][string]$ExpectedPublicPinsFileSha256,
  [Parameter(Mandatory=$true)][string]$PinnedPublisherThumbprint
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
if ($env:OS -cne 'Windows_NT') {Deny 'WINDOWS_REQUIRED'}
if ($env:GITHUB_ACTIONS -ceq 'true') {Deny 'NO_TEST_RUNNER_COUNTS_AS_PHYSICAL_RELEASE'}
foreach($pin in @($ExpectedHostBinarySha256,$ExpectedHostSourceSha256,
                   $ExpectedOwnerPublicSha256,$ExpectedReviewerPublicSha256,
                   $ExpectedWitnessPublicSha256,$ExpectedHostPublicSha256,
                   $ExpectedOperatorPublicSha256,$ExpectedPublicPinsFileSha256)) {
    if ($pin -cnotmatch '^[0-9a-fA-F]{64}$') {Deny 'EXTERNAL_SHA256_PINS_REQUIRED'}
}
$rolePinHashes=@($ExpectedOwnerPublicSha256.ToLowerInvariant(),
     $ExpectedReviewerPublicSha256.ToLowerInvariant(),
     $ExpectedWitnessPublicSha256.ToLowerInvariant(),
     $ExpectedHostPublicSha256.ToLowerInvariant(),
     $ExpectedOperatorPublicSha256.ToLowerInvariant())
if (@($rolePinHashes|Select-Object -Unique).Count -ne 5) {
    Deny 'ALL_FIVE_EXTERNAL_TRUST_ROOT_HASH_PINS_MUST_BE_DISTINCT'
}
if ($PinnedPublisherThumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') {
    Deny 'EXTERNAL_REAL_PUBLISHER_CERTIFICATE_PIN_REQUIRED'
}
$name='NeurofactoryCoreHost'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NeurofactoryProtectedHost'
# Independently provisioned fixed ROOT: same public pins as
# audit_windows_operator_public_pins.ps1. Do NOT fabricate a second root
# under NeurofactoryProtectedHost with different keys.
$operatorRoot=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Neurofactory'
$trust=Join-Path $operatorRoot 'trust'
$publicPins=Join-Path $trust 'four-party-public-pins.json'
$service=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
if ($null -eq $service) {Deny 'ACTUAL_WINDOWS_SERVICE_MISSING'}
if ($service.StartName -cnotmatch '^NT AUTHORITY\\LocalService$' -or
    $service.StartMode -cne 'Auto' -or $service.State -cne 'Running' -or
    $service.ProcessId -le 0) {
    Deny 'REAL_SERVICE_NOT_RESTRICTED_RESIDENT_LOCALSERVICE'
}
$sidResult=(& sc.exe qsidtype $name | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidResult -notmatch 'RESTRICTED') {
    Deny 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
}
$serviceSid=([Security.Principal.NTAccount]"NT SERVICE\$name").Translate(
    [Security.Principal.SecurityIdentifier]).Value
if ($serviceSid -notmatch '^S-1-5-80-') {Deny 'NO_UNIQUE_WINDOWS_SERVICE_ID'}
$processOwner=Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" |
    Invoke-CimMethod -MethodName GetOwner
if ($processOwner.ReturnValue -ne 0 -or
    $processOwner.User -cne 'LOCAL SERVICE' -or
    $processOwner.Domain -cne 'NT AUTHORITY') {
    Deny 'SCM_PROCESS_TOKEN_IDENTITY_NOT_REAL_LOCALSERVICE'
}
$expectedSource=Join-Path $root 'host\protected_scm_host.py'
$expectedRuntime=Join-Path $root 'runtime\python.exe'
function CheckFile([string]$path,[string]$expectedSha,[long]$maxBytes) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Deny 'PINNED_SERVICE_FILE_MISSING'
    }
    $file=Get-Item -LiteralPath $path -Force
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $file.Length -le 0 -or $file.Length -gt $maxBytes) {
        Deny 'INVALID_OR_LINKED_SERVICE_BINARY'
    }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $expectedSha.ToLowerInvariant()) {
        Deny 'ACTUAL_SERVICE_FILE_HASH_NOT_APPROVED'
    }
}
function DenyUnsafeWriteAcl([string]$path) {
    $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {Deny 'TRUST_FILE_INHERITED_UNVERIFIED_ACL'}
    foreach($ace in $acl.Access) {
        if ($ace.AccessControlType -cne 'Allow') {continue}
        $sid=$ace.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        # 0x00116 = write data/append/EA/attributes; 0xD0000 =
        # delete, change permissions, take ownership.
        $writes=(([int64]$ace.FileSystemRights -band 0x00116) -ne 0 -or
                 ([int64]$ace.FileSystemRights -band 0xD0000) -ne 0)
        if ($writes -and $sid -in @(
            'S-1-1-0',  # Everyone
            'S-1-5-11', # Authenticated users
            'S-1-5-32-545', # Builtin Users
            'S-1-5-19', # Shared LocalService
            $serviceSid  # Per-service host may READ but NEVER modify trust
        )) {
            Deny 'UNTRUSTED_CLIENT_OR_HOST_SID_CAN_REPLACE_TRUST_ROOT'
        }
    }
}
CheckFile $expectedSource $ExpectedHostSourceSha256 250000
CheckFile $expectedRuntime $ExpectedHostBinarySha256 20000000
DenyUnsafeWriteAcl $expectedSource
DenyUnsafeWriteAcl $expectedRuntime
$cmd=$service.PathName.Trim()
$want=('"'+$expectedRuntime+'" -B "'+$expectedSource+'" --scm')
if ($cmd -ine $want) {Deny 'ACTUAL_SCM_BINARY_NOT_PINNED_TO_SERVICE_ROOT'}
$signer=Get-AuthenticodeSignature -LiteralPath $expectedRuntime -ErrorAction Stop
if ($signer.Status.ToString() -cne 'Valid' -or
    $null -eq $signer.SignerCertificate -or
    $signer.SignerCertificate.Thumbprint.ToUpperInvariant() -cne
        $PinnedPublisherThumbprint.ToUpperInvariant()) {
    Deny 'SERVICE_RUNTIME_NOT_SIGNED_BY_INDEPENDENTLY_PINNED_PUBLISHER'
}
foreach($dir in @($root,(Join-Path $root 'host'),(Join-Path $root 'runtime'),
                 $operatorRoot,$trust)) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        Deny 'OS_PROTECTED_TRUST_DIRECTORY_ABSENT'
    }
    $item=Get-Item -LiteralPath $dir -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Deny 'OS_TRUST_DIRECTORY_LINKED'
    }
    DenyUnsafeWriteAcl $dir
}
# A single immutable four-party PUBLIC trust root shared with the separate
# Windows operator auditor. No second self-provided owner/reviewer key store.
if (-not (Test-Path -LiteralPath $publicPins -PathType Leaf)) {
    Deny 'FOUR_PARTY_FIXED_OS_PUBLIC_TRUST_ROOT_NOT_ENROLLED'
}
$rootFile=Get-Item -LiteralPath $publicPins -Force -ErrorAction Stop
if (($rootFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    $rootFile.Length -lt 220 -or $rootFile.Length -gt 8192) {
    Deny 'UNSAFE_FOUR_PARTY_OS_PUBLIC_PIN_FILE'
}
DenyUnsafeWriteAcl $publicPins
$observedPins=(Get-FileHash -LiteralPath $publicPins -Algorithm SHA256).Hash.ToLowerInvariant()
if ($observedPins -cne $ExpectedPublicPinsFileSha256.ToLowerInvariant()) {
    Deny 'EXTERNAL_ROOT_MANIFEST_SHA256_NOT_APPROVED'
}
try {
    $doc=Get-Content -LiteralPath $publicPins -Raw -Encoding UTF8 |
         ConvertFrom-Json -AsHashtable -ErrorAction Stop
} catch {
    Deny 'OS_OPERATOR_PUBLIC_ROOT_JSON_INVALID'
}
$keys=@('schema','repository','github_user_id','repository_id',
  'key_valid_from_unix','key_valid_until_unix',
  'operator_public_base64','owner_public_base64',
  'host_public_base64','witness_public_base64',
  'operator_public_sha256','mtls_witness_cert_sha256')
if ($doc -isnot [System.Collections.IDictionary] -or
    @($doc.Keys).Count -ne $keys.Count) {
    Deny 'FOUR_PARTY_TRUST_ROOT_WRONG_FIELDS'
}
foreach($key in $keys) {
    if (-not $doc.Contains($key)) {
        Deny 'FOUR_PARTY_TRUST_ROOT_MISSING_FIELD'
    }
}
if ($doc.schema -cne 'neurofactory.operator.public_pins.v1' -or
    $doc.repository -cne 'DSLitvinov1/my_first_repo' -or
    $doc.github_user_id -cne '151650108' -or
    $doc.repository_id -cne '723328237' -or
    $doc.operator_public_sha256 -cne $ExpectedOperatorPublicSha256.ToLowerInvariant() -or
    $doc.mtls_witness_cert_sha256 -cnotmatch '^[a-f0-9]{64}$') {
    Deny 'ACTUAL_PROJECT_OR_OPERATOR_TRUST_IDENTITY_NOT_PINNED'
}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($doc.key_valid_from_unix -isnot [long] -and $doc.key_valid_from_unix -isnot [int]) {
    Deny 'INVALID_ROOT_START_TIME'
}
if ($doc.key_valid_until_unix -isnot [long] -and $doc.key_valid_until_unix -isnot [int]) {
    Deny 'INVALID_ROOT_EXPIRY_TIME'
}
if ([long]$doc.key_valid_from_unix -gt $now -or
    [long]$doc.key_valid_until_unix -le $now -or
    [long]$doc.key_valid_until_unix -gt ($now+90*86400)) {
    Deny 'PUBLIC_OPERATOR_TRUST_ROOT_EXPIRED'
}
$expectedRoleHashes=@{
    operator=$ExpectedOperatorPublicSha256
    owner=$ExpectedOwnerPublicSha256
    host=$ExpectedHostPublicSha256
    witness=$ExpectedWitnessPublicSha256
}
foreach($role in $expectedRoleHashes.Keys) {
    $encoded=$doc[($role+'_public_base64')]
    if ($encoded -isnot [string] -or $encoded.Length -ne 44) {
        Deny 'WRONG_ED25519_PUBLIC_LENGTH_IN_OS_TRUST_ROOT'
    }
    try { $public=[Convert]::FromBase64String($encoded) }
    catch { Deny 'INVALID_ED25519_PUBLIC_BASE64_IN_OS_TRUST_ROOT' }
    if ($public.Length -ne 32) {Deny 'INVALID_ED25519_PUBLIC_BYTES_IN_OS_TRUST_ROOT'}
    $fingerprint=([Convert]::ToHexString(
      [Security.Cryptography.SHA256]::HashData($public))).ToLowerInvariant()
    if ($fingerprint -cne $expectedRoleHashes[$role].ToLowerInvariant()) {
        Deny 'REAL_OS_PUBLIC_ROOT_DIFFERS_FROM_INDEPENDENTLY_APPROVED_ROLE'
    }
}
# Release-review key is separately pinned to the same immutable binary.
# This document cannot self-appoint a reviewer or approve the host.
$reviewerFile=Join-Path $trust 'independent-reviewer-public.bin'
if (-not (Test-Path -LiteralPath $reviewerFile -PathType Leaf)) {
    Deny 'SEPARATE_REVIEWER_PUBLIC_ROOT_NOT_PROVISIONED'
}
$reviewer=Get-Item -LiteralPath $reviewerFile -Force
if ($reviewer.Length -ne 32 -or
    ($reviewer.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Deny 'REVIEWER_ROOT_FILE_INVALID'
}
DenyUnsafeWriteAcl $reviewerFile
if ((Get-FileHash -LiteralPath $reviewerFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne
    $ExpectedReviewerPublicSha256.ToLowerInvariant()) {
    Deny 'INDEPENDENT_REVIEWER_PUBLIC_ROOT_NOT_PINNED'
}
# Presence/ACL alone does not attest owner/reviewer private key control
# or remote highwater; intentionally block production even on true result.
[ordered]@{
    schema='nf.windows.physical_host_operator_preflight.v1'
    status='LOCAL_SERVICE_AND_PUBLIC_PINS_OBSERVED_NO_PRODUCTION_AUTHORITY'
    source_sha256=$ExpectedHostSourceSha256.ToLowerInvariant()
    runtime_sha256=$ExpectedHostBinarySha256.ToLowerInvariant()
    principal='NT AUTHORITY\LocalService'
    service_sid=$serviceSid
    owner_public_root_hash_matched=$true
    reviewer_public_root_hash_matched=$true
    witness_public_root_hash_matched=$true
    host_public_root_hash_matched=$true
    operator_public_root_hash_matched=$true
    reviewer_public_root_hash_matched=$true
    four_party_public_root_file_sha256=$observedPins
    observed_scm_running_and_restricted=$true
    physically_independent_review_verdict_proven=$false
    owner_per_task_signature_verified=$false
    remote_external_monotonic_witness_proven=$false
    host_work_effects_authorized=$false
    production_release_authorized=$false
    remote_private_keys_or_signatures_created=$false
    system_changed_by_this_audit=$false
}|ConvertTo-Json -Compress -Depth 4
