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
  [Parameter(Mandatory=$true)][string]$PinnedPublisherThumbprint
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
if ($env:OS -cne 'Windows_NT') {Deny 'WINDOWS_REQUIRED'}
if ($env:GITHUB_ACTIONS -ceq 'true') {Deny 'NO_TEST_RUNNER_COUNTS_AS_PHYSICAL_RELEASE'}
foreach($pin in @($ExpectedHostBinarySha256,$ExpectedHostSourceSha256,
                   $ExpectedOwnerPublicSha256,$ExpectedReviewerPublicSha256,
                   $ExpectedWitnessPublicSha256)) {
    if ($pin -cnotmatch '^[0-9a-fA-F]{64}$') {Deny 'EXTERNAL_SHA256_PINS_REQUIRED'}
}
$rolePinHashes=@($ExpectedOwnerPublicSha256.ToLowerInvariant(),
     $ExpectedReviewerPublicSha256.ToLowerInvariant(),
     $ExpectedWitnessPublicSha256.ToLowerInvariant())
if (@($rolePinHashes|Select-Object -Unique).Count -ne 3) {
    Deny 'OWNER_REVIEWER_WITNESS_MUST_HAVE_THREE_DISTINCT_KEYS'
}
if ($PinnedPublisherThumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') {
    Deny 'EXTERNAL_REAL_PUBLISHER_CERTIFICATE_PIN_REQUIRED'
}
$name='NeurofactoryCoreHost'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NeurofactoryProtectedHost'
$trust=Join-Path $root 'trust'
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
    # Only the OS root and Administrators may own or MODIFY the physical
    # public trust roots, executable, service source or their ancestors.
    # A per-service SID or an arbitrary local/domain account must not.
    $trustedOwnerSids=@('S-1-5-18','S-1-5-32-544')
    $ownerSid=([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -notin $trustedOwnerSids) {
        Deny 'TRUST_FILE_OWNER_NOT_SYSTEM_OR_ADMINISTRATORS'
    }
    foreach($ace in $acl.Access) {
        if ($ace.AccessControlType -cne 'Allow') {continue}
        $sid=$ace.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        # 0x00156: data/append/EA/attributes PLUS DELETE_CHILD on parent
        # directories; 0xD0000: DELETE, WRITE_DAC, WRITE_OWNER.
        # This is an allowlist, not a blacklist of a few well-known SIDs.
        # Unknown domain/local service identities are always untrusted.
        $writes=(([int64]$ace.FileSystemRights -band 0x00156) -ne 0 -or
                 ([int64]$ace.FileSystemRights -band 0xD0000) -ne 0)
        if ($writes -and $sid -notin $trustedOwnerSids) {
            Deny 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
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
foreach($dir in @($root,(Join-Path $root 'host'),(Join-Path $root 'runtime'),$trust)) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        Deny 'OS_PROTECTED_TRUST_DIRECTORY_ABSENT'
    }
    $item=Get-Item -LiteralPath $dir -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Deny 'OS_TRUST_DIRECTORY_LINKED'
    }
    DenyUnsafeWriteAcl $dir
}
$roots=@{
  owner=@{path=(Join-Path $trust 'owner-public.bin');pin=$ExpectedOwnerPublicSha256}
  reviewer=@{path=(Join-Path $trust 'reviewer-public.bin');pin=$ExpectedReviewerPublicSha256}
  witness=@{path=(Join-Path $trust 'witness-public.bin');pin=$ExpectedWitnessPublicSha256}
}
foreach($entry in $roots.Values) {
    $file=Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
    if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
         $file.Length -ne 32) {
        Deny 'NOT_AN_UNLINKED_ED25519_PUBLIC_ROOT'
    }
    if ((Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $entry.pin.ToLowerInvariant()) {
        Deny 'PUBLIC_ROOT_NOT_INDEPENDENTLY_PINNED'
    }
    DenyUnsafeWriteAcl $entry.path
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
    observed_scm_running_and_restricted=$true
    physically_independent_review_verdict_proven=$false
    owner_per_task_signature_verified=$false
    remote_external_monotonic_witness_proven=$false
    host_work_effects_authorized=$false
    production_release_authorized=$false
    remote_private_keys_or_signatures_created=$false
    system_changed_by_this_audit=$false
}|ConvertTo-Json -Compress -Depth 4
