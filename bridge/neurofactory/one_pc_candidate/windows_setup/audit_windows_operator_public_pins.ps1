# NEUROFACTORY Windows operator public trust roots: READ ONLY.
# Requires independently installed public pins. Never creates keys, modifies
# ACLs, trusts input-supplied public keys or grants production execution.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not [Environment]::OSVersion.Platform.ToString().StartsWith('Win')) {
    throw 'NF_TRUST_ROOT_AUDIT_WINDOWS_ONLY'
}
$known=[Environment]::GetFolderPath('CommonApplicationData')
if ([string]::IsNullOrWhiteSpace($known)) {throw 'NF_PROGRAMDATA_UNAVAILABLE'}
$root=Join-Path $known 'Neurofactory'
$trust=Join-Path $root 'trust'
$pins=Join-Path $trust 'four-party-public-pins.json'
$trustedOwners=@('S-1-5-18','S-1-5-32-544')
$writeMask = [int64]([System.Security.AccessControl.FileSystemRights]::Write -bor
                  [System.Security.AccessControl.FileSystemRights]::Modify -bor
                  [System.Security.AccessControl.FileSystemRights]::FullControl -bor
                  [System.Security.AccessControl.FileSystemRights]::Delete -bor
                  [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                  [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
foreach($file in @($root,$trust,$pins)) {
    $item=Get-Item -LiteralPath $file -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'NF_OPERATOR_PUBLIC_TRUST_REPARSE_DENIED'
    }
    if ($file -ne $pins -and -not $item.PSIsContainer) {
        throw 'NF_EXPECTED_FIXED_OPERATOR_TRUST_DIRECTORY'
    }
    if ($file -eq $pins -and ($item.PSIsContainer -or $item.Length -lt 220 -or $item.Length -gt 8192)) {
        throw 'NF_OPERATOR_PUBLIC_ROOT_FILE_NOT_BOUND'
    }
    $acl=Get-Acl -LiteralPath $file -ErrorAction Stop
    $ownerSid=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($trustedOwners -notcontains $ownerSid) {
        throw 'NF_TRUST_ROOT_NOT_OWNED_BY_SYSTEM_OR_ADMINISTRATORS'
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw 'NF_TRUST_ROOT_DACL_INHERITANCE_NOT_DISABLED'
    }
    foreach($entry in $acl.Access) {
        $who=$entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
           $trustedOwners -notcontains $who -and
           (([int64]$entry.FileSystemRights -band $writeMask) -ne 0)) {
            throw 'NF_UNPRIVILEGED_WINDOWS_WRITER_IN_TRUST_ROOT'
        }
    }
}
# Public-key root metadata only; Python independent validator handles strict
# key lengths and cryptographic identity. JSON content is NEVER emitted.
$raw=[IO.File]::ReadAllBytes($pins)
# Reject a file with merely protected ACLs but no plausible enrolled
# PUBLIC key structure. This is not proof of human consent or actual private
# key custody. The source format matches the existing operator v1 contract.
try {
    $json=[Text.Encoding]::ASCII.GetString($raw)
    $doc=ConvertFrom-Json -InputObject $json -AsHashtable -ErrorAction Stop
} catch {
    throw 'NF_PUBLIC_TRUST_JSON_NOT_VERIFIABLE'
}
$fields=@(
    'schema','repository','github_user_id','repository_id',
    'key_valid_from_unix','key_valid_until_unix',
    'operator_public_base64','owner_public_base64',
    'host_public_base64','witness_public_base64',
    'operator_public_sha256','mtls_witness_cert_sha256'
)
if ($doc -isnot [System.Collections.IDictionary] -or
    @($doc.Keys).Count -ne $fields.Count) {throw 'NF_PUBLIC_TRUST_FIELDS_MISMATCH'}
foreach($field in $fields) {
    if (-not $doc.Contains($field)) {throw 'NF_PUBLIC_TRUST_FIELDS_MISMATCH'}
}
if ($doc.schema -cne 'neurofactory.operator.public_pins.v1' -or
    $doc.repository -cne 'DSLitvinov1/my_first_repo' -or
    $doc.github_user_id -cne '151650108' -or
    $doc.repository_id -cne '723328237') {
    throw 'NF_PUBLIC_TRUST_NOT_PINNED_TO_EXPECTED_PROJECT'
}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($doc.key_valid_from_unix -isnot [long] -and $doc.key_valid_from_unix -isnot [int]) {
    throw 'NF_PUBLIC_TRUST_INVALID_TIME'
}
if ($doc.key_valid_until_unix -isnot [long] -and $doc.key_valid_until_unix -isnot [int]) {
    throw 'NF_PUBLIC_TRUST_INVALID_TIME'
}
if ([long]$doc.key_valid_from_unix -gt $now -or
    [long]$doc.key_valid_until_unix -le $now -or
    [long]$doc.key_valid_until_unix -gt ($now+90*86400)) {
    throw 'NF_PUBLIC_TRUST_EXPIRED_OR_OUT_OF_RANGE'
}
$rolePublic=@()
foreach($role in @('operator','owner','host','witness')) {
    $encoded=$doc[($role+'_public_base64')]
    if ($encoded -isnot [string] -or $encoded.Length -ne 44) {
        throw 'NF_PUBLIC_TRUST_WRONG_ED25519_LENGTH'
    }
    try {
        $key=[Convert]::FromBase64String($encoded)
    } catch {
        throw 'NF_PUBLIC_TRUST_KEY_BASE64_INVALID'
    }
    if ($key.Length -ne 32) {throw 'NF_PUBLIC_TRUST_WRONG_ED25519_LENGTH'}
    $rolePublic+=@([Convert]::ToHexString($key))
}
if (@($rolePublic | Select-Object -Unique).Count -ne 4) {
    throw 'NF_PUBLIC_TRUST_SIGNING_ROLES_NOT_DISTINCT'
}
$operatorKey=[Convert]::FromBase64String($doc.operator_public_base64)
$operatorHash=[Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($operatorKey)).ToLowerInvariant()
if ($doc.operator_public_sha256 -cne $operatorHash -or
    $doc.mtls_witness_cert_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'NF_PUBLIC_TRUST_FINGERPRINT_MISMATCH'
}
$hash=[Security.Cryptography.SHA256]::HashData($raw)
$hashHex=[Convert]::ToHexString($hash).ToLowerInvariant()
[ordered]@{
    schema='nf.windows.operator_public_pins_readonly_audit.v1'
    result='PROTECTED_PUBLIC_PIN_FILE_OBSERVED_NOT_ENROLLED'
    public_pin_file_sha256=$hashHex
    windows_file_owner_protected=$true
    untrusted_accounts_cannot_write=$true
    four_distinct_public_key_lengths_checked=$true
    operator_public_fingerprint_matches_file=$true
    independent_reviewer_key_enrolled=$false
    authentic_owner_approval_verified=$false
    independent_operator_hardware_attested=$false
    private_keys_enrolled_by_auditor=$false
    remote_witness_highwater_attested=$false
    production_service_enabled=$false
} | ConvertTo-Json -Compress
