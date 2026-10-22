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
$hash=[Security.Cryptography.SHA256]::HashData($raw)
$hashHex=[Convert]::ToHexString($hash).ToLowerInvariant()
[ordered]@{
    schema='nf.windows.operator_public_pins_readonly_audit.v1'
    result='PROTECTED_PUBLIC_PIN_FILE_OBSERVED_NOT_ENROLLED'
    public_pin_file_sha256=$hashHex
    windows_file_owner_protected=$true
    untrusted_accounts_cannot_write=$true
    authentic_owner_approval_verified=$false
    independent_operator_hardware_attested=$false
    private_keys_enrolled_by_auditor=$false
    remote_witness_highwater_attested=$false
    production_service_enabled=$false
} | ConvertTo-Json -Compress
