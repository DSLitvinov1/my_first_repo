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
# Service OBJECT DACL is distinct from NTFS file ACLs. An attacker with
# SERVICE_CHANGE_CONFIG can swap ImagePath AFTER file hashes were checked.
# This read-only check must fail even if current SCM PathName is correct.
function Assert-NfScmServiceDacl([string]$Sddl) {
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 16384) {
        Deny 'SERVICE_OBJECT_SDDL_MISSING_OR_OVERSIZED'
    }
    try {
        $descriptor=[System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {
        Deny 'SERVICE_OBJECT_SDDL_INVALID'
    }
    $trusted=@('S-1-5-18','S-1-5-32-544') # SYSTEM / BUILTIN Administrators
    if ($null -eq $descriptor.Owner -or
        $descriptor.Owner.Value -notin $trusted -or
        $null -eq $descriptor.DiscretionaryAcl -or
        $descriptor.DiscretionaryAcl.Count -eq 0) {
        Deny 'SERVICE_OBJECT_OWNER_OR_DACL_NOT_PROTECTED'
    }
    # Service rights: CHANGE_CONFIG, START, STOP, PAUSE, USER_CONTROL,
    # DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL/WRITE/EXECUTE,
    # MAXIMUM_ALLOWED. Read/query-only grants may be public.
    [long]$dangerous=0x720D0172
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            Deny 'SERVICE_OBJECT_UNKNOWN_ACE_TYPE'
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($null -eq $ace.SecurityIdentifier) {
                Deny 'SERVICE_OBJECT_ACE_WITHOUT_SID'
            }
            if ($ace.SecurityIdentifier.Value -notin $trusted -and
                (([long]$ace.AccessMask -band $dangerous) -ne 0)) {
                Deny 'UNTRUSTED_PRINCIPAL_CAN_CONTROL_WINDOWS_SERVICE'
            }
        } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            Deny 'SERVICE_OBJECT_UNEXPECTED_ACE_QUALIFIER'
        }
    }
    return $true
}
function Assert-NfActualScmServiceDacl([string]$ServiceName, $Service) {
    if ($ServiceName -cne 'NeurofactoryCoreHost' -or
        $null -eq $Service -or $Service.Name -cne $ServiceName) {
        Deny 'UNPINNED_SCM_SERVICE_NAME'
    }
    # sc.exe sdshow returns DACL but (on real Windows 2025) omits OWNER.
    # Query owner from the OS service SECURITY_DESCRIPTOR via read-only CIM;
    # never mistake the NTFS registry-key owner for the SCM object owner.
    try {
        $security=Invoke-CimMethod -InputObject $Service -MethodName GetSecurityDescriptor -ErrorAction Stop
        $ownerSid=[string]$security.Descriptor.Owner.SIDString
    } catch {
        Deny 'SCM_SERVICE_OWNER_QUERY_FAILED'
    }
    if ($security.ReturnValue -ne 0 -or
        $ownerSid -notin @('S-1-5-18','S-1-5-32-544')) {
        Deny 'SCM_SERVICE_OWNER_NOT_SYSTEM_OR_ADMINISTRATORS'
    }
    # Process-level SystemRoot is caller-controlled. Never use it to locate the
    # native SCM security query: a forged sc.exe could report a safe DACL.
    $windowsDirectory=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory)) {
        Deny 'TRUSTED_WINDOWS_DIRECTORY_UNAVAILABLE'
    }
    $sc=Join-Path $windowsDirectory 'System32\sc.exe'
    $result=(& $sc sdshow $ServiceName 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $result.Length -gt 16384) {
        Deny 'SCM_SERVICE_SECURITY_QUERY_FAILED'
    }
    # sc.exe prints a header on some OS versions; require exactly one
    # recognizable SDDL line, never infer permission from a textual summary.
    $lines=@($result -split "[\r\n]+" | Where-Object { $_.Trim() -match '^([OGDS]:)' })
    if ($lines.Count -ne 1) {
        Deny 'SCM_SERVICE_SDDL_NOT_UNAMBIGUOUS'
    }
    $actualSddl=$lines[0].Trim()
    if ($actualSddl -match 'O:') {
        try {
            $reportedOwner=[System.Security.AccessControl.RawSecurityDescriptor]::new(
                $actualSddl).Owner.Value
        } catch {
            Deny 'SCM_SERVICE_SDDL_OWNER_INVALID'
        }
        if ($reportedOwner -cne $ownerSid) {
            Deny 'SCM_SERVICE_OWNER_QUERIES_DISAGREE'
        }
    } else {
        $actualSddl='O:'+$ownerSid+$actualSddl
    }
    [void](Assert-NfScmServiceDacl $actualSddl)
}
# Verify the real SCM restricted service SID type using the OS-owned sc.exe.
# An unqualified sc.exe resolves through caller-controlled PATH and may forge
# SERVICE_SID_TYPE: RESTRICTED even for an unrestricted service.
function Assert-NfActualRestrictedServiceSidType([string]$ServiceName) {
    if ($ServiceName -cne 'NeurofactoryCoreHost') {
        Deny 'UNPINNED_SCM_SERVICE_NAME'
    }
    $windowsDirectory=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsDirectory)) {
        Deny 'TRUSTED_WINDOWS_DIRECTORY_UNAVAILABLE'
    }
    $sc=Join-Path $windowsDirectory 'System32\sc.exe'
    try {
        $sidResult=(& $sc qsidtype $ServiceName 2>&1 | Out-String).Trim()
        $exitCode=$LASTEXITCODE
    } catch {
        Deny 'SCM_SERVICE_SID_TYPE_QUERY_FAILED'
    }
    if ($exitCode -ne 0 -or $sidResult.Length -gt 8192) {
        Deny 'SCM_SERVICE_SID_TYPE_QUERY_FAILED'
    }
    # Reject a forged RESTRICTED substring in errors, comments or extra lines.
    # Exactly one native SERVICE_SID_TYPE field must be present and restricted.
    $sidLines=@($sidResult -split "[\r\n]+" | Where-Object {
        $_ -match '^\s*SERVICE_SID_TYPE\s*:'
    })
    if ($sidLines.Count -ne 1 -or
        $sidLines[0] -cnotmatch '^\s*SERVICE_SID_TYPE\s*:\s*RESTRICTED\s*([string]$Sddl) {
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 16384) {
        Deny 'REGISTRY_SDDL_MISSING_OR_OVERSIZED'
    }
    try {
        $sd=[System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {Deny 'REGISTRY_SDDL_INVALID'}
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if ($null -eq $sd.Owner -or $sd.Owner.Value -notin $trusted -or
        $null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -eq 0) {
        Deny 'REGISTRY_OWNER_OR_DACL_UNTRUSTED'
    }
    # SET_VALUE, CREATE_SUB_KEY, CREATE_LINK, DELETE, WRITE_DAC/OWNER,
    # SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL/EXECUTE/WRITE.
    [long]$dangerous=0x730D0026
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            Deny 'REGISTRY_UNKNOWN_ACE'
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($null -eq $ace.SecurityIdentifier -or
                ($ace.SecurityIdentifier.Value -notin $trusted -and
                 (([long]$ace.AccessMask -band $dangerous) -ne 0))) {
                Deny 'UNTRUSTED_SERVICE_REGISTRY_WRITER'
            }
        } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            Deny 'REGISTRY_UNEXPECTED_ACE'
        }
    }
    return $true
}
function Assert-NfActualServiceRegistryAcl([string]$ServiceName) {
    if ($ServiceName -cne 'NeurofactoryCoreHost') {Deny 'REGISTRY_UNPINNED_SERVICE'}
    foreach($key in @(
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NeurofactoryCoreHost'
    )) {
        try {
            $acl=Get-Acl -LiteralPath $key -ErrorAction Stop
            $sections=([System.Security.AccessControl.AccessControlSections]::Owner -bor
                [System.Security.AccessControl.AccessControlSections]::Access)
            $sddl=$acl.GetSecurityDescriptorSddlForm($sections)
        } catch {Deny 'REGISTRY_SECURITY_NOT_VERIFIABLE'}
        [void](Assert-NfServiceRegistrySddl $sddl)
    }
}
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
[void](Assert-NfActualRestrictedServiceSidType $name)
$serviceSid=([Security.Principal.NTAccount]"NT SERVICE\$name").Translate(
    [Security.Principal.SecurityIdentifier]).Value
if ($serviceSid -notmatch '^S-1-5-80-') {Deny 'NO_UNIQUE_WINDOWS_SERVICE_ID'}
Assert-NfActualScmServiceDacl $name $service
Assert-NfActualServiceRegistryAcl $name
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
) {
        Deny 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    }
    return $true
}
# Also audit OS Registry config key, separate from SCM service-object DACL.
function Assert-NfServiceRegistrySddl([string]$Sddl) {
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 16384) {
        Deny 'REGISTRY_SDDL_MISSING_OR_OVERSIZED'
    }
    try {
        $sd=[System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {Deny 'REGISTRY_SDDL_INVALID'}
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if ($null -eq $sd.Owner -or $sd.Owner.Value -notin $trusted -or
        $null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -eq 0) {
        Deny 'REGISTRY_OWNER_OR_DACL_UNTRUSTED'
    }
    # SET_VALUE, CREATE_SUB_KEY, CREATE_LINK, DELETE, WRITE_DAC/OWNER,
    # SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL/EXECUTE/WRITE.
    [long]$dangerous=0x730D0026
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            Deny 'REGISTRY_UNKNOWN_ACE'
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($null -eq $ace.SecurityIdentifier -or
                ($ace.SecurityIdentifier.Value -notin $trusted -and
                 (([long]$ace.AccessMask -band $dangerous) -ne 0))) {
                Deny 'UNTRUSTED_SERVICE_REGISTRY_WRITER'
            }
        } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            Deny 'REGISTRY_UNEXPECTED_ACE'
        }
    }
    return $true
}
function Assert-NfActualServiceRegistryAcl([string]$ServiceName) {
    if ($ServiceName -cne 'NeurofactoryCoreHost') {Deny 'REGISTRY_UNPINNED_SERVICE'}
    foreach($key in @(
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NeurofactoryCoreHost'
    )) {
        try {
            $acl=Get-Acl -LiteralPath $key -ErrorAction Stop
            $sections=([System.Security.AccessControl.AccessControlSections]::Owner -bor
                [System.Security.AccessControl.AccessControlSections]::Access)
            $sddl=$acl.GetSecurityDescriptorSddlForm($sections)
        } catch {Deny 'REGISTRY_SECURITY_NOT_VERIFIABLE'}
        [void](Assert-NfServiceRegistrySddl $sddl)
    }
}
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
Assert-NfActualScmServiceDacl $name $service
Assert-NfActualServiceRegistryAcl $name
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
) {
        Deny 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    }
    return $true
}
# Also audit OS Registry config key, separate from SCM service-object DACL.
function Assert-NfServiceRegistrySddl([string]$Sddl) {
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 16384) {
        Deny 'REGISTRY_SDDL_MISSING_OR_OVERSIZED'
    }
    try {
        $sd=[System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {Deny 'REGISTRY_SDDL_INVALID'}
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if ($null -eq $sd.Owner -or $sd.Owner.Value -notin $trusted -or
        $null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -eq 0) {
        Deny 'REGISTRY_OWNER_OR_DACL_UNTRUSTED'
    }
    # SET_VALUE, CREATE_SUB_KEY, CREATE_LINK, DELETE, WRITE_DAC/OWNER,
    # SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL/EXECUTE/WRITE.
    [long]$dangerous=0x730D0026
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            Deny 'REGISTRY_UNKNOWN_ACE'
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($null -eq $ace.SecurityIdentifier -or
                ($ace.SecurityIdentifier.Value -notin $trusted -and
                 (([long]$ace.AccessMask -band $dangerous) -ne 0))) {
                Deny 'UNTRUSTED_SERVICE_REGISTRY_WRITER'
            }
        } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            Deny 'REGISTRY_UNEXPECTED_ACE'
        }
    }
    return $true
}
function Assert-NfActualServiceRegistryAcl([string]$ServiceName) {
    if ($ServiceName -cne 'NeurofactoryCoreHost') {Deny 'REGISTRY_UNPINNED_SERVICE'}
    foreach($key in @(
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NeurofactoryCoreHost'
    )) {
        try {
            $acl=Get-Acl -LiteralPath $key -ErrorAction Stop
            $sections=([System.Security.AccessControl.AccessControlSections]::Owner -bor
                [System.Security.AccessControl.AccessControlSections]::Access)
            $sddl=$acl.GetSecurityDescriptorSddlForm($sections)
        } catch {Deny 'REGISTRY_SECURITY_NOT_VERIFIABLE'}
        [void](Assert-NfServiceRegistrySddl $sddl)
    }
}
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
[void](Assert-NfActualRestrictedServiceSidType $name)
$serviceSid=([Security.Principal.NTAccount]"NT SERVICE\$name").Translate(
    [Security.Principal.SecurityIdentifier]).Value
if ($serviceSid -notmatch '^S-1-5-80-') {Deny 'NO_UNIQUE_WINDOWS_SERVICE_ID'}
Assert-NfActualScmServiceDacl $name $service
Assert-NfActualServiceRegistryAcl $name
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
) {
        Deny 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    }
    return $true
}
# Also audit OS Registry config key, separate from SCM service-object DACL.
function Assert-NfServiceRegistrySddl([string]$Sddl) {
    if ([string]::IsNullOrWhiteSpace($Sddl) -or $Sddl.Length -gt 16384) {
        Deny 'REGISTRY_SDDL_MISSING_OR_OVERSIZED'
    }
    try {
        $sd=[System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {Deny 'REGISTRY_SDDL_INVALID'}
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if ($null -eq $sd.Owner -or $sd.Owner.Value -notin $trusted -or
        $null -eq $sd.DiscretionaryAcl -or $sd.DiscretionaryAcl.Count -eq 0) {
        Deny 'REGISTRY_OWNER_OR_DACL_UNTRUSTED'
    }
    # SET_VALUE, CREATE_SUB_KEY, CREATE_LINK, DELETE, WRITE_DAC/OWNER,
    # SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL/EXECUTE/WRITE.
    [long]$dangerous=0x730D0026
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
            Deny 'REGISTRY_UNKNOWN_ACE'
        }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
            if ($null -eq $ace.SecurityIdentifier -or
                ($ace.SecurityIdentifier.Value -notin $trusted -and
                 (([long]$ace.AccessMask -band $dangerous) -ne 0))) {
                Deny 'UNTRUSTED_SERVICE_REGISTRY_WRITER'
            }
        } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
            Deny 'REGISTRY_UNEXPECTED_ACE'
        }
    }
    return $true
}
function Assert-NfActualServiceRegistryAcl([string]$ServiceName) {
    if ($ServiceName -cne 'NeurofactoryCoreHost') {Deny 'REGISTRY_UNPINNED_SERVICE'}
    foreach($key in @(
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NeurofactoryCoreHost'
    )) {
        try {
            $acl=Get-Acl -LiteralPath $key -ErrorAction Stop
            $sections=([System.Security.AccessControl.AccessControlSections]::Owner -bor
                [System.Security.AccessControl.AccessControlSections]::Access)
            $sddl=$acl.GetSecurityDescriptorSddlForm($sections)
        } catch {Deny 'REGISTRY_SECURITY_NOT_VERIFIABLE'}
        [void](Assert-NfServiceRegistrySddl $sddl)
    }
}
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
Assert-NfActualScmServiceDacl $name $service
Assert-NfActualServiceRegistryAcl $name
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
