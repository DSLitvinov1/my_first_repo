# НЕЙРОЗАВОД — read-only actual Windows dormant SCM review.
# Reports what it observes, never installs/starts/stops/changes any service.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallRoot
)
$ErrorActionPreference='Stop'
$name='NeurofactoryCoreHost'
$root=[System.IO.Path]::GetFullPath($InstallRoot)
if (!(Test-Path -LiteralPath $root -PathType Container) -or
    ($root -notlike '*\NeurofactoryDormantAcceptanceCI' -and
     $root -notlike '*\NeurofactoryProtectedHost*')) {
    throw 'NF_REVIEW_ROOT_NOT_EXPLICITLY_PINNED'
}
$service=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
if (!$service) {throw 'NF_EXPECTED_PROTECTED_SERVICE_ABSENT'}
if ($service.StartName -notmatch '^NT AUTHORITY\\LocalService$' -or
    $service.StartMode -ne 'Manual') {
    throw 'NF_PROTECTED_SERVICE_PRINCIPAL_OR_START_MODE_WRONG'
}
$serviceSid=([System.Security.Principal.NTAccount]"NT SERVICE\$name").Translate([System.Security.Principal.SecurityIdentifier]).Value
if (!$serviceSid.StartsWith('S-1-5-80-')) {throw 'NF_SERVICE_SID_NOT_UNIQUE'}
$sidType=(& sc.exe qsidtype $name | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidType -notmatch 'RESTRICTED') {
    throw 'NF_ACTUAL_WINDOWS_SID_NOT_RESTRICTED'
}
$binary=Join-Path $root 'runtime\python.exe'
$source=Join-Path $root 'neurofactory_dormant_service.py'
$config=Join-Path $root 'dormant-config.json'
$statusDir=Join-Path $root 'status'
$statusFile=Join-Path $statusDir 'dormant-status.json'
foreach ($file in @($binary,$source,$config)) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
        throw 'NF_SERVICE_SOURCE_MISSING'
    }
}
$cfg=Get-Content -LiteralPath $config -Raw -Encoding Ascii | ConvertFrom-Json
$disabled=@('real_host_execution_allowed','core_queue_allowed',
           'network_listener_allowed','production_release_approved',
           'independent_review_approved','owner_key_installed','external_witness_verified')
if ($cfg.service_name -cne $name -or $cfg.mode -cne 'REVIEW_BLOCKED_NOT_PRODUCTION' -or
    $cfg.schema -cne 'nf.windows.dormant_host_provision.v1') {
    throw 'NF_SERVICE_CONFIG_NOT_IN_DORMANT_MODE'
}
foreach ($key in $disabled) {
    if ($cfg.$key -cne $false) {throw 'NF_SERVICE_CONFIG_ESCALATED'}
}
$normalizedCmd=($service.PathName -replace '/','\').ToLowerInvariant()
if (!$normalizedCmd.Contains($binary.ToLowerInvariant()) -or
    !$normalizedCmd.Contains($source.ToLowerInvariant())) {
    throw 'NF_SERVICE_BINARY_NOT_BOUND_TO_EXPECTED_ROOT'
}
$statusAcl=Get-Acl -LiteralPath $statusDir
$principalPermissions=@($statusAcl.Access | ForEach-Object {
    try {
        $sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        [pscustomobject]@{Sid=$sid;Rights=[int]$_.FileSystemRights;Type=[string]$_.AccessControlType}
    } catch {
        throw 'NF_UNVERIFIED_WINDOWS_ACL_ENTRY'
    }
})
$svcGrants=@($principalPermissions | Where-Object {
    $_.Sid -eq $serviceSid -and $_.Type -eq 'Allow' -and
    ($_.Rights -band [int][System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0
})
if ($svcGrants.Count -eq 0) {throw 'NF_STATUS_DIRECTORY_NOT_SERVICE_SID_WRITABLE'}
$sharedLocalService='S-1-5-19'
foreach ($entry in $principalPermissions) {
    if ($entry.Sid -eq $sharedLocalService -and $entry.Type -eq 'Allow' -and
        ($entry.Rights -band [int][System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0) {
        throw 'NF_SHARED_LOCAL_SERVICE_HAS_STATUS_WRITE'
    }
}
if ($service.State -ne 'Running' -or !(Test-Path -LiteralPath $statusFile)) {
    throw 'NF_DORMANT_SERVICE_NOT_RUNNING_WITH_PROTECTED_REPORT'
}
$record=Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json
if ($record.status -cne 'REVIEW_BLOCKED_NOT_PRODUCTION' -or
    $record.core_queue_allowed -cne $false -or
    $record.host_execution_allowed -cne $false -or
    $record.immutable_install_root_write_denied -cne $true) {
    throw 'NF_NO_WORKER_AUTHORITY_OR_ACL_PROOF_MISSING'
}
$owner=(Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" | Invoke-CimMethod -MethodName GetOwner).User
if ($owner.ToUpperInvariant() -cne 'LOCAL SERVICE') {
    throw 'NF_ACTUAL_SCM_PROCESS_NOT_LOCAL_SERVICE'
}
[ordered]@{
    schema='nf.windows.readonly_dormant_scm_acceptance.v1'
    result='DORMANT_RESTRICTED_SCM_OBSERVED_NOT_RELEASED'
    service=$name
    source_sha40=$cfg.source_sha40
    source_sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    actual_service_account='LOCAL SERVICE'
    actual_service_sid=$serviceSid
    service_sid_restricted=$true
    shared_local_service_write_denied=$true
    protected_root_write_denied=$true
    startup='Manual'
    core_queue_enabled=$false
    host_effects_enabled=$false
    production_signer_approved=$false
    release_approved=$false
    independent_reviewer_approval_established=$false
    runtime_service_was_modified_by_audit=$false
} | ConvertTo-Json -Compress
