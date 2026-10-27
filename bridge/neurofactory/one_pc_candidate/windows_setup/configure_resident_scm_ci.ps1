# Targeted rehearsal of automatic Windows SCM residence and crash recovery.
# This is NOT an owner-PC enrollment procedure or authority to execute CORE.
# Only disposable GitHub-hosted Windows; exact CI ownership and binary path.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Configure','Audit')][string]$Operation)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or
    $env:NF_CI_REVIEW_INSTALLER_ONLY -cne '1' -or
    $env:GITHUB_SHA -notmatch '^[a-f0-9]{40}$') {
    throw 'NF_RESIDENT_SCM_TEST_ON_DISPOSABLE_GITHUB_WINDOWS_ONLY'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'NF_RESIDENT_SCM_NEEDS_CI_ADMIN'
}
$name='NeurofactoryCoreHost'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'NeurofactoryDormantAcceptanceCI'
$marker=Join-Path $root 'review-ci-install-marker.json'
if ((Test-Path -LiteralPath $root -PathType Container) -ne $true -or
    (Test-Path -LiteralPath $marker -PathType Leaf) -ne $true) {
    throw 'NF_RESIDENT_SCM_NO_OPERATOR_CI_MARKER'
}
foreach ($path in @($root,$marker,
    (Join-Path $root 'runtime\python.exe'),
    (Join-Path $root 'neurofactory_dormant_service.py'),
    (Join-Path $root 'dormant-config.json'))) {
    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'NF_RESIDENT_SCM_REPARSE_POINT_DENIED'
    }
}
$permit=Get-Content -LiteralPath $marker -Raw -Encoding ascii | ConvertFrom-Json
if ($permit.schema -cne 'nf.onepc.ci_review_install_marker.v1' -or
    $permit.service_name -cne $name -or
    $permit.source_sha40 -cne $env:GITHUB_SHA -or
    $permit.status -cne 'REVIEW_ONLY_NO_EXECUTION') {
    throw 'NF_RESIDENT_SCM_CI_MARKER_INVALID'
}
$cfg=Get-Content (Join-Path $root 'dormant-config.json') -Raw -Encoding ascii | ConvertFrom-Json
if ($cfg.mode -cne 'REVIEW_BLOCKED_NOT_PRODUCTION' -or
    $cfg.real_host_execution_allowed -cne $false -or
    $cfg.core_queue_allowed -cne $false -or
    $cfg.network_listener_allowed -cne $false -or
    $cfg.production_release_approved -cne $false -or
    $cfg.independent_review_approved -cne $false -or
    $cfg.owner_key_installed -cne $false -or
    $cfg.external_witness_verified -cne $false) {
    throw 'NF_RESIDENT_SCM_DORMANT_FENCE_BROKEN'
}
$service=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
if ($null -eq $service) {throw 'NF_RESIDENT_SCM_SERVICE_MISSING'}
$want=('"'+(Join-Path $root 'runtime\python.exe')+'" -B "'+
    (Join-Path $root 'neurofactory_dormant_service.py')+'"')
if ($service.PathName.Trim() -ine $want -or
    $service.StartName -notmatch '^NT AUTHORITY\\LocalService$') {
    throw 'NF_RESIDENT_SCM_FOREIGN_SERVICE_DENIED'
}
$type=& sc.exe qsidtype $name | Out-String
if ($LASTEXITCODE -ne 0 -or $type -notmatch 'RESTRICTED') {
    throw 'NF_RESIDENT_SCM_MISSING_RESTRICTED_SID'
}
if ($Operation -eq 'Configure') {
    # Never change startup policy until ALL of the above are validated.
    & sc.exe config $name start= delayed-auto | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_CI_DELAYED_AUTO_NOT_CONFIGURED'}
    & sc.exe failure $name reset= 3600 actions= restart/6000/restart/15000/none/0 | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_CI_RECOVERY_NOT_CONFIGURED'}
    & sc.exe failureflag $name 1 | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_CI_FAILUREFLAG_NOT_CONFIGURED'}
}
$service=Get-CimInstance Win32_Service -Filter "Name='$name'"
if ($service.StartMode -cne 'Auto' -or $service.State -cne 'Running') {
    throw 'NF_RESIDENT_SCM_NOT_RUNNING_AUTOMATICALLY'
}
$qc=& sc.exe qc $name | Out-String
if ($LASTEXITCODE -ne 0 -or $qc -notmatch 'DELAYED_AUTO_START') {
    # "sc qc" may report AUTO_START; actual delayed flag is registry-backed.
    # Fail only if the base startup isn't AUTO_START.
    if ($qc -notmatch 'AUTO_START') {throw 'NF_RESIDENT_SCM_START_MODE_NOT_CONFIRMED'}
}
$reg=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction Stop
if ($reg.DelayedAutoStart -ne 1) {throw 'NF_RESIDENT_SCM_DELAYED_AUTO_NOT_PERSISTED'}
$recovery=(& sc.exe qfailure $name | Out-String)
if ($LASTEXITCODE -ne 0 -or $recovery -notmatch 'RESTART' -or
    $recovery -notmatch '6000' -or $recovery -notmatch '15000') {
    throw 'NF_RESIDENT_SCM_RECOVERY_POLICY_NOT_PERSISTED'
}
[ordered]@{
    schema='nf.windows.resident_scm_review_audit.v1'
    result='AUTOSTART_RECOVERY_CONFIGURED_INERT_CI_ONLY'
    service_name=$name
    expected_source_sha40=$env:GITHUB_SHA
    configured_start='delayed-auto'
    configured_restart_delay_ms=@(6000,15000)
    restricted_service_sid=$true
    core_queue_authorized=$false
    host_execution_authorized=$false
    production_service_approved=$false
    physical_owner_machine_installed=$false
} | ConvertTo-Json -Compress
