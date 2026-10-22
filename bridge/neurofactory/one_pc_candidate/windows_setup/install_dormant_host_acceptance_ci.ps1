# CI-only, non-production protected Windows SCM installer rehearsal.
# Never runs on a personal/self-hosted runner. Does NOT sign code or grant effects.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Install','Remove')]
    [string]$Operation,
    [switch]$InjectFailureAfterCreate
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or
    $env:NF_CI_REVIEW_INSTALLER_ONLY -cne '1' -or
    $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') {
    throw 'NF_NOT_A_DISPOSABLE_HOSTED_WINDOWS_INSTALLER_REHEARSAL'
}
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$role=New-Object System.Security.Principal.WindowsPrincipal($identity)
if (!$role.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'NF_NO_OPERATOR_ADMIN_RIGHTS'
}
$name='NeurofactoryCoreHost'
$commonData=[System.Environment]::GetFolderPath('CommonApplicationData')
if ([string]::IsNullOrWhiteSpace($commonData) -or
    [System.IO.Path]::GetFullPath($env:PROGRAMDATA).TrimEnd([char]92) -ine
        [System.IO.Path]::GetFullPath($commonData).TrimEnd([char]92)) {
    throw 'NF_PROGRAMDATA_MUST_BE_OS_PINNED'
}
$target=Join-Path $commonData 'NeurofactoryDormantAcceptanceCI'
$package=Join-Path $env:RUNNER_TEMP 'NeurofactoryProtectedHost-REVIEW-ONLY'
$marker=Join-Path $target 'review-ci-install-marker.json'
$script=Join-Path $target 'neurofactory_dormant_service.py'
$binary=Join-Path $target 'runtime\python.exe'
$readOnlyAuditor=Join-Path $target 'audit_protected_host_readonly.ps1'
$service=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
function Wait-Scm([string]$wanted) {
    for($i=0;$i -lt 70;$i++) {
        $s=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($s -and $s.State -eq $wanted) {return}
        Start-Sleep -Milliseconds 250
    }
    throw 'NF_SERVICE_DID_NOT_REACH_EXPECTED_STATE'
}
function Remove-CreatedService {
    & sc.exe stop $name | Out-Null
    & sc.exe delete $name | Out-Null
}
if ($Operation -eq 'Remove') {
    if ($InjectFailureAfterCreate) {throw 'NF_INVALID_REMOVE_OPTIONS'}
    if (!$service -or !(Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'NF_NEVER_REMOVE_UNOWNED_SERVICE'
    }
    foreach($checkPath in @($target,$marker,$script,$binary)) {
        $item=Get-Item -LiteralPath $checkPath -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'NF_NEVER_REMOVE_REPARSE_OR_JUNCTION_BOUND_SERVICE'
        }
    }
    $sealed=Get-Content -LiteralPath $marker -Raw -Encoding ascii | ConvertFrom-Json
    if ($sealed.schema -cne 'nf.onepc.ci_review_install_marker.v1' -or
        $sealed.service_name -cne $name -or
        $sealed.source_sha40 -cne $env:GITHUB_SHA -or
        $sealed.status -cne 'REVIEW_ONLY_NO_EXECUTION') {
        throw 'NF_NEVER_REMOVE_FOREIGN_OR_UNVERIFIED_SERVICE'
    }
    $cmd=$service.PathName
    $onlyExpectedCommand=('"{0}" -B "{1}"' -f $binary,$script)
    if (!$cmd -or $cmd.Trim() -ine $onlyExpectedCommand) {
        throw 'NF_SCM_BINARY_IS_NOT_OUR_REVIEW_INSTALLATION'
    }
    Remove-CreatedService
    Start-Sleep -Milliseconds 450
    if (Test-Path -LiteralPath $target -PathType Container) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    Write-Output 'NF_CI_PROTECTED_HOST_REVIEW_INSTALL_REMOVED'
    return
}
if ($service -or (Test-Path -LiteralPath $target)) {
    throw 'NF_NO_OVERWRITE_OR_UPGRADE_EXISTING_INSTALLATION'
}
if (!(Test-Path -LiteralPath $package -PathType Container)) {
    throw 'NF_MISSING_IMMUTABLE_REVIEW_STAGE'
}
# Immutable detached verifier from THIS checkout, not a script provided by
# the unsigned archive being inspected. A production workflow would
# additionally require independently signed owner/reviewer/witness approval.
$py=@'
import json, os, sys
from pathlib import Path
base=Path(os.getcwd())/"bridge/neurofactory/one_pc_candidate/windows_setup"
sys.path.insert(0,str(base))
from inspect_dormant_review_bundle import verify_review_bundle
check=verify_review_bundle(Path(os.environ["RUNNER_TEMP"])/"NeurofactoryProtectedHost-REVIEW-ONLY",
    expected_source_sha=os.environ["GITHUB_SHA"])
if check["windows_service_install_allowed"] is not False:
    raise SystemExit("REVIEW_ARCHIVE_TRIED_TO_GRANT_RELEASE")
print("NF_CI_OPERATOR_INERT_BUNDLE_HASH_VERIFIED="+str(check["checked_files"]))
'@
$py | python -B -
if ($LASTEXITCODE -ne 0) {
    throw 'NF_UNTRUSTED_SERVICE_REVIEW_BUNDLE_REFUSED'
}
$manifest=Get-Content -LiteralPath (Join-Path $package 'bundle-manifest.json') -Raw|ConvertFrom-Json
$createdRoot=$false
$createdService=$false
try {
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    $createdRoot=$true
    New-Item -ItemType Directory -Force -Path "$target\runtime","$target\status" | Out-Null
    foreach ($entry in $manifest.entries) {
        $source=Join-Path $package ($entry.path.Replace('/','\'))
        $dest=Join-Path $target ($entry.path.Replace('/','\'))
        Copy-Item -LiteralPath $source -Destination $dest -ErrorAction Stop
    }
    Copy-Item -LiteralPath (Join-Path $package 'bundle-manifest.json') -Destination (Join-Path $target 'bundle-manifest.json')
    $scCmd=('"{0}" -B "{1}"' -f $binary,$script)
    & sc.exe create $name binPath= $scCmd obj= 'NT AUTHORITY\LocalService' start= demand type= own | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_CANNOT_REGISTER_CI_SCM'}
    $createdService=$true
    if ($InjectFailureAfterCreate) {
        throw 'NF_INJECTED_FAILURE_MUST_ROLL_BACK_ONLY_OWNED_CI_SERVICE'
    }
    & sc.exe sidtype $name restricted | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_CANNOT_SET_RESTRICTED_SERVICE_SID'}
    $sid=([System.Security.Principal.NTAccount]"NT SERVICE\$name").Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    if (!$sid.StartsWith('S-1-5-80-')) {throw 'NF_SERVICE_SID_WRONG'}
    & icacls $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' ('*'+$sid+':(OI)(CI)RX') /T | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_PROGRAMDATA_ROOT_ACL_FAILED'}
    foreach($file in @(Get-ChildItem -LiteralPath $target -File -Recurse)) {
        & icacls $file.FullName /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-19:RX' ('*'+$sid+':RX') | Out-Null
        if ($LASTEXITCODE -ne 0) {throw 'NF_RUNTIME_FILE_ACL_FAILED'}
    }
    & icacls "$target\status" /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ('*'+$sid+':(OI)(CI)M') | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_STATUS_SID_WRITE_ACL_FAILED'}
    # Write restricted CI-only ownership marker as the admin AFTER sealing.
    [ordered]@{
      schema='nf.onepc.ci_review_install_marker.v1'
      service_name=$name
      source_sha40=$env:GITHUB_SHA
      status='REVIEW_ONLY_NO_EXECUTION'
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $marker -Encoding ascii
    & icacls $marker /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-19:R' ('*'+$sid+':R') | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_OPERATOR_MARKER_ACL_FAILED'}
    & sc.exe start $name | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'NF_DORMANT_SCM_FAILED_TO_START'}
    Wait-Scm 'Running'
    if (!(Test-Path -LiteralPath "$target\status\dormant-status.json")) {
        throw 'NF_PROTECTED_DORMANT_STATUS_NOT_WRITTEN'
    }
    # This auditor never changes the service, the ledger or any release flag.
    $audit = & pwsh -NoProfile -NonInteractive -File $readOnlyAuditor -InstallRoot $target | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or
        $audit.result -cne 'DORMANT_RESTRICTED_SCM_OBSERVED_NOT_RELEASED' -or
        $audit.core_queue_enabled -cne $false -or
        $audit.host_effects_enabled -cne $false) {
        throw 'NF_OPERATOR_INDEPENDENT_READONLY_SCM_AUDIT_DENIED'
    }
    Write-Output 'NF_OPERATOR_SEALED_DORMANT_WINDOWS_SERVICE=PASS_CI_NO_PRODUCTION_AUTHORITY'
    Write-Output 'NF_OPERATOR_RESTRICTED_SERVICE_SID_AND_READONLY_AUDIT=PASS_CI_ONLY'
} catch {
    if ($createdService) {Remove-CreatedService}
    if ($createdRoot -and (Test-Path -LiteralPath $target -PathType Container)) {
        Start-Sleep -Milliseconds 350
        Remove-Item -LiteralPath $target -Force -Recurse -ErrorAction SilentlyContinue
    }
    throw
}
