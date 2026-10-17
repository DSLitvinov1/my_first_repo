#Requires -Version 5.1
<#
Read-only Windows trusted runtime PRE-FLIGHT (NOT installer).
NEVER alters ACLs, registry, services, keys, queues, filesystem, or startup.
Only the human owner and separate reviewer can authorize a real receiver.
No result from this script can authorize live work.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$blockers = [System.Collections.Generic.List[string]]::new()
$observedServices = [ordered]@{}

$runningOnWindows = $env:OS -eq 'Windows_NT'
if (-not $runningOnWindows) {
    $blockers.Add('WINDOWS_OS_NOT_PRESENT')
}

$receiverName = 'NeurofactoryReceiver'
$signerName = 'NeurofactorySigner'
$workerName = 'NeurofactoryRunner'
$serviceNames = @($receiverName, $signerName, $workerName)

foreach ($serviceName in $serviceNames) {
    $exists = $false
    $nonRoot = $false
    $accountKind = 'NOT_INSPECTED'
    if ($runningOnWindows) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $serviceName + "'") -ErrorAction Stop
            if ($null -ne $svc) {
                $exists = $true
                $accountKind = [string]$svc.StartName
                $nonRoot = -not (
                    $svc.StartName -match '^(LocalSystem|NT AUTHORITY\\SYSTEM)$'
                )
            }
        } catch {
            $blockers.Add('WINDOWS_SERVICE_INSPECTION_FAILED:' + $serviceName)
        }
    }
    $observedServices[$serviceName] = @{
        service_present = $exists
        non_system_service_account_reported = $nonRoot
        # A service name/account alone is not verified policy or SID ACL.
        service_sid_and_privileges_independently_verified = $false
    }
    if (-not $exists) {
        $blockers.Add('SEPARATE_PROTECTED_WINDOWS_SERVICE_NOT_VERIFIED:' + $serviceName)
    } elseif (-not $nonRoot) {
        $blockers.Add('SERVICE_ADMINISTRATIVE_PRIVILEGE_OR_UNKNOWN:' + $serviceName)
    }
}

$tpmPresent = $false
if ($runningOnWindows) {
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($null -ne $tpm) {
            $tpmPresent = $tpm.TpmPresent -eq $true
        }
    } catch {
        $blockers.Add('TPM_STATUS_NOT_VERIFIED')
    }
}
if (-not $tpmPresent) {
    $blockers.Add('TPM_HARDWARE_NOT_CONFIRMED')
}

$protectedTrustStoreExists = $false
if ($runningOnWindows -and -not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
    $protectedTrustStore = Join-Path $env:ProgramData 'Neurofactory\Trust'
    $protectedTrustStoreExists = Test-Path -LiteralPath $protectedTrustStore -PathType Container
}
if (-not $protectedTrustStoreExists) {
    $blockers.Add('PROTECTED_WINDOWS_OPERATOR_TRUST_STORE_NOT_INSTALLED')
}

# Require a distinct vetted local receiver SID and independently attested
# machine trust. Merely finding a TPM, folder or existing service is NEVER
# adequate to grant a live execution permit or bind a user identity.
$requiredExternalChecks = @(
    'operator_owner_identity_and_fresh_repo_acl',
    'root_pinned_public_keys_and_nonexportable_signer_custody',
    'protected_named_pipe_explicit_sid_dacl',
    'worker_and_receiver_write_acl_separation',
    'windows_receiver_scoped_effect_and_live_lease',
    'off_machine_monotonic_witness_for_full_rollback_protection',
    'actual_windows_reboot_and_protected_journal_recovery',
    'signed_independent_reviewer_approval'
)
$externalStatus = [ordered]@{}
foreach ($gate in $requiredExternalChecks) {
    $externalStatus[$gate] = 'NOT_INDEPENDENTLY_VERIFIED'
}

$report = [ordered]@{
    schema = 'neurofactory.windows_trusted_runtime_readiness.v1'
    mode = 'LOCAL_WINDOWS_MVP_WITH_MANUAL_CONFIRMATION'
    windows_instead_of_linux_allowed_by_architecture = $true
    linux_server_required_for_local_pilot = $false
    host_trust_boundary_required = $true
    current_os_is_windows = $runningOnWindows
    observed_service_state = $observedServices
    tpm_hardware_presence_only = $tpmPresent
    protected_trust_directory_present_only = $protectedTrustStoreExists
    external_proofs = $externalStatus
    blockers = @($blockers.ToArray())
    standalone_windows_receiver_installed_and_verified = $false
    local_pilot_automatic_real_project_writes = $false
    external_highwater_or_independent_device_proven = $false
    remote_witness_attested = $false
    cross_machine_acceptance_completed = $false
    independent_review_approved = $false
    can_install_or_modify_machine = $false
    can_reboot_machine = $false
    can_enable_live_queue = $false
    can_modify_real_project_files = $false
    release_approved = $false
    status = 'WINDOWS_ARCHITECTURE_SELECTED_DEPLOYMENT_BLOCKED'
    handoff = 'PAUSED_BY_USER'
}
$report | ConvertTo-Json -Depth 8 -Compress
# Deliberately nonzero: MUST NOT become a GitHub Actions deployment green gate.
exit 2
