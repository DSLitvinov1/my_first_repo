# Test-only contract on GitHub HOSTED disposable Windows runner, NOT user PC.
# Do not create services, system keys, journals, alter ACLs or execute effects.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'windows_trusted_runtime_preflight.ps1'

$rows = @(& pwsh -NoLogo -NoProfile -NonInteractive -File $scriptPath)
$exitCode = $LASTEXITCODE

if ($exitCode -ne 2) {
    throw "FAIL CLOSED: Windows host preflight must return blocked code 2"
}
if ($rows.Count -ne 1) {
    throw "Preflight must emit one JSON report and no data/secrets"
}
$report = $rows[0] | ConvertFrom-Json

function AssertEqual($left, $right, $message) {
    if ($left -cne $right) { throw "$message : expected [$right], got [$left]" }
}
AssertEqual $report.schema 'neurofactory.windows_trusted_runtime_readiness.v1' 'schema'
AssertEqual $report.linux_server_required_for_local_pilot $false 'no Linux required for pilot'
AssertEqual $report.windows_instead_of_linux_allowed_by_architecture $true 'Windows choice'
AssertEqual $report.host_trust_boundary_required $true 'never remove trust'
AssertEqual $report.current_os_is_windows $true 'executed on Windows GitHub CI'
AssertEqual $report.status 'WINDOWS_ARCHITECTURE_SELECTED_DEPLOYMENT_BLOCKED' 'status'
AssertEqual $report.handoff 'PAUSED_BY_USER' 'handoff'

foreach ($name in @(
    'standalone_windows_receiver_installed_and_verified',
    'local_pilot_automatic_real_project_writes',
    'external_highwater_or_independent_device_proven',
    'remote_witness_attested',
    'cross_machine_acceptance_completed',
    'independent_review_approved',
    'can_install_or_modify_machine',
    'can_reboot_machine',
    'can_enable_live_queue',
    'can_modify_real_project_files',
    'release_approved')) {
    AssertEqual $report.$name $false $name
}

$required = @(
    'operator_owner_identity_and_fresh_repo_acl',
    'root_pinned_public_keys_and_nonexportable_signer_custody',
    'protected_named_pipe_explicit_sid_dacl',
    'worker_and_receiver_write_acl_separation',
    'windows_receiver_scoped_effect_and_live_lease',
    'off_machine_monotonic_witness_for_full_rollback_protection',
    'actual_windows_reboot_and_protected_journal_recovery',
    'signed_independent_reviewer_approval'
)
foreach ($gate in $required) {
    AssertEqual $report.external_proofs.$gate 'NOT_INDEPENDENTLY_VERIFIED' $gate
}

if ($report.blockers.Count -lt 1) {
    throw 'There must be at least one blocker on unprovisioned GH Windows CI'
}
# Redaction: never emit local environment identity or paths.
Write-Output 'NF_WINDOWS_NO_LINUX_ARCHITECTURE=PASS'
Write-Output 'NF_WINDOWS_PREINSTALL_EFFECT_AND_QUEUE=BLOCKED'
Write-Output 'NF_WINDOWS_PRODUCTION_APPROVAL=REJECT'
Write-Output 'Ran 17 Windows policy assertions; ALL PASS'
