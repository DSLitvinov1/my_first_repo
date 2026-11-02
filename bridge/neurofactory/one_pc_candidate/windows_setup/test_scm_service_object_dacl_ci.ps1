# Windows-hosted disposable unit tests of ACTUAL preflight service-object ACL.
# No service is opened, installed, started, reconfigured, or given permissions.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'NF_SCM_DACL_GUARD_NOT_PARSEABLE' }
foreach ($name in @('Assert-NfScmServiceDacl','Assert-NfActualScmServiceDacl')) {
    $defs=@($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    },$true))
    if ($defs.Count -ne 1) {throw ('NF_SCM_DACL_FUNCTION_NOT_UNIQUE:'+ $name)}
    Invoke-Expression $defs[0].Extent.Text
}
function Deny([string]$why) { throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why) }
function MustAllow([string]$name,[string]$sddl) {
    [void](Assert-NfScmServiceDacl $sddl)
    Write-Output ('PASS_ALLOW:'+ $name)
}
function MustReject([string]$name,[string]$sddl) {
    try {
        [void](Assert-NfScmServiceDacl $sddl)
    } catch {
        if ($_.Exception.Message -like '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED:*') {
            Write-Output ('PASS_DENY:'+ $name)
            return
        }
        throw
    }
    throw ('NF_UNTRUSTED_SERVICE_CONTROL_ALLOWED:'+ $name)
}
# All service-control rights only for SYSTEM and Administrators. Others may query.
$allowed='O:SYG:SYD:(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)(A;;0x00000005;;;AU)'
MustAllow 'admin_only_mutation_readonly_authenticated_users' $allowed
MustAllow 'numeric_owner_sid_from_real_cim' ('O:S-1-5-18G:SYD:(A;;0x000F01FF;;;SY)(A;;0x00000005;;;AU)')
MustReject 'sc_sdshow_owner_missing_without_independent_cim' 'D:(A;;0x000F01FF;;;SY)'
$rights=@(
    @{label='change_config';value='0x00000002'},
    @{label='start';value='0x00000010'},
    @{label='stop';value='0x00000020'},
    @{label='pause';value='0x00000040'},
    @{label='user_control';value='0x00000100'},
    @{label='delete';value='0x00010000'},
    @{label='write_dacl';value='0x00040000'},
    @{label='write_owner';value='0x00080000'},
    @{label='generic_all';value='0x10000000'},
    @{label='generic_execute';value='0x20000000'},
    @{label='generic_write';value='0x40000000'},
    @{label='maximum_allowed';value='0x02000000'}
)
foreach ($right in $rights) {
    MustReject ('authenticated_users_'+$right.label) (
        'O:SYG:SYD:(A;;0x000F01FF;;;SY)(A;;'+$right.value+';;;AU)')
}
MustReject 'arbitrary_domain_user_can_change_config' (
    'O:SYG:SYD:(A;;0x000F01FF;;;SY)(A;;0x00000002;;;S-1-5-21-111111111-222222222-333333333-1001)')
MustReject 'service_object_owner_is_users' (
    'O:BUG:SYD:(A;;0x000F01FF;;;SY)')
MustReject 'missing_dacl' 'O:SYG:SY'
MustReject 'malformed_sddl' 'not-sddl'
Write-Output 'NF_REAL_WINDOWS_SCM_SERVICE_OBJECT_DACL_DENY_REGRESSION=PASS_TEST_ONLY'
