# Only disposable synthetic OS registry security descriptors. No registry writes.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {throw 'NF_REGISTRY_GUARD_SCRIPT_PARSE_FAILED'}
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
foreach($name in @('Assert-NfServiceRegistrySddl','Assert-NfActualServiceRegistryAcl')) {
    $defs=@($ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $n.Name -ceq $name
    },$true))
    if ($defs.Count -ne 1) {throw ('NF_REGISTRY_GUARD_MISSING:'+ $name)}
    Invoke-Expression $defs[0].Extent.Text
}
function Allow([string]$label,[string]$sddl) {
    [void](Assert-NfServiceRegistrySddl $sddl)
    Write-Output ('ALLOW:'+ $label)
}
function Denied([string]$label,[string]$sddl) {
    try {
        [void](Assert-NfServiceRegistrySddl $sddl)
        throw ('UNTRUSTED_REGISTRY_RIGHT_ALLOWED:'+ $label)
    } catch {
        if ($_.Exception.Message -notlike '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED:*') { throw }
        Write-Output ('DENY:'+ $label)
    }
}
Allow 'system_and_admin_own_write' 'O:SYG:SYD:(A;;0x000F003F;;;SY)(A;;0x000F003F;;;BA)(A;;0x00000001;;;AU)'
Allow 'read_only_authenticated_users' 'O:BAG:BAD:(A;;0x00000001;;;AU)(A;;0x000F003F;;;SY)'
foreach($item in @(
    @{name='set_value';mask='0x00000002'},
    @{name='create_subkey';mask='0x00000004'},
    @{name='create_link';mask='0x00000020'},
    @{name='delete';mask='0x00010000'},
    @{name='write_dac';mask='0x00040000'},
    @{name='write_owner';mask='0x00080000'},
    @{name='access_system_security';mask='0x01000000'},
    @{name='maximum_allowed';mask='0x02000000'},
    @{name='generic_all';mask='0x10000000'},
    @{name='generic_execute';mask='0x20000000'},
    @{name='generic_write';mask='0x40000000'}
)) {
    Denied $item.name ('O:SYG:SYD:(A;;0x000F003F;;;SY)(A;;'+$item.mask+';;;AU)')
}
Denied 'foreign_owner' 'O:BUG:SYD:(A;;0x000F003F;;;SY)'
Denied 'null_acl' 'O:SYG:SY'
Denied 'malformed' 'this-is-not-sddl'
# Exercise BOTH physical wrapper key paths with a deliberately simulated
# Get-Acl. No Registry provider writes or privilege escalation.
$script:seenKeys=@()
$script:syntheticRight='O:SYG:SYD:(A;;0x000F003F;;;SY)(A;;0x00000001;;;AU)'
function Get-Acl {
    param([string]$LiteralPath)
    $script:seenKeys+= $LiteralPath
    $obj=[pscustomobject]@{}
    $obj | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptorSddlForm -Value {
        param($sections)
        return $script:syntheticRight
    }
    return $obj
}
[void](Assert-NfActualServiceRegistryAcl 'NeurofactoryCoreHost')
if ($script:seenKeys.Count -ne 2 -or
    $script:seenKeys[0] -notlike '*CurrentControlSet\Services' -or
    $script:seenKeys[1] -notlike '*CurrentControlSet\Services\NeurofactoryCoreHost') {
    throw 'NF_REGISTRY_OS_PATH_PAIR_NOT_CHECKED'
}
$script:syntheticRight='O:SYG:SYD:(A;;0x000F003F;;;SY)(A;;0x00000002;;;AU)'
try {
    [void](Assert-NfActualServiceRegistryAcl 'NeurofactoryCoreHost')
    throw 'NF_REGISTRY_WRAPPER_DID_NOT_REJECT'
} catch {
    if ($_.Exception.Message -notlike '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED:*') {throw}
}
Write-Output 'NF_REGISTRY_SERVICE_AND_PARENT_ACL_WRAPPER=PASS_TEST_ONLY'
