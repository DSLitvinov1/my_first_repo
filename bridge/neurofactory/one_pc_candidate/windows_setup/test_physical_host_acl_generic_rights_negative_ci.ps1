# Windows CI negative test of the actual physical preflight NTFS ACL gate.
# Pure mocked Get-Acl: never reads or changes machine ACLs, services or keys.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {throw 'NF_PHYSICAL_ACL_SOURCE_NOT_PARSEABLE'}
$defs=@($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'DenyUnsafeWriteAcl'
},$true))
if ($defs.Count -ne 1) {throw 'NF_PHYSICAL_ACL_FUNCTION_NOT_UNIQUE'}
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
Invoke-Expression $defs[0].Extent.Text
$script:fixture=$null
function Get-Acl {
    param([string]$LiteralPath,$ErrorAction)
    if ($LiteralPath -cne 'C:\nf-fixture-no-file') {throw 'NF_ACL_TEST_UNEXPECTED_PATH'}
    return $script:fixture
}
function SetFixture([long]$Mask,[string]$Sid='S-1-5-32-545',
                    [string]$Owner='BUILTIN\Administrators',
                    [bool]$Protected=$true) {
    $script:fixture=[pscustomobject]@{
        AreAccessRulesProtected=$Protected
        Owner=$Owner
        Access=@([pscustomobject]@{
            AccessControlType='Allow'
            IdentityReference=[System.Security.Principal.SecurityIdentifier]::new($Sid)
            FileSystemRights=$Mask
        })
    }
}
function ExpectAllow([string]$Label) {
    DenyUnsafeWriteAcl 'C:\nf-fixture-no-file'
    Write-Output ('PASS_ALLOW:'+ $Label)
}
function ExpectDeny([string]$Label,[string]$Expected) {
    try {
        DenyUnsafeWriteAcl 'C:\nf-fixture-no-file'
        throw ('NF_PHYSICAL_ACL_NEGATIVE_BYPASS:'+ $Label)
    } catch {
        if ($_.Exception.Message -notlike ('*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$Expected+'*')) {
            throw ('NF_WRONG_PHYSICAL_ACL_REFUSAL_'+$Label+': '+$_.Exception.Message)
        }
        Write-Output ('PASS_DENY:'+ $Label)
    }
}
# Query-only public grants and full control by trusted SYSTEM remain legal.
SetFixture 0x00000001
ExpectAllow 'untrusted_read_only'
SetFixture 0x00000020
ExpectAllow 'untrusted_execute_only'
SetFixture 0x001F01FF 'S-1-5-18'
ExpectAllow 'trusted_system_full_control'
# Raw generic bits must not bypass a mask that checks only specific rights.
SetFixture 0x10000000
ExpectDeny 'untrusted_generic_all' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x40000000
ExpectDeny 'untrusted_generic_write' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x02000000
ExpectDeny 'untrusted_maximum_allowed' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x01000000
ExpectDeny 'untrusted_access_system_security' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x00000002
ExpectDeny 'untrusted_write_data' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x00000040
ExpectDeny 'untrusted_delete_child' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x00040000
ExpectDeny 'untrusted_write_dac' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x00010000
ExpectDeny 'untrusted_delete' 'NON_SYSTEM_PRINCIPAL_CAN_REPLACE_TRUST_ROOT'
SetFixture 0x00000001 'S-1-5-32-545' 'BUILTIN\Users'
ExpectDeny 'untrusted_owner' 'TRUST_FILE_OWNER_NOT_SYSTEM_OR_ADMINISTRATORS'
SetFixture 0x00000001 'S-1-5-32-545' 'BUILTIN\Administrators' $false
ExpectDeny 'inherited_acl' 'TRUST_FILE_INHERITED_UNVERIFIED_ACL'
Write-Output 'NF_PHYSICAL_TRUST_ACL_GENERIC_RIGHTS_NEGATIVE=PASS_TEST_ONLY'
