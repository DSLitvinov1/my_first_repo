# PowerShell test of the ACTUAL preflight ACL helper without running preflight.
# No real registry, services, machine ACL or owner files are changed.
# Synthetic ACEs model an untrusted arbitrary domain/local SID and DELETE_CHILD.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$sourcePath = Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $sourcePath, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'P0_HOST_ACL_PREFLIGHT_NOT_PARSEABLE' }
$functionDefs = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'DenyUnsafeWriteAcl'
}, $true))
if ($functionDefs.Count -ne 1) { throw 'P0_HOST_ACL_FUNCTION_NOT_UNIQUE' }

function Deny([string]$reason) { throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED:' + $reason) }
function Get-Acl {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return $script:mockAcl
}
Invoke-Expression $functionDefs[0].Extent.Text

function AccessEntry([string]$sid, [string]$rights) {
    [pscustomobject]@{
        AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
        IdentityReference = [System.Security.Principal.SecurityIdentifier]::new($sid)
        FileSystemRights = [System.Enum]::Parse([System.Security.AccessControl.FileSystemRights], $rights)
    }
}
function Fixture([string]$owner,[bool]$protected,[object[]]$aces) {
    $script:mockAcl = [pscustomobject]@{
        Owner = $owner
        AreAccessRulesProtected = $protected
        Access = $aces
    }
}
function MustReject([string]$test) {
    try {
        DenyUnsafeWriteAcl 'CI-FAKE-NO-OS-FILE'
    } catch {
        if ($_.Exception.Message -like '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED:*') {
            Write-Output ('PASS_DENY:' + $test)
            return
        }
        throw
    }
    throw ('P0_ACL_UNSAFE_ALLOW:' + $test)
}
function MustAllow([string]$test) {
    DenyUnsafeWriteAcl 'CI-FAKE-NO-OS-FILE'
    Write-Output ('PASS_ALLOW:' + $test)
}
# System/Admin-only writable trust material and read-only service are allowed.
Fixture 'BUILTIN\Administrators' $true @(
    (AccessEntry 'S-1-5-18' 'FullControl'),
    (AccessEntry 'S-1-5-32-544' 'FullControl'),
    (AccessEntry 'S-1-5-19' 'ReadAndExecute'))
MustAllow 'system_admin_writes_service_read_only'

# Any arbitrary SID, even if not in the old short blacklist, must fail.
Fixture 'BUILTIN\Administrators' $true @(
    (AccessEntry 'S-1-5-18' 'FullControl'),
    (AccessEntry 'S-1-5-21-111111111-222222222-333333333-1001' 'WriteData'))
MustReject 'arbitrary_nonadmin_sid_write'

# Parent directory DELETE_CHILD permits removing protected files.
Fixture 'BUILTIN\Administrators' $true @(
    (AccessEntry 'S-1-5-18' 'FullControl'),
    (AccessEntry 'S-1-5-32-545' 'DeleteSubdirectoriesAndFiles'))
MustReject 'untrusted_delete_child'

# Ownership itself must be protected, even with no write grant.
Fixture 'BUILTIN\Users' $true @(
    (AccessEntry 'S-1-5-18' 'FullControl'))
MustReject 'untrusted_owner'

# Inherited ACEs are never accepted as operator-installed trust configuration.
Fixture 'BUILTIN\Administrators' $false @(
    (AccessEntry 'S-1-5-18' 'FullControl'))
MustReject 'unprotected_inherited_acl'

Write-Output 'NF_P0_TRUST_ACL_WIDE_SID_DENY_REGRESSION=PASS_TEST_ONLY'
