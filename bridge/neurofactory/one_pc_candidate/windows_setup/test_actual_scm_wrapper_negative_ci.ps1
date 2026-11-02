# Windows CI negative integration for the REAL physical preflight SCM wrapper.
# Only a disposable native .cmd stand-in and mocked CIM response are used.
# No installed service, real sc.exe, registry, permissions or keys are changed.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
$source=Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {throw 'NF_SCM_WRAPPER_SOURCE_NOT_PARSEABLE'}
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
foreach($name in @('Assert-NfScmServiceDacl','Assert-NfActualScmServiceDacl')) {
    $defs=@($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    },$true))
    if ($defs.Count -ne 1) {throw ('NF_SCM_WRAPPER_FUNCTION_NOT_UNIQUE:'+ $name)}
    Invoke-Expression $defs[0].Extent.Text
}
$script:tempRoot=Join-Path ([IO.Path]::GetTempPath()) ('nf-scm-wrapper-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:tempRoot)
$script:mockScPath=Join-Path $script:tempRoot 'sc-fixture.cmd'
$script:expectedWindowsRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($script:expectedWindowsRoot)) {throw 'NF_WINDOWS_SPECIAL_FOLDER_UNAVAILABLE'}
$script:seenRoot=$null
$script:scCalls=0
$script:cimCalls=0
$script:cimOwner='S-1-5-18'
$script:cimReturn=0
$script:cimThrows=$false
# Shadow only the native binary path resolution and CIM method, never the
# production function itself. The real wrapper still executes its own parsing.
function Join-Path {
    param([string]$Path,[string]$ChildPath)
    if ($ChildPath -cne 'System32\sc.exe') {
        throw ('NF_TEST_UNEXPECTED_JOIN_PATH:'+ $ChildPath)
    }
    $script:seenRoot=$Path
    $script:scCalls++
    return $script:mockScPath
}
function Invoke-CimMethod {
    param($InputObject,[string]$MethodName,$ErrorAction)
    $script:cimCalls++
    if ($MethodName -cne 'GetSecurityDescriptor' -or
        $InputObject.Name -cne 'NeurofactoryCoreHost') {
        throw 'NF_TEST_UNEXPECTED_CIM_METHOD'
    }
    if ($script:cimThrows) {throw 'NF_TEST_CIM_FAILURE'}
    return [pscustomobject]@{
        ReturnValue=$script:cimReturn
        Descriptor=[pscustomobject]@{
            Owner=[pscustomobject]@{SIDString=$script:cimOwner}
        }
    }
}
function FakeSc([string]$Output,[int]$ExitCode=0) {
    $lines=@(
        '@echo off',
        'if /I not "%~1"=="sdshow" exit /b 98',
        'if /I not "%~2"=="NeurofactoryCoreHost" exit /b 99'
    )
    foreach($line in ($Output -split ([char]10))) {
        if ($line.Length -gt 0) {$lines+=('echo '+$line)}
    }
    $lines+=('exit /b '+$ExitCode)
    [IO.File]::WriteAllLines($script:mockScPath,$lines,[Text.Encoding]::ASCII)
}
$script:service=[pscustomobject]@{Name='NeurofactoryCoreHost'}
$script:safeDacl='D:(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)(A;;0x00000005;;;AU)'
function ExpectDeny([string]$Label,[string]$Expected) {
    try {
        Assert-NfActualScmServiceDacl 'NeurofactoryCoreHost' $script:service
        throw ('NF_SCM_WRAPPER_NEGATIVE_BYPASS:'+ $Label)
    } catch {
        if ($_.Exception.Message -notlike ('*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$Expected+'*')) {
            throw ('NF_WRONG_REFUSAL_'+$Label+': '+$_.Exception.Message)
        }
        Write-Output ('PASS_DENY:'+ $Label)
    }
}
$originalRoot=$env:SystemRoot
try {
    # A caller can spoof process environment but must not choose the
    # executable that supplies the service DACL for a physical decision.
    $env:SystemRoot=$script:tempRoot
    FakeSc $script:safeDacl
    Assert-NfActualScmServiceDacl 'NeurofactoryCoreHost' $script:service
    if ($script:seenRoot -cne $script:expectedWindowsRoot -or
        $script:seenRoot -ceq $env:SystemRoot -or $script:scCalls -ne 1 -or
        $script:cimCalls -ne 1) {
        throw 'NF_SCM_WRAPPER_ENV_ROOT_SPOOF_NOT_BLOCKED'
    }
    Write-Output 'PASS_ALLOW:os_windows_root_not_caller_environment'
    FakeSc ('O:SYG:SY'+$script:safeDacl)
    Assert-NfActualScmServiceDacl 'NeurofactoryCoreHost' $script:service
    Write-Output 'PASS_ALLOW:explicit_matching_sddl_owner'
    FakeSc ('O:BAG:BA'+$script:safeDacl)
    ExpectDeny 'cim_and_sc_owner_disagree' 'SCM_SERVICE_OWNER_QUERIES_DISAGREE'
    FakeSc $script:safeDacl
    $script:cimOwner='S-1-5-32-545'
    ExpectDeny 'untrusted_cim_owner' 'SCM_SERVICE_OWNER_NOT_SYSTEM_OR_ADMINISTRATORS'
    $script:cimOwner='S-1-5-18'
    $script:cimReturn=5
    ExpectDeny 'cim_access_denied' 'SCM_SERVICE_OWNER_NOT_SYSTEM_OR_ADMINISTRATORS'
    $script:cimReturn=0
    $script:cimThrows=$true
    ExpectDeny 'cim_method_error' 'SCM_SERVICE_OWNER_QUERY_FAILED'
    $script:cimThrows=$false
    FakeSc $script:safeDacl 23
    ExpectDeny 'sc_nonzero_exit' 'SCM_SERVICE_SECURITY_QUERY_FAILED'
    FakeSc ($script:safeDacl+([char]10)+$script:safeDacl)
    ExpectDeny 'multiple_sddl_lines' 'SCM_SERVICE_SDDL_NOT_UNAMBIGUOUS'
    FakeSc 'not-an-sddl'
    ExpectDeny 'no_sddl_line' 'SCM_SERVICE_SDDL_NOT_UNAMBIGUOUS'
    FakeSc 'D:(A;;0x000F01FF;;;SY)(A;;0x00000002;;;AU)'
    ExpectDeny 'untrusted_service_change_config' 'UNTRUSTED_PRINCIPAL_CAN_CONTROL_WINDOWS_SERVICE'
    try {
        Assert-NfActualScmServiceDacl 'OtherService' $script:service
        throw 'NF_UNPINNED_SERVICE_WAS_ACCEPTED'
    } catch {
        if ($_.Exception.Message -notlike '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: UNPINNED_SCM_SERVICE_NAME*') {throw}
    }
    Write-Output 'PASS_DENY:untrusted_service_name'
    Write-Output 'NF_ACTUAL_SCM_WRAPPER_NEGATIVE_INTEGRATION=PASS_TEST_ONLY'
} finally {
    $env:SystemRoot=$originalRoot
    [IO.Directory]::Delete($script:tempRoot,$true)
}
