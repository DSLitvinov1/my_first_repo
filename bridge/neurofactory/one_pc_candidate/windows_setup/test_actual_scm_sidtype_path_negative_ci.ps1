# Windows-only isolated negative integration of the REAL read-only SID-type preflight function.
# No actual SCM service, machine settings, keys, registry or protected roots are modified.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
$source=Join-Path $PSScriptRoot 'physical_host_production_preflight.ps1'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    $source,[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {throw 'NF_SIDTYPE_SOURCE_NOT_PARSEABLE'}
$defs=@($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-NfActualRestrictedServiceSidType'
},$true))
if ($defs.Count -ne 1) {throw 'NF_SIDTYPE_FUNCTION_NOT_UNIQUE'}
# The original unqualified invocation must not survive anywhere in the script.
if ((Get-Content -LiteralPath $source -Raw) -match '&\s+sc\.exe\s+qsidtype') {
    throw 'NF_SIDTYPE_UNQUALIFIED_NATIVE_LOOKUP'
}
function Deny([string]$why) {throw ('NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$why)}
Invoke-Expression $defs[0].Extent.Text
$script:tempRoot=Join-Path ([IO.Path]::GetTempPath()) ('nf-sidtype-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:tempRoot)
$script:mockScPath=Join-Path $script:tempRoot 'safe-native.cmd'
$script:expectedWindowsRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
if ([string]::IsNullOrWhiteSpace($script:expectedWindowsRoot)) {throw 'NF_WINDOWS_SPECIAL_FOLDER_UNAVAILABLE'}
$script:seenRoot=$null
$script:scCalls=0
function Join-Path {
    param([string]$Path,[string]$ChildPath)
    if ($ChildPath -cne 'System32\sc.exe') {
        throw ('NF_TEST_UNEXPECTED_JOIN_PATH:'+ $ChildPath)
    }
    $script:seenRoot=$Path
    $script:scCalls++
    return $script:mockScPath
}
function FakeSc([string]$Output,[int]$ExitCode=0) {
    $lines=@(
        '@echo off',
        'if /I not "%~1"=="qsidtype" exit /b 98',
        'if /I not "%~2"=="NeurofactoryCoreHost" exit /b 99'
    )
    foreach($line in ($Output -split ([char]10))) {
        if ($line.Length -gt 0) {$lines+=('echo '+$line)}
    }
    $lines+=('exit /b '+$ExitCode)
    [IO.File]::WriteAllLines($script:mockScPath,$lines,[Text.Encoding]::ASCII)
}
function ExpectDeny([string]$Label,[string]$Expected) {
    try {
        [void](Assert-NfActualRestrictedServiceSidType 'NeurofactoryCoreHost')
        throw ('NF_SIDTYPE_NEGATIVE_BYPASS:'+ $Label)
    } catch {
        if ($_.Exception.Message -notlike ('*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: '+$Expected+'*')) {
            throw ('NF_WRONG_SIDTYPE_REFUSAL_'+$Label+': '+$_.Exception.Message)
        }
        Write-Output ('PASS_DENY:'+ $Label)
    }
}
$originalPath=$env:PATH
$originalRoot=$env:SystemRoot
try {
    # Invalid attacker-controlled sc.exe first in PATH: the positive case
    # succeeds only when the preflight uses its trusted absolute OS path.
    [IO.File]::WriteAllBytes(($script:tempRoot+'\sc.exe'),[byte[]]@(0,1,2,3))
    $env:PATH=$script:tempRoot+';'+$originalPath
    $env:SystemRoot=$script:tempRoot
    FakeSc 'SERVICE_SID_TYPE: RESTRICTED'
    [void](Assert-NfActualRestrictedServiceSidType 'NeurofactoryCoreHost')
    if ($script:seenRoot -cne $script:expectedWindowsRoot -or
        $script:seenRoot -ceq $env:SystemRoot -or $script:scCalls -ne 1) {
        throw 'NF_SIDTYPE_PATH_OR_SYSTEMROOT_SPOOF_NOT_BLOCKED'
    }
    Write-Output 'PASS_ALLOW:trusted_windows_sc_path_despite_spoofed_PATH_and_SystemRoot'
    FakeSc ("[SC] QueryServiceConfig2 SUCCESS"+[char]10+"SERVICE_SID_TYPE : RESTRICTED")
    [void](Assert-NfActualRestrictedServiceSidType 'NeurofactoryCoreHost')
    Write-Output 'PASS_ALLOW:single_exact_restricted_field'
    FakeSc 'SERVICE_SID_TYPE: NONE'
    ExpectDeny 'not_restricted' 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    FakeSc 'NOTICE: RESTRICTED'
    ExpectDeny 'misleading_substring' 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    FakeSc ("SERVICE_SID_TYPE: RESTRICTED"+[char]10+"SERVICE_SID_TYPE: NONE")
    ExpectDeny 'duplicate_field' 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    FakeSc 'SERVICE_SID_TYPE: RESTRICTED_EXTRA'
    ExpectDeny 'suffix_instead_of_exact_value' 'NO_RESTRICTED_WINDOWS_SERVICE_SID'
    FakeSc 'SERVICE_SID_TYPE: RESTRICTED' 5
    ExpectDeny 'nonzero_native_exit' 'SCM_SERVICE_SID_TYPE_QUERY_FAILED'
    FakeSc 'SERVICE_SID_TYPE: RESTRICTED'
    try {
        [void](Assert-NfActualRestrictedServiceSidType 'OtherService')
        throw 'NF_SIDTYPE_WRONG_SERVICE_ACCEPTED'
    } catch {
        if ($_.Exception.Message -notlike '*NF_REAL_WINDOWS_HOST_PRECHECK_DENIED: UNPINNED_SCM_SERVICE_NAME*') {throw}
    }
    Write-Output 'PASS_DENY:wrong_service_name'
    Write-Output 'NF_ACTUAL_SCM_SIDTYPE_PATH_NEGATIVE=PASS_TEST_ONLY'
} finally {
    $env:PATH=$originalPath
    $env:SystemRoot=$originalRoot
    [IO.Directory]::Delete($script:tempRoot,$true)
}
