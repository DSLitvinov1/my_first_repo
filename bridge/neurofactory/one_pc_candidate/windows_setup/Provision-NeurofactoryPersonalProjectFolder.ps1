#requires -RunAsAdministrator
# Local personal project source sandbox, no resets or external side effects.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^[a-f0-9]{32}$')]
  [string]$ProjectId
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root='C:\ProgramData\NeurofactoryPersonalHost'
$projects=Join-Path $root 'projects'
$project=Join-Path $projects $ProjectId
$serviceName='NeurofactoryPersonalHost'
$state=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if(!$state -or $state.StartName -cne 'NT AUTHORITY\LocalService' -or
    $state.StartMode -ne 'Auto') {
    throw 'Protected personal LocalService must already be installed'
}
$serviceSid=([Security.Principal.NTAccount]('NT SERVICE\'+$serviceName)).
    Translate([Security.Principal.SecurityIdentifier]).Value
if(!$serviceSid.StartsWith('S-1-5-80-')) {throw 'Restricted service SID missing'}
$manifest=Join-Path 'C:\Program Files\NeurofactoryPersonalHost' 'bundle-manifest.json'
if(!(Test-Path $manifest) -or !(Test-Path (Join-Path $root 'operator-config.json'))) {
    throw 'Existing pinned runtime and policy required'
}
foreach($dir in @($root, 'C:\Program Files\NeurofactoryPersonalHost')) {
    if((Get-Item $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Reparse point in protected service roots'
    }
}
if(Test-Path -LiteralPath $project) {throw 'Existing project folder: never reset'}
if(Test-Path -LiteralPath $projects) {
    if((Get-Item $projects).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Existing workspaces root redirected'
    }
} else {
    New-Item -ItemType Directory -Path $projects -ErrorAction Stop | Out-Null
}
$service='*'+$serviceSid
$system='*S-1-5-18'
$admins='*S-1-5-32-544'
$user='*'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function SecurePath([string]$path) {
    $argsVector=@($path,'/inheritance:r','/grant:r',
       ('{0}:(OI)(CI)F' -f $system),
       ('{0}:(OI)(CI)F' -f $admins),
       ('{0}:(OI)(CI)M' -f $service),
       ('{0}:(OI)(CI)RX' -f $user))
    & icacls.exe @argsVector | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Protected folder ACL setup failed'}
}
SecurePath $projects
# The owner's NON-elevated console must inspect public policy but may never
# change it. Allow read-only of public pins; private SSH/witness keys stay
# SYSTEM/Administrators/ServiceSID only.
$operatorConfig=Join-Path $root 'operator-config.json'
& icacls.exe $operatorConfig '/grant:r' ('{0}:R' -f $user) | Out-Null
if($LASTEXITCODE -ne 0){throw 'Owner cannot read pinned public policy'}
New-Item -ItemType Directory -Path $project -ErrorAction Stop | Out-Null
SecurePath $project
$acl=Get-Acl $project
$actual=@($acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $serviceSid
})
if($actual.Count -ne 1) {throw 'Project folder not owned by restricted service SID'}
Write-Output ('NF_PERSONAL_HOST_PROJECT_SANDBOX_READY='+$project)
Write-Output 'NF_PERSONAL_HOST_ONE_USE_SOURCE_CREATE_ONLY=TRUE'
Write-Output 'NF_PERSONAL_HOST_UNTRUSTED_QWEN_OS_COMMAND_ALLOWED=FALSE'
