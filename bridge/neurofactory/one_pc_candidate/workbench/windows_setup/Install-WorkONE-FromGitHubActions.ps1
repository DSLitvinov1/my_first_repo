# GitHub Actions owner-PC installer for ONLY the portable Work ONE user app.
# Does NOT touch CORE9, Windows services, Linux witness, existing projects or keys.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Inspect','Install')]
    [string]$Mode,
    [Parameter(Mandatory=$true)]
    [string]$PackageDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ExpectedComputer='WIN-LIDC05TBOQD'
$ExpectedRelease='b0345ee50d09be499d6ecbf8b858d77d48d2e5b0'
function Deny([string]$Reason) { throw ('NF_OWNER_WORKONE_' + $Reason) }
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_OS -cne 'Windows' -or
    $env:RUNNER_ENVIRONMENT -cne 'self-hosted') {
    Deny 'SELF_HOSTED_WINDOWS_REQUIRED'
}
if ($env:COMPUTERNAME -ine $ExpectedComputer) { Deny 'WRONG_OWNER_DEVICE' }
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0 -or
    -not [Environment]::UserInteractive) { Deny 'INTERACTIVE_USER_REQUIRED' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Deny 'ELEVATED_RUNNER_REFUSED'
}
if ($identity.IsSystem -or $identity.IsGuest -or $identity.IsAnonymous) {
    Deny 'NON_OWNER_WINDOWS_IDENTITY'
}
$console=Get-CimInstance Win32_ComputerSystem
if ([string]::IsNullOrWhiteSpace($console.UserName) -or
    $console.UserName -ine $identity.Name) {
    Deny 'RUNNER_USER_NOT_DESKTOP_OWNER'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)) {
    Deny 'USER_PROFILE_OR_WORKSPACE_MISSING'
}
$workspace=[IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\','/') + '\'
$source=[IO.Path]::GetFullPath($PackageDirectory).TrimEnd('\','/')
if (-not $source.StartsWith($workspace,[StringComparison]::OrdinalIgnoreCase)) {
    Deny 'PACKAGE_OUTSIDE_ACTIONS_WORKSPACE'
}
$sourceItem=Get-Item -LiteralPath $source -Force -ErrorAction Stop
if (-not $sourceItem.PSIsContainer -or
    ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    Deny 'PACKAGE_ROOT_UNTRUSTED'
}
$manifest=Join-Path $source 'manifest.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    Deny 'RELEASE_MANIFEST_MISSING'
}
$spec=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
if ($spec.schema -cne 'nf.workone.personal-bundle.v1' -or
    $spec.source_sha -cne $ExpectedRelease -or
    $spec.portable_runtime -ne $true -or
    $spec.installs_windows_service -ne $false -or
    $spec.contains_secrets -ne $false) {
    Deny 'RELEASE_MANIFEST_MISMATCH'
}
$python=Join-Path $source 'runtime\python\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    Deny 'EMBEDDED_PYTHON_MISSING'
}
# Exact file allowlist; no artifact extras or untracked script execution.
$expected=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
[void]$expected.Add('manifest.json')
foreach ($name in @($spec.file_digests.PSObject.Properties.Name) +
                 @($spec.vendor_file_digests.PSObject.Properties.Name)) {
    [void]$expected.Add(([string]$name).Replace('\','/'))
}
$found=0
foreach ($entry in Get-ChildItem -LiteralPath $source -Recurse -Force) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Deny 'PACKAGE_REPARSE_POINT'
    }
    if ($entry.PSIsContainer) { continue }
    $relative=$entry.FullName.Substring($source.Length+1).Replace('\','/')
    if (-not $expected.Contains($relative)) { Deny 'PACKAGE_UNTRACKED_FILE' }
    $found++
}
if ($found -ne $expected.Count) { Deny 'PACKAGE_FILE_COUNT_MISMATCH' }
& $python (Join-Path $source 'private_preflight_one.py') | Out-Null
if ($LASTEXITCODE -ne 0) { Deny 'SHA256_PREFLIGHT_FAILED' }
Write-Output 'WORKONE_OWNER_WINDOWS_PHYSICAL_SESSION=VERIFIED'
Write-Output 'WORKONE_SIGNED_MANIFEST_AND_VENDOR_SHA256=VERIFIED'
Write-Output ('WORKONE_VERIFIED_FILE_COUNT=' + $found)
if ($Mode -ceq 'Inspect') {
    Write-Output 'WORKONE_ACTIONS_INSPECT_ONLY_NO_FILE_CHANGES=YES'
    exit 0
}
# Only a new versioned per-user release, not the existing app or CORE/HOST.
$base=Join-Path $env:LOCALAPPDATA 'NeirozavodWorkONEPrivatePilot'
$releases=Join-Path $base 'releases'
foreach ($dir in @($base,$releases)) {
    if (Test-Path -LiteralPath $dir) {
        $obj=Get-Item -LiteralPath $dir -Force
        if (-not $obj.PSIsContainer -or
            ($obj.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Deny 'STATE_PATH_NOT_TRUSTED'
        }
    } else {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}
$releaseName='work-one-' + $ExpectedRelease.Substring(0,12)
$target=Join-Path $releases $releaseName
if (Test-Path -LiteralPath $target) {
    $targetItem=Get-Item -LiteralPath $target -Force
    if (-not $targetItem.PSIsContainer -or
        ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'EXISTING_RELEASE_NOT_TRUSTED'
    }
    & (Join-Path $target 'runtime\python\python.exe') (Join-Path $target 'private_preflight_one.py') | Out-Null
    if ($LASTEXITCODE -ne 0) { Deny 'EXISTING_RELEASE_INTEGRITY_FAILED' }
    Write-Output 'WORKONE_OWNER_RELEASE_ALREADY_INSTALLED=YES'
    exit 0
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_RUN_ID) -or
    $env:GITHUB_RUN_ID -notmatch '^[0-9]{8,18}$') {
    Deny 'GITHUB_RUN_ID_UNTRUSTED'
}
$stage=Join-Path $releases ('.staging-' + $env:GITHUB_RUN_ID)
if (Test-Path -LiteralPath $stage) { Deny 'STAGE_ALREADY_EXISTS' }
New-Item -ItemType Directory -Path $stage | Out-Null
$committed=$false
try {
    foreach ($child in Get-ChildItem -LiteralPath $source -Force) {
        Copy-Item -LiteralPath $child.FullName -Destination $stage -Recurse -Force
    }
    $stagePython=Join-Path $stage 'runtime\python\python.exe'
    & $stagePython (Join-Path $stage 'private_preflight_one.py') | Out-Null
    if ($LASTEXITCODE -ne 0) { Deny 'STAGED_RELEASE_INTEGRITY_FAILED' }
    Move-Item -LiteralPath $stage -Destination $target -ErrorAction Stop
    $committed=$true
} finally {
    if (-not $committed -and (Test-Path -LiteralPath $stage)) {
        # Only our unique newly-created staging folder is ever removed.
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
& (Join-Path $target 'runtime\python\python.exe') (Join-Path $target 'private_preflight_one.py') | Out-Null
if ($LASTEXITCODE -ne 0) { Deny 'INSTALLED_RELEASE_INTEGRITY_FAILED' }
# Write only an own app launcher shortcut. Existing shortcuts are left untouched.
$shortcuts=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$link=Join-Path $shortcuts 'Neirozavod Work ONE.lnk'
if (-not (Test-Path -LiteralPath $link)) {
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut($link)
    $shortcut.TargetPath=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $shortcut.Arguments='-NoProfile -File "' + (Join-Path $target 'START_PRIVATE_WORK_ONE.ps1') + '"'
    $shortcut.WorkingDirectory=$target
    $shortcut.Description='Work ONE local private portable'
    $shortcut.Save()
}
Write-Output 'WORKONE_OWNER_RELEASE_INSTALLED=YES'
Write-Output ('WORKONE_SOURCE_SHA=' + $ExpectedRelease)
Write-Output 'WORKONE_EXISTING_NEUROFACTORY_CORE_HOST_UNCHANGED=YES'
Write-Output 'WORKONE_DESKTOP_QWEN_E2E_NOT_YET_TESTED=YES'
