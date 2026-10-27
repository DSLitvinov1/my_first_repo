<#
  НЕЙРОЗАВОД: local Windows owner read-only PRE-ACCEPTANCE.
  Never enrolls owner signer, starts services, installs packages, requests admin
  privileges, downloads models, executes queue tasks or modifies user files.

  This is a diagnostic for a previously installed inert REVIEW build only.
  Operator must externally compare expected components manifest SHA-256 against
  exact reviewed Windows artifact; the installed manifest cannot approve itself.
  Unsigned software can NEVER yield production APPROVED status.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [Parameter(Mandatory=$true)][string]$ExpectedComponentsManifestSha256,
    [switch]$ObserveLocalOllama,
    [ValidateSet('Review','Production')][string]$AcceptanceMode='Review'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Deny([string]$why) {throw ('NF_OWNER_ACCEPTANCE_DENIED: '+$why)}
if ($env:OS -cne 'Windows_NT') {Deny 'WINDOWS_ONLY'}
if ($AcceptanceMode -cne 'Review') {Deny 'PRODUCTION_REQUIRES_INDEPENDENT_PHYSICAL_AUTHORITY'}
if ($ExpectedComponentsManifestSha256 -cnotmatch '^[a-fA-F0-9]{64}$') {
    Deny 'EXTERNALLY_PINNED_MANIFEST_SHA256_REQUIRED'
}
if (-not [IO.Path]::IsPathFullyQualified($InstallDir)) {
    Deny 'INSTALL_ROOT_MUST_BE_ABSOLUTE'
}
$root=[IO.Path]::GetFullPath($InstallDir)
if ($root -match '^[\\]{2}' -or $root -match '^\\\\\?\\') {
    Deny 'NO_NETWORK_OR_DEVICE_PATHS'
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    Deny 'INSTALLED_APPLICATION_NOT_FOUND'
}
function StrictFile([string]$relative,[long]$maxBytes) {
    $parts=$relative.Split('\')
    if ($parts.Length -lt 1 -or @($parts | Where-Object {$_ -in @('','..','.')}).Count -gt 0) {
        Deny 'RELATIVE_SOURCE_PATH_INVALID'
    }
    $cursor=$root
    foreach ($part in $parts) {
        $cursor=Join-Path $cursor $part
        $fi=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Deny 'INSTALL_TREE_LINK_OR_REPARSE_POINT'
        }
    }
    if (-not (Test-Path -LiteralPath $cursor -PathType Leaf)) {
        Deny ('REQUIRED_FILE_NOT_FOUND: '+$relative)
    }
    $info=Get-Item -LiteralPath $cursor -Force
    if ($info.Length -lt 1 -or $info.Length -gt $maxBytes) {
        Deny 'FILE_SIZE_OUTSIDE_BOUND'
    }
    return $info.FullName
}
$manifestFile=StrictFile 'components\manifest.json' 32768
$observed=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash
if ($observed.ToUpperInvariant() -cne $ExpectedComponentsManifestSha256.ToUpperInvariant()) {
    Deny 'INSTALLED_MANIFEST_NOT_INDEPENDENTLY_PINNED'
}
$manifest=Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 |
    ConvertFrom-Json -ErrorAction Stop
$keys=@($manifest.PSObject.Properties.Name)
$allowed=@('schema','source','core_queue_wired','host_service_enrolled',
           'model_weights_verified','release_approved','handoff_enabled',
           'independent_review_complete','entries')
if (@(Compare-Object $keys $allowed).Count -ne 0) {Deny 'INSTALLED_MANIFEST_SCHEMA_INVALID'}
if ($manifest.schema -cne 'neurofactory.installed_components.v1' -or
    $manifest.source -cne 'pinned_git_blobs_only' -or
    @($manifest.entries).Count -ne 15 -or
    $manifest.core_queue_wired -cne $false -or
    $manifest.host_service_enrolled -cne $false -or
    $manifest.model_weights_verified -cne $false -or
    $manifest.release_approved -cne $false -or
    $manifest.handoff_enabled -cne $false -or
    $manifest.independent_review_complete -cne $false) {
    Deny 'REVIEW_ONLY_COMPONENT_FLAGS_NOT_SEALED'
}
$seen=New-Object 'System.Collections.Generic.HashSet[string]'
foreach($entry in $manifest.entries) {
    if (@(Compare-Object @($entry.PSObject.Properties.Name) @(
      'role','file','source_commit','git_blob','sha256','bytes')).Count -ne 0) {
        Deny 'COMPONENT_ENTRY_FIELDS_CHANGED'
    }
    if ($entry.role -cnotmatch '^(core|host|providers|coordinator)$' -or
        $entry.file -cnotmatch '^[A-Za-z0-9_]+[.]py$' -or
        $entry.source_commit -cnotmatch '^[a-f0-9]{40}$' -or
        $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $entry.git_blob -cnotmatch '^[a-f0-9]{40}$' -or
        $entry.bytes -isnot [long] -and $entry.bytes -isnot [int]) {
        Deny 'COMPONENT_ENTRY_INVALID'
    }
    $key=$entry.role+'/'+$entry.file
    if (-not $seen.Add($key)) {Deny 'DUPLICATED_COMPONENT'}
    $relative='components\'+$entry.role+'\'+$entry.file
    $file=StrictFile $relative 250000
    if ((Get-Item -LiteralPath $file).Length -ne [long]$entry.bytes -or
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne
         $entry.sha256) {
        Deny 'COMPONENT_SHA256_DIVERGED'
    }
}
foreach($name in @('runtime\python.exe','app\local_workspace.py','ui\index.html',
                 'ui\app.js','start_neurofactory.cmd','README.txt')) {
    [void](StrictFile $name 12000000)
}
$service=Get-CimInstance Win32_Service -Filter "Name='NeurofactoryCoreHost'" -ErrorAction Stop
if ($null -ne $service -and $service.State -ceq 'Running') {
    # An already active foreign service cannot receive a review-only pass.
    Deny 'EXISTING_ACTIVE_CORE_HOST_REQUIRES_SEPARATE_IDENTITY_AUDIT'
}
$ollama='NOT_OBSERVED'
if ($ObserveLocalOllama) {
    try {
        $probe=Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -Method Get -TimeoutSec 2
        $names=@($probe.models|ForEach-Object {$_.name})
        if (@($names|Where-Object {$_ -match '^qwen'}).Count -gt 0) {
            $ollama='QWEN_LOCAL_INVENTORY_PRESENT_NO_INFERENCE'
        } else {
            $ollama='OLLAMA_LOCAL_NO_QWEN_REPORTED'
        }
    } catch {
        $ollama='OLLAMA_LOCAL_NOT_RUNNING_OR_UNREACHABLE'
    }
}
$dataDir=Join-Path $env:LOCALAPPDATA 'NeurofactoryData'
$userDb=Test-Path -LiteralPath (Join-Path $dataDir 'workspace.sqlite3') -PathType Leaf
$report=[ordered]@{
    schema='nf.windows.owner_readonly_review.v1'
    status='REVIEW_COMPONENTS_MATCH_PIN_NO_PRODUCTION_AUTHORITY'
    source_manifest_sha256=$observed.ToLowerInvariant()
    pinned_components_verified=$seen.Count
    windows_platform='Windows'
    package_is_independently_publisher_signed=$false
    production_release_authorized=$false
    service_running=$false
    core_queue_execution_enabled=$false
    host_effects_allowed=$false
    local_qwen_inventory=$ollama
    user_sqlite_database_present=[bool]$userDb
    external_witness_provisioned_by_this_check=$false
    owner_local_install_and_reboot_accepted=$false
    full_physical_acceptance='NOT_COMPLETE'
    changes_to_user_system=0
}
$report|ConvertTo-Json -Compress -Depth 4
