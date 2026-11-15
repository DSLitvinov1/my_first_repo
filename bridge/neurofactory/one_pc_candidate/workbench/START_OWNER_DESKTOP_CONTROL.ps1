<#
ONE Agent — owner-session interactive activation helper.
This is not remote access bypass. It operates only after the Windows account
owner explicitly executes it in their own visible non-admin desktop.
Playwright controls browser tabs; ONE Desktop is separate UI Automation.
#>
[CmdletBinding()]
param(
  [switch]$Activate,
  [switch]$SkipStartOne
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$install=Join-Path $env:SystemDrive 'ChatGPTProjects\WorkOneStage\qwen-combined-b9fcd433-20261114'
$candidate=Join-Path $env:SystemDrive 'ChatGPTProjects\ONE-Playwright-Candidate-20261115'
$local=Join-Path $env:LOCALAPPDATA 'Neirozavod\PlaywrightOwner'
if(-not [Environment]::UserInteractive -or
   [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){
  throw 'OWNER_INTERACTIVE_WINDOWS_SESSION_REQUIRED'
}
$user=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($user)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  throw 'ONE_OWNER_MUST_RUN_NON_ELEVATED'
}
$expected='b9fcd4337f0f76cca0bcbb41c150e9cfe2582cc8'
$manifest=Join-Path $install 'manifest.json'
if(!(Test-Path -LiteralPath $manifest -PathType Leaf)){
  throw 'INSTALLED_ONE_MANIFEST_NOT_FOUND'
}
$m=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8|ConvertFrom-Json
if([string]$m.source_sha -ne $expected){throw 'ONE_INSTALLED_MANIFEST_CHANGED'}
if(!(Test-Path -LiteralPath $candidate -PathType Container)){
  throw 'PLAYWRIGHT_CANDIDATE_NOT_STAGED'
}
$stage=Join-Path $candidate 'playwright_stage_owner.ps1'
$config=Join-Path $candidate 'playwright_owner_mcp.json'
if(!(Test-Path -LiteralPath $stage -PathType Leaf) -or
   !(Test-Path -LiteralPath $config -PathType Leaf)){
  throw 'PLAYWRIGHT_CANDIDATE_INCOMPLETE'
}
$p=Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
if($p.extension -ne $true -or $p.server.host -ne '127.0.0.1' -or
   $p.saveSession -ne $false -or $p.allowUnrestrictedFileAccess -ne $false){
  throw 'PLAYWRIGHT_CONFIG_UNSAFE'
}
$apps=@('chrome.exe','notepad.exe','explorer.exe')
$hosts=@('potrebpravo.ru','semya-yurist.ru',
  'metrika.yandex.ru','webmaster.yandex.ru','hosting.timeweb.ru',
  'b24-xlzm11.bitrix24.ru','b24-s2dosa.bitrix24site.ru','search.google.com')
$listener=@(Get-NetTCPConnection -State Listen -LocalPort 18770 -ErrorAction SilentlyContinue)
$report=[ordered]@{
  state=if($Activate){'OWNER_SESSION_CONFIGURATION_APPLIED'}else{'READINESS_ONLY'}
  interactive=$true
  admin=$false
  candidatePresent=$true
  baselineVerified=$true
  desktopApps=$apps
  approvedBrowserHosts=$hosts
  existingWorkOneListener=($listener.Count -gt 0)
  localPlaywrightConfigured=$false
  browserExtensionPaired=$false
  chatgptBrowserConnected=$false
  noSecurityBypass=$true
}
if(!$Activate){
  $report|ConvertTo-Json -Depth 5
  return
}
& $stage -Apply
if($LASTEXITCODE -and $LASTEXITCODE -ne 0){
  throw 'PLAYWRIGHT_USER_STAGE_FAILED'
}
if(!(Test-Path -LiteralPath (Join-Path $local 'playwright_owner_mcp.json') -PathType Leaf)){
  throw 'PLAYWRIGHT_USER_STAGE_MISSING'
}
$report.localPlaywrightConfigured=$true
# Never attempt to start the second ONE process while the owner UI is already up.
if($listener.Count -gt 0){
  Write-Host 'ONE Agent is already running at http://127.0.0.1:18770/'
  Write-Host 'Use its local desktop controls; no duplicate process was started.'
}else{
  if(!$SkipStartOne){
    $launcherPaths=@(
      (Join-Path $install 'START_PRIVATE_WORK_ONE.ps1'),
      (Join-Path $install 'workbench\START_PRIVATE_WORK_ONE.ps1')
    )
    $launcher=@($launcherPaths|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf})
    if($launcher.Count -ne 1){
      throw 'ONE_OWNER_LAUNCHER_NOT_UNAMBIGUOUS_CHECK_INSTALLED_LAYOUT'
    }
    Write-Host 'Starting protected ONE desktop in the current owner session.'
    Write-Host 'All new browser tabs and desktop windows require owner approval in the ONE UI.'
    & $launcher[0] -AllowedHosts ($hosts -join ',') -AllowApps ($apps -join ',')
    if($LASTEXITCODE -and $LASTEXITCODE -ne 0){
      throw 'ONE_USER_INTERFACE_EXITED_WITH_ERROR'
    }
  }
}
$report|ConvertTo-Json -Depth 5
Write-Host 'Playwright Extension connection is still owner-controlled; no browser tab was auto-granted.'
