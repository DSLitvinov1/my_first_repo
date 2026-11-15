<#
Local ONE / Playwright owner readiness check.
Read-only. No installs, no permission changes, no tokens, no cookie access.
Run in the user's interactive Windows session, never as SYSTEM/service.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$me = [Diagnostics.Process]::GetCurrentProcess()
$node = Get-Command node -ErrorAction SilentlyContinue
$npx = Get-Command npx.cmd -ErrorAction SilentlyContinue
if (-not $npx) { $npx = Get-Command npx -ErrorAction SilentlyContinue }
$chrome = @(Get-Process chrome -ErrorAction SilentlyContinue)
$edge = @(Get-Process msedge -ErrorAction SilentlyContinue)
$opera = @(Get-Process opera -ErrorAction SilentlyContinue)
$policy = @()
foreach ($key in @(
  'HKCU:\SOFTWARE\Policies\Google\Chrome',
  'HKLM:\SOFTWARE\Policies\Google\Chrome',
  'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
  'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
)) {
  if (!(Test-Path -LiteralPath $key)) { continue }
  $record = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
  $policy += @{
    browser = if ($key -match 'Microsoft') { 'Edge' } else { 'Chrome' }
    scope = if ($key.StartsWith('HKLM:')) { 'machine' } else { 'user' }
    remoteDebuggingAllowed = $record.RemoteDebuggingAllowed
    developerToolsAvailability = $record.DeveloperToolsAvailability
    # Do not enumerate URL blocklists, passwords or enterprise policy content.
    managed = $true
  }
}
$report = @{
  status = 'READ_ONLY_PREFLIGHT'
  machine = $env:COMPUTERNAME
  interactive = [Environment]::UserInteractive
  userSession = [int]$me.SessionId
  nodeAvailable = [bool]$node
  npxAvailable = [bool]$npx
  chromeRunning = [bool]$chrome.Count
  edgeRunning = [bool]$edge.Count
  operaRunning = [bool]$opera.Count
  browserProcessCount = ($chrome.Count + $edge.Count + $opera.Count)
  policySummaries = $policy
  playwrightExtensionPaired = 'NOT_VERIFIED_FROM_THIS_PROBE'
  oneChatgptConnection = 'NOT_VERIFIED_FROM_THIS_PROBE'
  modifiesComputer = $false
}
$report | ConvertTo-Json -Depth 5 -Compress
if(-not [Environment]::UserInteractive) {
  Write-Error 'MUST_RUN_IN_OWNER_INTERACTIVE_SESSION'
  exit 3
}
if(-not $node -or -not $npx) {
  Write-Error 'NODE_OR_NPX_MISSING'
  exit 4
}
