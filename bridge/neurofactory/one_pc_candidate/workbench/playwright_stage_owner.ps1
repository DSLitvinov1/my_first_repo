<#
Stage an official Playwright MCP extension configuration for this Windows user.
Does not install extensions, bypass the browser, open CDP, or start a server.
Dry-run by default. Apply only in the owner's INTERACTIVE non-elevated session.
#>
[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference='Stop'
$policyFile=Join-Path $PSScriptRoot 'playwright_owner_mcp.json'
if(!(Test-Path -LiteralPath $policyFile -PathType Leaf)){throw 'PLAYWRIGHT_CONFIG_MISSING'}
$policy=Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json
if($policy.extension -ne $true -or $policy.server.host -ne '127.0.0.1' -or
   $policy.allowUnrestrictedFileAccess -ne $false -or $policy.saveSession -ne $false){
  throw 'PLAYWRIGHT_POLICY_SECURITY_MISMATCH'
}
$origins=@($policy.network.allowedOrigins)
if($origins.Count -lt 8 -or $origins.Count -gt 30){throw 'PLAYWRIGHT_ORIGINS_INVALID'}
foreach($origin in $origins){
  if([string]$origin -notmatch '^https://[a-z0-9.-]+$' -or
     $origin -match '\*' -or $origin -match '^http://'){
    throw 'PLAYWRIGHT_ORIGIN_UNSAFE'
  }
}
$node=Get-Command node -ErrorAction SilentlyContinue
$npx=Get-Command npx.cmd -ErrorAction SilentlyContinue
if(!$node -or !$npx){throw 'NODE_OR_NPX_NOT_INSTALLED'}
if(-not [Environment]::UserInteractive){throw 'OWNER_INTERACTIVE_SESSION_REQUIRED'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  throw 'DO_NOT_INSTALL_AS_ADMINISTRATOR'
}
$base=Join-Path $env:LOCALAPPDATA 'Neirozavod\PlaywrightOwner'
$configDest=Join-Path $base 'playwright_owner_mcp.json'
$clientDest=Join-Path $base 'playwright_client.example.json'
$client=@{
  mcpServers=@{
    'playwright-owner'=@{
      command='npx.cmd'
      args=@('@playwright/mcp@latest','--extension','--config',$configDest)
    }
  }
}
$result=@{
  mode=if($Apply){'apply'}else{'dry-run'}
  status=if($Apply){'LOCAL_FILES_PREPARED'}else{'READY_TO_PREPARE'}
  destination=$base
  extensionPairing='REQUIRES_BROWSER_OWNER_APPROVAL'
  chatgptWorkConnection='REQUIRES_CLIENT_CONFIGURATION'
  currentOwnerSession=[int]([Diagnostics.Process]::GetCurrentProcess().SessionId)
  affectsBrowserPermissions=$false
  startsBrowser=$false
  opensNetworkPorts=$false
}
if($Apply){
  New-Item -ItemType Directory -Path $base -Force | Out-Null
  foreach($candidate in @($configDest,$clientDest)){
    if(Test-Path -LiteralPath $candidate -PathType Leaf){
      $backup=$candidate+'.backup-'+(Get-Date -Format 'yyyyMMddHHmmss')
      Copy-Item -LiteralPath $candidate -Destination $backup -ErrorAction Stop
    }
  }
  Copy-Item -LiteralPath $policyFile -Destination $configDest -Force
  $client|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $clientDest -Encoding UTF8
}
$result|ConvertTo-Json -Depth 4 -Compress
