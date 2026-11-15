# Start a separate, owner-only ChatGPT/Playwright ONE pilot without replacing production.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){
  throw 'OWNER_INTERACTIVE_SESSION_REQUIRED'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  throw 'ONE_OWNER_NONADMIN_REQUIRED'
}
if(!$env:LOCALAPPDATA){throw 'ONE_USER_PROFILE_REQUIRED'}
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$python=Join-Path $root 'runtime\python\python.exe'
if(!(Test-Path -LiteralPath $python -PathType Leaf)){throw 'ONE_VERIFIED_EMBEDDED_PYTHON_MISSING'}
# The package is immutable: verify every source and vendored binary before acting.
& $python (Join-Path $root 'private_preflight_one.py')
if($LASTEXITCODE -ne 0){throw 'ONE_PACKAGE_INTEGRITY_REFUSED'}
$stage=Join-Path $root 'playwright_stage_owner.ps1'
if(!(Test-Path -LiteralPath $stage -PathType Leaf)){throw 'ONE_PLAYWRIGHT_STAGE_MISSING'}
& $stage -Apply
if($LASTEXITCODE -and $LASTEXITCODE -ne 0){throw 'ONE_PLAYWRIGHT_LOCAL_STAGE_FAILED'}
$state=Join-Path $env:LOCALAPPDATA 'NeirozavodWorkONEChatGPTPilot'
foreach($folder in @($state,(Join-Path $state 'projects'),(Join-Path $state 'data'))){
  if(Test-Path -LiteralPath $folder){
    $item=Get-Item -LiteralPath $folder -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
      throw 'ONE_CHATGPT_PILOT_DIRECTORY_UNSAFE'
    }
  }else{
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
  }
}
$port=18771
$listener=@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
if($listener.Count -gt 0){throw 'ONE_CHATGPT_PILOT_PORT_IN_USE_NO_RESTART'}
$hosts='potrebpravo.ru,semya-yurist.ru,metrika.yandex.ru,webmaster.yandex.ru,direct.yandex.ru,search.google.com,hosting.timeweb.ru,b24-xlzm11.bitrix24.ru'
Write-Host 'OWNER ONE CHATGPT PILOT: http://127.0.0.1:18771/'
Write-Host 'Old ONE on port 18770 remains untouched.'
Write-Host 'Next: pair the private GitHub Issues bridge inside ONE, approve the Playwright Chrome Extension locally.'
Write-Host 'This pilot does not automatically connect Playwright MCP to ChatGPT or approve Chrome tabs.'
& $python (Join-Path $root 'work_server.py') --root (Join-Path $state 'projects') --data (Join-Path $state 'data') --port $port --open-ui --browser-allow-hosts $hosts
if($LASTEXITCODE -ne 0){throw 'ONE_CHATGPT_PILOT_STOPPED'}
