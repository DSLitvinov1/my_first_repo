# Build a self-contained, private Work ONE Windows source/runtime bundle.
# GitHub-hosted Windows runner ONLY; never a self-hosted user PC.
[CmdletBinding()]
param([string]$SourceRoot='bridge/neurofactory/one_pc_candidate/workbench',
      [string]$Output='bundle_output/Work_ONE_Private_Ready')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows') {
  throw 'BUNDLE_DISPOSABLE_WINDOWS_RUNNER_ONLY'
}
$source=(Resolve-Path -LiteralPath $SourceRoot).Path
$destination=[IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $destination) { throw 'BUNDLE_NO_OVERWRITE' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$names=@(
  'work_core.py','work_server.py','agent_one.py',
  'browser_control.py','browser_typing.cjs','browser_worker.cjs',
  'workflow_one.py','desktop_one.py','desktop_worker.ps1',
  'credentials_one.py','google_oauth_one.py','service_one.py',
  'qwen_planner_one.py','llama_connector_one.py',
  'personal_readiness_one.py','private_flow_one.py',
  'index.html','styles.css','app.js','toolmesh.js',
  'package.json','package-lock.json','README.md',
  'START_PRIVATE_WORK_ONE.ps1','PERSONAL_START_README.md',
  'private_preflight_one.py','portable_runtime_one.py','SETUP_LOCAL_QWEN.ps1'
)
if ($names.Count -ne 28) {throw 'BUNDLE_SOURCE_ALLOWLIST_CHANGED'}
$digests=@{}
foreach ($name in $names) {
  if ($name -notmatch '^[A-Za-z0-9_.-]{2,90}$') {throw 'BUNDLE_UNSAFE_SOURCE_NAME'}
  $entry=Get-Item -LiteralPath (Join-Path $source $name) -Force -ErrorAction Stop
  if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
      $entry.Length -gt 524288) {throw 'BUNDLE_UNSAFE_SOURCE_FILE'}
  Copy-Item -LiteralPath $entry.FullName -Destination (Join-Path $destination $name)
  $digest=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  if ((Get-FileHash -LiteralPath (Join-Path $destination $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {
    throw 'BUNDLE_COPY_DIGEST_MISMATCH'
  }
  $digests[$name]=$digest
}
$pythonZip=Join-Path $env:RUNNER_TEMP 'python-3.12.10-embed-amd64.zip'
Invoke-WebRequest 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip' -OutFile $pythonZip -MaximumRedirection 2 -TimeoutSec 180
if ((Get-Item $pythonZip).Length -ne 11133606 -or
    (Get-FileHash $pythonZip -Algorithm SHA256).Hash.ToUpperInvariant() -cne '4ACBED6DD1C744B0376E3B1CF57CE906F9DC9E95E68824584C8099A63025A3C3') {
  throw 'BUNDLE_OFFICIAL_PYTHON_HASH_MISMATCH'
}
$pythonDir=Join-Path $destination 'runtime/python'
Expand-Archive -LiteralPath $pythonZip -DestinationPath $pythonDir
$python=Join-Path $pythonDir 'python.exe'
if (!(Test-Path -LiteralPath $python -PathType Leaf)) {throw 'BUNDLE_PYTHON_MISSING'}
& $python -c 'import sys,sqlite3; assert sys.version_info >= (3,12); sqlite3.connect(":memory:").close()'
if ($LASTEXITCODE -ne 0) {throw 'BUNDLE_EMBEDDED_PYTHON_BROKEN'}
$nodeVersion='v24.22.3'
$nodeName='node-v24.22.3-win-x64.zip'
$nodeBase='https://nodejs.org/dist/'+$nodeVersion+'/'
$sums=Join-Path $env:RUNNER_TEMP 'node-sha256.txt'
$nodeZip=Join-Path $env:RUNNER_TEMP $nodeName
Invoke-WebRequest ($nodeBase+'SHASUMS256.txt') -OutFile $sums -MaximumRedirection 2 -TimeoutSec 120
$matches=@(Get-Content -LiteralPath $sums | Where-Object { $_ -match ([regex]::Escape($nodeName)+'$') })
if ($matches.Count -ne 1) {throw 'BUNDLE_OFFICIAL_NODE_SHA_NOT_FOUND'}
$expected=($matches[0].Trim() -split '\s+')[0].ToLowerInvariant()
if ($expected -notmatch '^[a-f0-9]{64}$') {throw 'BUNDLE_OFFICIAL_NODE_SHA_INVALID'}
Invoke-WebRequest ($nodeBase+$nodeName) -OutFile $nodeZip -MaximumRedirection 2 -TimeoutSec 180
if ((Get-FileHash $nodeZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) {
  throw 'BUNDLE_OFFICIAL_NODE_HASH_MISMATCH'
}
$unpacked=Join-Path $env:RUNNER_TEMP 'NF_NODE_UNPACKED'
Expand-Archive -LiteralPath $nodeZip -DestinationPath $unpacked
$nodeHome=Join-Path $unpacked 'node-v24.22.3-win-x64'
$nodeDir=Join-Path $destination 'runtime/node'
New-Item -ItemType Directory -Path $nodeDir | Out-Null
Copy-Item -LiteralPath (Join-Path $nodeHome 'node.exe') -Destination $nodeDir
Copy-Item -LiteralPath (Join-Path $nodeHome 'LICENSE') -Destination $nodeDir
$node=Join-Path $nodeDir 'node.exe'
& $node -e 'if (!process.version.startsWith("v24.")) process.exit(1)'
if ($LASTEXITCODE -ne 0) {throw 'BUNDLE_NODE_RUNTIME_BROKEN'}
Push-Location $destination
try {
  $env:PUPPETEER_SKIP_DOWNLOAD='1'
  & npm.cmd ci --omit=dev --ignore-scripts --no-audit --no-fund
  if ($LASTEXITCODE -ne 0) {throw 'BUNDLE_PUPPETEER_INSTALL_FAILED'}
  $binary=Join-Path $destination 'node_modules/.bin'
  if (Test-Path $binary) {Remove-Item -LiteralPath $binary -Recurse -Force}
  & $node -e 'const p=require("puppeteer-core"); if(typeof p.launch!=="function") process.exit(1)'
  if ($LASTEXITCODE -ne 0) {throw 'BUNDLE_PUPPETEER_RUNTIME_FAILED'}
} finally {
  Pop-Location
}
$vendorDigests=@{}
foreach ($area in @('runtime/python','runtime/node','node_modules')) {
  $vendorRoot=Join-Path $destination $area
  foreach ($item in Get-ChildItem -LiteralPath $vendorRoot -File -Recurse -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'BUNDLE_VENDOR_LINK_REFUSED'}
    $relative=[IO.Path]::GetRelativePath($destination,$item.FullName).Replace('\','/')
    $vendorDigests[$relative]=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}
if (-not $vendorDigests.ContainsKey('runtime/python/python.exe') -or
    -not $vendorDigests.ContainsKey('runtime/node/node.exe') -or
    -not $vendorDigests.ContainsKey('node_modules/puppeteer-core/package.json')) {
  throw 'BUNDLE_VENDOR_REQUIRED_FILE_MISSING'
}
$manifest=@{
  schema='nf.workone.personal-bundle.v1'
  source_sha=$env:GITHUB_SHA
  requires_user_authorization=$true
  installs_windows_service=$false
  contains_secrets=$false
  portable_runtime=$true
  file_digests=$digests
  vendor_file_digests=$vendorDigests
}
$manifest|ConvertTo-Json -Depth 6 -Compress|Set-Content -LiteralPath (Join-Path $destination 'manifest.json') -Encoding UTF8
& $python (Join-Path $destination 'private_preflight_one.py')
if ($LASTEXITCODE -ne 0) {throw 'BUNDLE_INTEGRITY_VALIDATION_FAILED'}
Write-Host ('READY_BUNDLE_SOURCE_FILES='+$digests.Count)
Write-Host ('READY_BUNDLE_VENDOR_FILES='+$vendorDigests.Count)
Write-Host ('READY_BUNDLE_SOURCE_SHA='+$env:GITHUB_SHA)
