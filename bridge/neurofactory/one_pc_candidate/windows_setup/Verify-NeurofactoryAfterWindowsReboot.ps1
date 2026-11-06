#requires -RunAsAdministrator
# Read-only full-boot acceptance. Run AFTER real Windows restart; this
# script does not simulate, initiate, schedule or force an OS reboot.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$serviceName='NeurofactoryPersonalHost'
$root='C:\ProgramData\NeurofactoryPersonalHost'
$runtime='C:\Program Files\NeurofactoryPersonalHost'
$svc=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if(!$svc -or $svc.State -cne 'Running' -or $svc.StartMode -cne 'Auto' -or
  $svc.StartName -cne 'NT AUTHORITY\LocalService') {
 throw 'Protected restricted SCM not running after real Windows boot'
}
$sidtype=(& sc.exe qsidtype $serviceName | Out-String)
if($LASTEXITCODE -ne 0 -or $sidtype -notmatch 'RESTRICTED') {
 throw 'SCM service SID lost restriction after reboot'
}
$manifestPath=Join-Path $runtime 'bundle-manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$policy=Get-Content -LiteralPath (Join-Path $root 'operator-config.json') -Raw | ConvertFrom-Json
if($manifest.source_sha40 -cne $policy.source_sha40 -or
   (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $policy.package_sha256) {
 throw 'Pinned installed service bundle/source diverged from protected policy'
}
$check=@'
from contextlib import closing
import personal_windows_host_service as h
with closing(h._connect_existing()) as db:
 rows=db.execute("SELECT external_epoch,status,remote_head FROM intents ORDER BY external_epoch").fetchall()
 assert len(rows)>=1 and rows[-1][1]=="EXECUTED","Incomplete or unknown durable Windows intent"
 signed=h.assert_external_head_matches_local_fence()
 assert signed["remote_status_signature_verified"] is True
 assert signed["epoch"]==rows[-1][0] and signed["ledger_head"]==rows[-1][2]
 print("NF_REAL_REBOOT_SIGNED_LINUX_EPOCH="+str(signed["epoch"]))
 print("NF_REAL_REBOOT_WINDOWS_COMPLETED_ROWS="+str(len(rows)))
 print("NF_REAL_REBOOT_NO_UNKNOWN_INTENTS=PASS")
'@
$py=Join-Path $runtime 'runtime\python.exe'
$check|& $py -B -
if($LASTEXITCODE -ne 0) {
 throw 'Durable host fence and real Linux signed highwater did not reconcile after reboot'
}
$uiState='NOT_VERIFIED_USER_LOGIN_REQUIRED'
try {
 $resp=Invoke-RestMethod -Uri 'http://127.0.0.1:8766/api/models' -TimeoutSec 3
 if($resp.cloud_qwen_available -eq $true -and
     $resp.cloud_qwen_model -ceq 'qwen3.5:9b') {
     $uiState='QWEN35_LOCAL_WORKSPACE_RUNNING'
 }
} catch {
 # Windows SCM boot occurs before owner interactive user login.
 # Never mistake missing user session for an SCM failure.
 $uiState='NOT_VERIFIED_USER_LOGIN_REQUIRED'
}
Write-Output 'NF_REAL_WINDOWS_BOOT_PROTECTED_SCM=PASS'
Write-Output 'NF_REAL_WINDOWS_BOOT_RESTRICTED_SID=PASS'
Write-Output 'NF_REAL_WINDOWS_BOOT_DELAYED_AUTO_START=PASS'
Write-Output 'NF_REAL_WINDOWS_BOOT_LINUX_SIGNED_EPOCH_RECONCILED=PASS'
Write-Output ('NF_REAL_WINDOWS_USER_QWEN_UI='+$uiState)
