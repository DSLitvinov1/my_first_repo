#requires -RunAsAdministrator
# Completes private self-managed deployment only AFTER Linux forced-witness
# was independently provisioned and returns an authentic signed HEAD=0.
# No fake independent-review or publisher-signature claim is made.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9+/]{43}=$')][string]$WitnessPublicBase64
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$name='NeurofactoryPersonalHost'
$root=Join-Path $env:ProgramData $name
$bin=Join-Path $env:ProgramFiles $name
$reportPath=Join-Path $root 'prepare-report.json'
$configPath=Join-Path $root 'operator-config.json'
$ownerFolder=Join-Path $env:LOCALAPPDATA 'NeurofactoryData\owner-signing'
$ownerKey=Join-Path $ownerFolder 'personal-owner-private.key'
$py=Join-Path $bin 'runtime\python.exe'
$hostScript=Join-Path $bin 'service\personal_windows_host_service.py'
$manifest=Join-Path $bin 'bundle-manifest.json'
if ((Get-Service $name -ErrorAction SilentlyContinue) -or
    !(Test-Path $reportPath) -or
    (Test-Path $configPath) -or
    !(Test-Path $hostScript) -or
    !(Test-Path $ownerKey) -or
    !(Test-Path $py) -or
    (Test-Path (Join-Path $root 'state\intent-fence.sqlite3'))) {
  throw 'MISSING_STAGE_OR_EXISTING_SERVICE/FENCE: NO_RESET_OR_OVERWRITE'
}
$report=Get-Content $reportPath -Raw -Encoding ascii|ConvertFrom-Json
$bundle=Get-Content $manifest -Raw -Encoding utf8|ConvertFrom-Json
if ($report.schema -cne 'nf.personal.host.prepare.v1' -or
    $report.phase -cne 'PREPARED_ONLY_SERVICE_NOT_REGISTERED' -or
    $bundle.source_sha40 -cne $report.source_sha40 -or
    $report.package_sha256 -cne (Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()) {
  throw 'PERSONAL_HOST_RELEASE_PIN_OR_STAGED_PROVENANCE_MISMATCH'
}
try {
  $witnessBytes=[Convert]::FromBase64String($WitnessPublicBase64)
  $ownerBytes=[Convert]::FromBase64String([string]$report.owner_public_base64)
} catch {throw 'INVALID_ED25519_PUBLIC_KEY_ENCODING'}
if ($witnessBytes.Length -ne 32 -or $ownerBytes.Length -ne 32 -or
    $WitnessPublicBase64 -ceq $report.owner_public_base64) {
  throw 'WITNESS_MUST_HAVE_A_SEPARATE_ED25519_KEY'
}
$actualOwner=& $py -B -c 'import base64,sys;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;from cryptography.hazmat.primitives import serialization;k=Ed25519PrivateKey.from_private_bytes(open(sys.argv[1],"rb").read());print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())' $ownerKey
if ($LASTEXITCODE -ne 0 -or $actualOwner.Trim() -cne $report.owner_public_base64) {
  throw 'USER_OWNER_KEY_DOES_NOT_MATCH_PINNED_SCM_IDENTITY'
}
function RunNative([string]$executable,[string[]]$argumentVector) {
  & $executable @argumentVector | Out-Null
  if ($LASTEXITCODE -ne 0) {throw ('PERSONAL_HOST_SETUP_OPERATION_FAILED_'+$executable)}
}
$admin='*S-1-5-32-544'
$system='*S-1-5-18'
$localService='*S-1-5-19'
$user='*'+([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
# Any existing user grants on the trust-root or runtime are forbidden.
RunNative icacls.exe @($bin,'/inheritance:r','/grant:r',
    "${system}:(OI)(CI)F","${admin}:(OI)(CI)F")
RunNative icacls.exe @($root,'/inheritance:r','/grant:r',
    "${system}:(OI)(CI)F","${admin}:(OI)(CI)F",
    "${localService}:(OI)(CI)RX")
# Operator provisioned signer is PUBLIC ONLY, Windows service never holds
# the owner's private signing key.
$config=[ordered]@{
  schema='nf.personal.host.operator_pinned.v1'
  owner_public_base64=$report.owner_public_base64
  witness_public_base64=$WitnessPublicBase64
  source_sha40=$report.source_sha40
  machine_sha256=$report.machine_sha256
  package_sha256=$report.package_sha256
}
$config|ConvertTo-Json|Set-Content -LiteralPath $configPath -Encoding ascii
RunNative icacls.exe @($configPath,'/inheritance:r','/grant:r',
    "${system}:F","${admin}:F")
# Exact startup identity check BEFORE service registration; a timeout is
# a real blocker and must never be "fixed" by resetting the Linux journal.
$script=@'
import base64,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from personal_ssh_highwater_client import read_signed_remote_head
doc=__import__("json").loads(Path(sys.argv[2]).read_text("ascii"))
pub=base64.b64decode(doc["witness_public_base64"],validate=True)
st=read_signed_remote_head(trusted_service_root=Path(sys.argv[3]),
    pinned_public_raw=pub,
    expected_source=doc["source_sha40"],
    expected_machine=doc["machine_sha256"],
    expected_package=doc["package_sha256"])
assert st["remote_status_signature_verified"] is True
assert st["epoch"]==0 and st["ledger_head"]=="0"*64
print("NF_LINUX_REMOTE_SIGNED_ZERO_HEAD_VERIFIED")
'@
& $py -B -c $script (Join-Path $bin 'service') $configPath $root
if ($LASTEXITCODE -ne 0) {throw 'PHYSICAL_LINUX_SIGNED_WITNESS_NOT_READY_STOP_BEFORE_SERVICE_CREATE'}
# Only now allocate local persistent state. NO service ever creates/reset it.
New-Item -ItemType Directory (Join-Path $root 'state'),(Join-Path $root 'inbox'),(Join-Path $root 'outputs') -Force|Out-Null
& $py -B -c 'import sys;sys.path.insert(0,sys.argv[1]);import personal_windows_host_service as h;print(h.provision_empty_fence_offline())' (Join-Path $bin 'service')
if ($LASTEXITCODE -ne 0) {throw 'OWNER_WINDOWS_DURABLE_LOCAL_FENCE_NOT_PROVISIONED'}
$svcBin='"'+$py+'" -u "'+$hostScript+'" --scm'
RunNative sc.exe @('create',$name,'binPath=',$svcBin,
                   'obj=','NT AUTHORITY\LocalService','start=','demand',
                   'DisplayName=','Neurofactory personal protected host')
RunNative sc.exe @('sidtype',$name,'restricted')
$serviceSid=([Security.Principal.NTAccount]("NT SERVICE\"+$name)).
             Translate([Security.Principal.SecurityIdentifier]).Value
if (!$serviceSid.StartsWith('S-1-5-80-')) {throw 'ACTUAL_WINDOWS_SERVICE_SID_NOT_RESTRICTED'}
$svc='*'+$serviceSid
RunNative icacls.exe @($bin,'/grant:r',"${svc}:(OI)(CI)RX")
RunNative icacls.exe @($root,'/grant:r',"${svc}:(OI)(CI)RX")
RunNative icacls.exe @($configPath,'/grant:r',"${svc}:R")
RunNative icacls.exe @((Join-Path $root 'known_hosts'),'/grant:r',"${svc}:R")
RunNative icacls.exe @((Join-Path $root 'remote-client-id_ed25519'),
    '/grant:r',"${svc}:R")
RunNative icacls.exe @((Join-Path $root 'state'),'/inheritance:r',
    '/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F","${svc}:(OI)(CI)M")
RunNative icacls.exe @((Join-Path $root 'state\intent-fence.sqlite3'),
    '/inheritance:r','/grant:r',"${system}:F","${admin}:F","${svc}:M")
RunNative icacls.exe @((Join-Path $root 'inbox'),'/inheritance:r',
    '/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F",
    "${svc}:(OI)(CI)RX","${user}:(OI)(CI)M")
RunNative icacls.exe @((Join-Path $root 'outputs'),'/inheritance:r',
    '/grant:r',"${system}:(OI)(CI)F","${admin}:(OI)(CI)F",
    "${svc}:(OI)(CI)M")
# Neither unrelated users nor the shared LocalService logon SID may
# write the service-owned output or local highwater journal.
RunNative icacls.exe @((Join-Path $root 'outputs'),'/remove:g',$localService)
RunNative sc.exe @('config',$name,'start=','delayed-auto')
RunNative sc.exe @('failure',$name,'reset=','3600',
                   'actions=','restart/6000/restart/15000/none/0')
RunNative sc.exe @('start',$name)
Start-Sleep -Seconds 2
$observed=Get-CimInstance Win32_Service -Filter "Name='$name'"
if ($null -eq $observed -or $observed.State -cne 'Running' -or
    $observed.StartName -notmatch 'LocalService') {
  throw 'PROTECTED_PERSONAL_WINDOWS_SCM_FAILED_AFTER_INSTALL_STOP_AND_AUDIT'
}
Write-Output 'NF_PERSONAL_WINDOWS_SCM_RUNNING=TRUE'
Write-Output 'NF_PERSONAL_WINDOWS_SCM_ACCOUNT=NT_AUTHORITY_LOCAL_SERVICE'
Write-Output ('NF_PERSONAL_WINDOWS_SCM_RESTRICTED_SERVICE_SID='+$serviceSid)
Write-Output 'NF_SIGNED_LINUX_HIGHWATER_ZERO_HEAD=CONFIRMED'
Write-Output 'NF_ARBITRARY_QWEN_COMMANDS_PERMITTED=FALSE'
Write-Output 'NF_SELF_MANAGED_NOT_INDEPENDENT_LINUX_OPERATOR=TRUE'
