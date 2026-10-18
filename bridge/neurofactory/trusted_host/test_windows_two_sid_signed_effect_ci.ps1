# DISPOSABLE GITHUB WINDOWS RUNNER ONLY. Never run on an owner's PC.
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:NF_WINDOWS_TWO_SID_CI_ONLY -ne '1') {throw 'CI only'}
$actor=Join-Path $PSScriptRoot 'windows_two_sid_pilot_actor.py'
$python=(Get-Command python).Source
$tag=([guid]::NewGuid().ToString('N')).Substring(0,7)
$rc="nf_rc_$tag"; $wk="nf_wk_$tag"
$stage=Join-Path $env:RUNNER_TEMP "nf-two-sid-$tag"
$null=New-Item -Type Directory -Path $stage -Force
$pw1=ConvertTo-SecureString ([Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36))) -AsPlainText -Force
$pw2=ConvertTo-SecureString ([Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(36))) -AsPlainText -Force
$created=@()
function CheckProc($item,$label) {
    $item.proc.WaitForExit(15000) | Out-Null
    if (!$item.proc.HasExited) {$item.proc.Kill();throw "timeout $label"}
    if ($item.proc.ExitCode -ne 0) {
        $err=if(Test-Path $item.err){Get-Content -Raw $item.err}else{''}
        $out=if(Test-Path $item.out){Get-Content -Raw $item.out}else{''}
        throw "$label exit=$($item.proc.ExitCode) output=$out error=$err"
    }
}
function Actor($cred,$mode,$tagName,$extra='') {
    $o=Join-Path $stage "$tagName.stdout"
    $e=Join-Path $stage "$tagName.stderr"
    $argText='-B "' + $actor + '" ' + $mode + ' --stage "' + $stage + '" ' + $extra
    $p=Start-Process -FilePath $python -ArgumentList $argText -Credential $cred -PassThru -WindowStyle Hidden -RedirectStandardOutput $o -RedirectStandardError $e
    return @{proc=$p;out=$o;err=$e}
}
function ExistsWithin($path,$seconds=9) {
    $deadline=[DateTime]::UtcNow.AddSeconds($seconds)
    while (!(Test-Path -LiteralPath $path) -and [DateTime]::UtcNow -lt $deadline) {Start-Sleep -Milliseconds 50}
    if (!(Test-Path -LiteralPath $path)) {throw "file not observed $path"}
}
function DoCase($rcCred,$wkCred,$expected,$tagName,$tamper='none') {
    $server=Actor $rcCred server "server-$tagName"
    $client=Actor $wkCred client "client-$tagName" "--expected $expected --tamper $tamper"
    CheckProc $client "client-$tagName"
    CheckProc $server "server-$tagName"
}
try {
    $null=New-LocalUser -Name $rc -Password $pw1 -PasswordNeverExpires -Description 'DISPOSABLE CI isolated receiver'
    $created+= $rc
    $null=New-LocalUser -Name $wk -Password $pw2 -PasswordNeverExpires -Description 'DISPOSABLE CI isolated worker'
    $created+= $wk
    $rSid=(Get-LocalUser $rc).SID.Value
    $wSid=(Get-LocalUser $wk).SID.Value
    if($rSid -eq $wSid){throw 'same SID'}
    $admins=@(Get-LocalGroupMember -Group Administrators | ForEach-Object {$_.SID.Value})
    if(($admins -contains $rSid) -or ($admins -contains $wSid)){throw 'nonadmin invariant failed'}
    $rCred=New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$rc",$pw1)
    $wCred=New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$wk",$pw2)
    & $python -B $actor prepare --stage $stage
    if($LASTEXITCODE -ne 0){throw 'actual CORE claim preparation failed'}
    $stageRights=@(('*'+$rSid+':(OI)(CI)M'),('*'+$wSid+':(OI)(CI)M'),'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    & icacls.exe $stage /inheritance:r /grant:r $stageRights | Out-Null
    if($LASTEXITCODE -ne 0){throw 'stage DACL failed'}
    $sandbox=Join-Path $stage 'protected-receiver'
    $null=New-Item -Type Directory -Path $sandbox
    $rootRights=@(('*'+$rSid+':(OI)(CI)F'),'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    & icacls.exe $sandbox /inheritance:r /grant:r $rootRights | Out-Null
    if($LASTEXITCODE -ne 0){throw 'protected NTFS ACL failed'}
    $pipe='\\.\pipe\neurofactory-pilot-'+([guid]::NewGuid().ToString('N')).Substring(0,24)
    @{schema='nf.win.two_sid.ci.v1';worker_sid=$wSid;receiver_sid=$rSid;pipe=$pipe;protected_root=$sandbox} | ConvertTo-Json -Compress | Set-Content -Encoding ascii (Join-Path $stage 'server_config.json')
    $probe=Actor $wCred probe 'ntfs-direct-probe'
    CheckProc $probe 'worker direct-write denial'
    if((Get-Content -Raw $probe.out) -notmatch 'WORKER_DIRECT_FILE_ACCESS=DENIED'){throw 'worker can write protected folder'}
    Write-Output 'NF_TWO_REAL_DIFFERENT_NONADMIN_WINDOWS_SIDS=PASS'
    Write-Output 'NF_WORKER_PROTECTED_NTFS_DIRECT_WRITE=DENIED'
    DoCase $rCred $wCred positive 'first'
    $file=Join-Path $sandbox windows_pilot.txt
    $marker=Join-Path $sandbox one_effect_unknown.json
    ExistsWithin $file
    ExistsWithin $marker
    $original=(Get-FileHash $file -Algorithm SHA256).Hash
    DoCase $rCred $wCred denied 'replay'
    if((Get-FileHash $file -Algorithm SHA256).Hash -cne $original){throw 'repeat modified file'}
    Write-Output 'NF_TWO_SID_SIGNED_ONCE_AND_REPLAY_BLOCKED=PASS'
    Remove-Item -LiteralPath $file,$marker -Force
    DoCase $rCred $wCred denied 'forged-owner' signature
    if((Test-Path $file) -or (Test-Path $marker)){throw 'forged signature created effect'}
    Write-Output 'NF_TWO_SID_OWNER_SIGNATURE_FORGERY=DENIED'
    $env:NF_WINDOWS_CI_POST_FSYNC_PAUSE='1'
    $server=Actor $rCred server 'post-fsync-crash'
    $client=Actor $wCred client 'crash-client'
    ExistsWithin $file
    ExistsWithin $marker
    $crashHash=(Get-FileHash $file -Algorithm SHA256).Hash
    Stop-Process -Id $server.proc.Id -Force
    $client.proc.WaitForExit(8000) | Out-Null
    if(!$client.proc.HasExited){$client.proc.Kill()}
    $env:NF_WINDOWS_CI_POST_FSYNC_PAUSE='0'
    DoCase $rCred $wCred denied 'restart-after-crash'
    if((Get-FileHash $file -Algorithm SHA256).Hash -cne $crashHash){throw 'crash retry altered file'}
    if((Get-Content -Raw $marker | ConvertFrom-Json).state -cne 'UNKNOWN_NO_AUTO_RETRY'){throw 'unknown state lost'}
    Write-Output 'NF_TWO_SID_FORCED_POST_FSYNC_CRASH_RECOVERY=PASS_TEST_ONLY'
    Write-Output 'NF_NEUROFACTORY_LIVE_QUEUE=OFF'
}
finally {
    Remove-Item Env:NF_WINDOWS_CI_POST_FSYNC_PAUSE -ErrorAction SilentlyContinue
    foreach($account in $created){
        try{Disable-LocalUser $account -ErrorAction SilentlyContinue}catch{}
        try{Remove-LocalUser $account -ErrorAction SilentlyContinue}catch{}
    }
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
