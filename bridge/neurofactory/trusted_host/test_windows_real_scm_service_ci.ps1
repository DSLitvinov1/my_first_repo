# Actual Windows SCM service smoke: disposable GitHub-hosted Windows only.
# Creates two nonadmin accounts, registers a real SCM service for the receiver
# and removes EVERYTHING in finally. No user's PC, no production queue.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:NF_WINDOWS_TWO_SID_CI_ONLY -ne '1'){throw 'CI ONLY'}
$actor=Join-Path $PSScriptRoot 'windows_two_sid_pilot_actor.py'
$python=(Get-Command python).Source
$tag=([guid]::NewGuid().ToString('N')).Substring(0,7)
$rc="nf_rc_$tag"
$wk="nf_wk_$tag"
$stage=Join-Path $env:RUNNER_TEMP "nf-scm-$tag"
$svcName='NeurofactorySandboxReceiver'
$svcConfigRoot=Join-Path $env:ProgramData $svcName
$null=New-Item -ItemType Directory -Path $stage -Force
$pw1=ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(36))) -AsPlainText -Force
$pw2=ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(36))) -AsPlainText -Force
$created=@()
function LaunchWorker($creds,$name) {
    $out=Join-Path $stage "$name.out"
    $err=Join-Path $stage "$name.err"
    $args='-B "' + $actor + '" client --stage "' + $stage + '" --expected ' + $name
    $p=Start-Process -FilePath $python -Credential $creds -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
    $p.WaitForExit(16000) | Out-Null
    if(!$p.HasExited){$p.Kill();throw "worker timeout"}
    if($p.ExitCode -ne 0){throw "worker-$name failed: $(Get-Content -Raw $err) $(Get-Content -Raw $out)"}
}
function WaitFile($path) {
    $end=[DateTime]::UtcNow.AddSeconds(12)
    while(!(Test-Path -LiteralPath $path) -and [DateTime]::UtcNow -lt $end){Start-Sleep -Milliseconds 70}
    if(!(Test-Path -LiteralPath $path)){throw "missing created output $path"}
}
try {
    $null=New-LocalUser -Name $rc -Password $pw1 -PasswordNeverExpires -Description 'TEMP CI Windows protected SCM receiver'
    $created+= $rc
    $null=New-LocalUser -Name $wk -Password $pw2 -PasswordNeverExpires -Description 'TEMP CI Windows CORE worker'
    $created+= $wk
    $rs=(Get-LocalUser $rc).SID.Value
    $ws=(Get-LocalUser $wk).SID.Value
    if($rs -eq $ws){throw 'same sid forbidden'}
    & $python -B $actor prepare --stage $stage
    if($LASTEXITCODE -ne 0){throw 'pre-sign actual CORE task failure'}

    $readerACL=@(('*'+$rs+':(OI)(CI)RX'),('*'+$ws+':(OI)(CI)RX'))
    & icacls.exe $env:GITHUB_WORKSPACE /grant $readerACL /T /C | Out-Null
    if($LASTEXITCODE -ne 0){throw 'repo read-only rights error'}
    $stagingACL=@(('*'+$rs+':(OI)(CI)M'),('*'+$ws+':(OI)(CI)M'),'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    & icacls.exe $stage /inheritance:r /grant:r $stagingACL | Out-Null
    if($LASTEXITCODE -ne 0){throw 'staging DACL error'}
    $sandbox=Join-Path $stage 'protected-sandbox'
    $null=New-Item -ItemType Directory -Path $sandbox
    $protectedACL=@(('*'+$rs+':(OI)(CI)F'),'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    & icacls.exe $sandbox /inheritance:r /grant:r $protectedACL | Out-Null
    if($LASTEXITCODE -ne 0){throw 'root ACL error'}
    $pipe='\\.\pipe\neurofactory-pilot-'+([guid]::NewGuid().ToString('N')).Substring(0,24)
    @{worker_sid=$ws;receiver_sid=$rs;pipe=$pipe;protected_root=$sandbox} | ConvertTo-Json -Compress | Set-Content -Encoding ascii (Join-Path $stage 'server_config.json')
    $key=((Get-Content -Raw (Join-Path $stage 'public.json'))|ConvertFrom-Json).public_key_base64

    if(Test-Path -LiteralPath $svcConfigRoot){throw 'refuse existing operator service config'}
    $null=New-Item -ItemType Directory -Path $svcConfigRoot
    $cfgDACL=@(('*'+$rs+':(OI)(CI)RX'),'*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    & icacls.exe $svcConfigRoot /inheritance:r /grant:r $cfgDACL | Out-Null
    if($LASTEXITCODE -ne 0){throw 'service public config ACL error'}
    @{schema='nf.windows.scm.single_file.v1';mode='SANDBOX_ONLY';receiver_sid=$rs;worker_sid=$ws;pipe=$pipe;protected_root=$sandbox;owner_public_base64=$key} | ConvertTo-Json -Compress | Set-Content -Encoding ascii (Join-Path $svcConfigRoot 'service_config.json')

    # Register installed module in this EPHEMERAL Python toolchain, never
    # machine's pre-existing Python/runtime. Site-packages belongs to CI VM.
    $site=(& $python -c "import site;print(site.getsitepackages()[0])").Trim()
    $moduleFiles=@('windows_scm_one_shot_receiver.py','windows_named_pipe_pilot_receiver.py','windows_receiver_sid_acl_guard.py')
    foreach($file in $moduleFiles){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $site $file) -Force}
    # Explicit Windows LSA right is required to run a service under a
    # disposable non-admin account; never grant this on the owner's PC.
    & $python -B (Join-Path $PSScriptRoot 'windows_ci_allow_service_logon.py') $rs
    if($LASTEXITCODE -ne 0){throw 'isolated SCM logon right missing'}
    $env:NF_EPHEMERAL_SCM_USER="$env:COMPUTERNAME\$rc"
    $env:NF_EPHEMERAL_SCM_PASSWORD=([System.Management.Automation.PSCredential]::new('ephemeral',$pw1)).GetNetworkCredential().Password
    & $python -c "import os,win32serviceutil,win32service;win32serviceutil.InstallService('windows_scm_one_shot_receiver.NeurofactorySandboxReceiverService','NeurofactorySandboxReceiver','Neurofactory isolated sandbox recipient',startType=win32service.SERVICE_DEMAND_START,userName=os.environ['NF_EPHEMERAL_SCM_USER'],password=os.environ['NF_EPHEMERAL_SCM_PASSWORD'])"
    if($LASTEXITCODE -ne 0){throw 'Windows SCM service registration failed'}
    Remove-Item Env:NF_EPHEMERAL_SCM_PASSWORD -ErrorAction SilentlyContinue

    $registered=Get-CimInstance Win32_Service -Filter ("Name='"+$svcName+"'")
    if(!$registered -or $registered.StartName -notmatch [Regex]::Escape($rc)){throw 'SCM principal not pinned receiver user'}
    Write-Output 'NF_WINDOWS_REAL_SCM_SERVICE_REGISTERED_UNDER_SEPARATE_NONADMIN_SID=PASS'

    $wCred=New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$wk",$pw2)
    & sc.exe qc $svcName | Out-Host
    & sc.exe start $svcName | Out-Host
    if($LASTEXITCODE -ne 0) {throw ('SCM_START_EXIT_CODE='+$LASTEXITCODE)}
    try { Start-Service -Name $svcName -ErrorAction Stop } catch {
        $events=Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-3)} -ErrorAction SilentlyContinue
        $recent=@($events | Where-Object { $_.Message -match 'NeurofactorySandboxReceiver|nf_rc_|pythonservice' } | Select-Object -First 8)
        foreach($evt in $recent) {Write-Output ('NF_DISPOSABLE_SCM_DIAG: '+$evt.Id+' '+$evt.Message)}
        $app=Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=(Get-Date).AddMinutes(-3)} -ErrorAction SilentlyContinue
        foreach($evt in @($app | Where-Object {$_.Message -match 'Neurofactory|pythonservice'} | Select-Object -First 8)){
            Write-Output ('NF_DISPOSABLE_APP_DIAG: '+$evt.Id+' '+$evt.Message)
        }
        throw
    }
    LaunchWorker $wCred positive
    WaitFile (Join-Path $sandbox 'windows_pilot.txt')
    $one=(Get-FileHash (Join-Path $sandbox 'windows_pilot.txt') -Algorithm SHA256).Hash
    # SCM start is ON DEMAND. First request has finished; restart service.
    $deadline=[DateTime]::UtcNow.AddSeconds(8)
    while((Get-Service $svcName).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
    if((Get-Service $svcName).Status -ne 'Stopped'){throw 'one-shot SCM service did not stop'}
    Start-Service -Name $svcName -ErrorAction Stop
    LaunchWorker $wCred denied
    if((Get-FileHash (Join-Path $sandbox 'windows_pilot.txt') -Algorithm SHA256).Hash -cne $one){throw 'replay changed file'}
    Write-Output 'NF_WINDOWS_REAL_SCM_STOP_START_REPLAY_DENIED=PASS'
    Write-Output 'NF_WINDOWS_PRODUCTION_QUEUE=OFF'
}
finally {
    Remove-Item Env:NF_EPHEMERAL_SCM_PASSWORD -ErrorAction SilentlyContinue
    try {Stop-Service $svcName -Force -ErrorAction SilentlyContinue} catch {}
    try {& sc.exe delete $svcName | Out-Null} catch {}
    foreach($name in $created){
        try{Disable-LocalUser $name -ErrorAction SilentlyContinue}catch{}
        try{Remove-LocalUser $name -ErrorAction SilentlyContinue}catch{}
    }
    Remove-Item -LiteralPath $svcConfigRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
