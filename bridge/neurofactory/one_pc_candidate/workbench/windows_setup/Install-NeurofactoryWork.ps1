#requires -RunAsAdministrator
# One-time personal install; never migrates or stops protected CORE/HOST.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$src='C:\ChatGPTProjects\NeurofactoryWork-Staging-20261107'
$app='C:\Program Files\NeurofactoryWork'
$root='C:\NeurofactoryProjects'
$taskName='NeurofactoryWorkPersonal'
$expectedCore='3e74492281a8d5df8d8873d7f42944853dbf1d1b'
$existingService=Get-CimInstance Win32_Service -Filter "Name='NeurofactoryPersonalHost'"
if(-not $existingService -or $existingService.State -cne 'Running'){
  throw 'CORE_HOST_NOT_RUNNING_ABORT_INSTALL'
}
$existingManifest='C:\Program Files\NeurofactoryPersonalHost.next-core9-3e744922\bundle-manifest.json'
$m=Get-Content -LiteralPath $existingManifest -Raw|ConvertFrom-Json
if($m.source_sha40 -cne $expectedCore){throw 'CORE_HOST_SOURCE_CHANGED_ABORT'}
if(Test-Path -LiteralPath $app){throw 'WORK_APP_ALREADY_EXISTS_REFUSE_OVERWRITE'}
if(Test-Path -LiteralPath $root){throw 'WORK_PROJECT_ROOT_ALREADY_EXISTS_REFUSE_OVERWRITE'}
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){
  throw 'WORK_SCHEDULED_TASK_ALREADY_EXISTS_REFUSE_OVERWRITE'
}
$desktop=[Environment]::GetFolderPath('Desktop')
$link=Join-Path $desktop 'Neurofactory Work.lnk'
if(Test-Path -LiteralPath $link){throw 'WORK_SHORTCUT_EXISTS_REFUSE_OVERWRITE'}
$items=@('work_core.py','work_server.py','index.html','styles.css','app.js','README.md','test_workbench.py')
$entries=@()
foreach($filename in $items){
  $file=Join-Path $src $filename
  if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw "STAGE_MISSING_$filename"}
  $entries+= [pscustomobject]@{name=$filename;sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $file).Length}
}
New-Item -ItemType Directory -Path $app -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'projects') -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root '.work-data') -ErrorAction Stop | Out-Null
$owner=([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$admin='*S-1-5-32-544:(OI)(CI)F'
$system='*S-1-5-18:(OI)(CI)F'
$userWrite=('*'+$owner+':(OI)(CI)M')
$userRead=('*'+$owner+':(OI)(CI)RX')
& icacls.exe $root /inheritance:r /grant:r $system $admin $userWrite | Out-Null
if($LASTEXITCODE -ne 0){throw 'WORK_PROJECTS_ACL_FAILED'}
foreach($entry in $entries){
  Copy-Item -LiteralPath (Join-Path $src $entry.name) -Destination (Join-Path $app $entry.name) -ErrorAction Stop
  $actual=(Get-FileHash -LiteralPath (Join-Path $app $entry.name) -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -cne $entry.sha256){throw ('WORK_INSTALLED_ASSET_MISMATCH_'+$entry.name)}
}
$manifest=[ordered]@{
  schema='nf.work.personal.one_pc.v1'
  source_commit='a64e7da39a286b1fbbdc868fcc19f19a465cb2b3'
  based_on_core9_source=$expectedCore
  public_listener=$false
  binds_to='127.0.0.1:8770'
  model_generated_code_execution=$false
  installed_entries=$entries
}
$payload=($manifest|ConvertTo-Json -Depth 6)
$encoder=New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $app 'work-manifest.json'),$payload,$encoder)
& icacls.exe $app /inheritance:r /grant:r $system $admin $userRead | Out-Null
if($LASTEXITCODE -ne 0){throw 'WORK_APPLICATION_ACL_FAILED'}
$pythonw='C:\Program Files\NeurofactoryPersonalHost.next-core9-3e744922\runtime\pythonw.exe'
if(-not(Test-Path -LiteralPath $pythonw -PathType Leaf)){throw 'EXISTING_EMBEDDED_PYTHON_MISSING'}
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$argline=('-B "'+$app+'\work_server.py" --root "'+$root+'\projects" --data "'+$root+'\.work-data" --port 8770')
$action=New-ScheduledTaskAction -Execute $pythonw -Argument $argline -WorkingDirectory $app
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Personal Neurofactory Work localhost UI only, user context' -ErrorAction Stop | Out-Null
$chrome='C:\Program Files\Google\Chrome\Application\chrome.exe'
if(-not(Test-Path -LiteralPath $chrome)){throw 'CHROME_LAUNCHER_MISSING'}
$shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut($link)
$shortcut.TargetPath=$chrome
$shortcut.Arguments='--app=http://127.0.0.1:8770/'
$shortcut.WorkingDirectory=$app
$shortcut.IconLocation=($chrome+',0')
$shortcut.Description='Neurofactory Work personal workspace'
$shortcut.Save()
Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
Write-Output ('NEUROFACTORY_WORK_INSTALLED='+$app)
Write-Output ('NEUROFACTORY_WORK_PROJECT_ROOT='+$root)
Write-Output ('NEUROFACTORY_WORK_DESKTOP_LINK='+$link)
Write-Output ('NEUROFACTORY_WORK_RUN_USER='+$user)
Write-Output ('NEUROFACTORY_WORK_RELEASE_MANIFEST_SHA256='+(Get-FileHash -LiteralPath (Join-Path $app 'work-manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant())
Write-Output ('CORE_HOST_UNTOUCHED='+$expectedCore)
Write-Output ('AUTOSTART_TASK='+$taskName)
