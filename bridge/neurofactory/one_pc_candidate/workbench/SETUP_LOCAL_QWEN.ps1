# Opt-in local Ollama Qwen setup. NO service installation or privilege escalation.
[CmdletBinding()]
param(
    [ValidateSet('qwen3.5:0.8b','qwen3.5:2b','qwen3.5:4b','qwen3.5:9b')]
    [string]$Model='qwen3.5:2b',
    [switch]$Pull
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::UserInteractive) {throw 'QWEN_INTERACTIVE_USER_REQUIRED'}
$p=[Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'QWEN_ELEVATED_EXECUTION_REFUSED'
}
$ollama=Get-Command 'ollama.exe' -ErrorAction SilentlyContinue
if ($null -eq $ollama) {
    Write-Host 'Ollama отсутствует. Бесплатная установка от официального поставщика:'
    Write-Host 'https://ollama.com/download/windows'
    Write-Host 'Не запускайте неизвестные установщики и не вводите ключи в чат.'
    exit 2
}
& $ollama.Source list
if ($LASTEXITCODE -ne 0) {
    throw 'QWEN_OLLAMA_NOT_RESPONDING'
}
if (!$Pull) {
    Write-Host ('Чтобы скачать модель '+$Model+', запустите этот же сценарий с -Pull.')
    Write-Host 'Скачивание модели 0.8B требует около 1.3 ГБ; 9B — более 6 ГБ.'
    exit 0
}
$drive=(Get-Item -LiteralPath $env:LOCALAPPDATA).PSDrive
if ($drive.Free -lt 8589934592) {throw 'QWEN_INSUFFICIENT_FREE_DISK'}
Write-Host ('Загружаю бесплатную локальную модель '+$Model)
& $ollama.Source pull $Model
if ($LASTEXITCODE -ne 0) {throw 'QWEN_PULL_FAILED'}
Write-Host ('Модель '+$Model+' скачана; запустите Work ONE снова, чтобы он её обнаружил.')
