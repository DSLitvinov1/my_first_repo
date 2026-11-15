@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0START_ONE_CHATGPT_CONNECT.ps1"
if errorlevel 1 (
  echo ONE connection pilot did not start. It did not replace the installed ONE Agent.
  pause
  exit /b 1
)
endlocal
