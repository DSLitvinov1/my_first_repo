@echo off
chcp 65001 >nul
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0SETUP_FREE_DC_READONLY.ps1"
set "exitcode=%ERRORLEVEL%"
echo.
if not "%exitcode%"=="0" echo Setup did not finish. Nothing is connected to ChatGPT.
pause
exit /b %exitcode%
