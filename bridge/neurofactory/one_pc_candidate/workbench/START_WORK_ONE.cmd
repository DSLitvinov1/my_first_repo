@echo off
setlocal
cd /d "%~dp0"
if not exist "runtime\python\python.exe" goto no_runtime
"runtime\python\python.exe" "start_work_one.py"
if errorlevel 1 goto failed
exit /b 0
:no_runtime
echo Work ONE: embedded Python is missing. Restore the verified archive.
goto failed
:failed
echo Work ONE did not start. Copy the error above for diagnosis. No Windows settings were changed.
pause
exit /b 1
