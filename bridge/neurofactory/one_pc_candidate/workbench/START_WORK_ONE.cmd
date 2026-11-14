@echo off
setlocal
cd /d "%~dp0"
if not exist "runtime\python\python.exe" goto no_runtime
if /I "%~1"=="--verify-only" goto verify
if not "%~1"=="" goto invalid_args
"runtime\python\python.exe" "start_work_one.py"
if errorlevel 1 goto failed
exit /b 0
:verify
"runtime\python\python.exe" "start_work_one.py" --verify-only
exit /b %ERRORLEVEL%
:invalid_args
echo Work ONE: unknown launcher arguments.
goto failed
:no_runtime
echo Work ONE: embedded Python is missing. Restore the verified archive.
goto failed
:failed
echo Work ONE did not start. Copy the error above for diagnosis. No Windows settings were changed.
pause
exit /b 1
