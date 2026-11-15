@echo off
setlocal
cd /d "%~dp0"
if not exist "runtime\python\python.exe" goto no_runtime
if /I "%~1"=="--verify-only" goto verify
if not "%~1"=="" goto failed
"runtime\python\python.exe" "start_chatgpt_candidate_one.py"
if errorlevel 1 goto failed
exit /b 0
:verify
"runtime\python\python.exe" "start_chatgpt_candidate_one.py" --verify-only
exit /b %ERRORLEVEL%
:no_runtime
echo ONE: the verified local Python runtime is missing.
goto failed
:failed
echo ONE ChatGPT candidate did not start. Your original ONE installation is unchanged.
pause
exit /b 1
