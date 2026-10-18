@echo off
setlocal
set "DATA=%LOCALAPPDATA%\NeurofactoryData"
echo НЕЙРОЗАВОД: локальная база проектов и заданий.
echo Режим только для черновиков. Очередь ИИ, HOST и публикация выключены.
echo Откройте в браузере: http://127.0.0.1:8766/
echo Закройте это окно для остановки локальной базы.
"%~dp0runtime\python.exe" -B "%~dp0app\verify_installed_components.py" --components "%~dp0components"
if errorlevel 1 (
  echo Ошибка контроля компонентов. Запуск остановлен, состояние проектов не изменено.
  pause
  exit /b 1
)
"%~dp0runtime\python.exe" -B "%~dp0app\local_workspace.py" --data-dir "%DATA%" --ui-dir "%~dp0ui" --port 8766
if errorlevel 1 (
  echo Не удалось открыть локальную базу. Убедитесь, что порт 8766 свободен.
  pause
)
endlocal
