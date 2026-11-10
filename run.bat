@echo off
chcp 65001 > nul
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Виртуальное окружение не найдено, создаю .venv на Python 3.14...
    py -3.14 -m venv .venv
)

echo Установка зависимостей...
".venv\Scripts\python.exe" -m pip install -r requirements.txt

echo Запуск стенда Этапа 0 (HOST и PORT берутся из .env)...
".venv\Scripts\python.exe" "App\main.py"

pause
