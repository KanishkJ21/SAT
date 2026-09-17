@echo off
cd /d "%~dp0"

echo Starting SAT-SA...
echo.

if not exist ".venv\Scripts\python.exe" (
    echo Virtual environment not found.
    echo Please run the setup commands first.
    pause
    exit /b
)

start "" ".venv\Scripts\python.exe" -m streamlit run sat_sa\app.py

exit