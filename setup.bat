@echo off
echo ========================================
echo SENTINEL - Setup Script for Windows
echo ========================================
echo.

echo [1/4] Checking Python...
python --version >nul 2>&1 || (echo ERROR: Python not found. Install Python 3.11+ & pause & exit /b 1)
echo      Python found.

echo.
echo [2/4] Creating virtual environment...
if not exist venv (
    python -m venv venv
    echo      Virtual environment created.
) else (
    echo      Virtual environment already exists.
)

echo.
echo [3/4] Installing dependencies...
call venv\Scripts\pip install -r backend\requirements.txt
echo      Dependencies installed.

echo.
echo [4/4] Checking Nmap...
where nmap >nul 2>&1 || (
    echo WARNING: Nmap not found in PATH.
    echo Please install Nmap from: https://nmap.org/download.html
    echo Add Nmap to your PATH or place it in: C:\Program Files\Nmap
)
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To run SENTINEL:
echo   1. Start backend:   venv\Scripts\python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
echo   2. Start frontend:  cd frontend ^&^& npm install ^&^& npm run dev
echo   3. Open browser:     http://localhost:3000
echo.
pause
