@echo off
title VRA Launcher
cd /d "%~dp0"

echo.
echo  Starting VRA - Vulnerability Remediation Assistant
echo  ====================================================
echo.

REM ── 1. Ollama ──────────────────────────────────────────────────────────────
echo  [1/3] Starting Ollama...
start "Ollama" cmd /k "ollama serve"
timeout /t 2 /nobreak >nul

REM ── 2. Backend ─────────────────────────────────────────────────────────────
echo  [2/3] Starting backend  (http://localhost:8000)...
start "VRA Backend" cmd /k "set PYTHONIOENCODING=utf-8 && set JWT_SECRET_KEY=8bcc5f6893289288bcd65f53e7e28360e9d6eb09946ddd44ea4b9a67bd0d6a22 && set PLATFORM_DB_PATH=data/cache/platform.db && python run_api.py"
timeout /t 3 /nobreak >nul

REM ── 3. Frontend ────────────────────────────────────────────────────────────
echo  [3/3] Starting frontend (http://localhost:5173)...
start "VRA Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo  Done. Three windows opened:
echo    Ollama   - AI model server
echo    Backend  - http://localhost:8000  (/docs for Swagger)
echo    Frontend - http://localhost:5173
echo.
pause
