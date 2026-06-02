@echo off
title VRA — Demo Instance
cd /d "%~dp0"

echo.
echo  ██╗   ██╗██████╗  █████╗     DEMO INSTANCE
echo  ██║   ██║██╔══██╗██╔══██╗   ══════════════
echo  ██║   ██║██████╔╝███████║   Clean DB — no pre-seeded jobs or assets.
echo  ╚██╗ ██╔╝██╔══██╗██╔══██║   Upload your own scan files to populate.
echo   ╚████╔╝ ██║  ██║██║  ██║
echo    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
echo.
echo  Backend   http://localhost:8001   (Swagger: /docs)
echo  Frontend  http://localhost:5174
echo.
echo  DB        data\cache\demo.db      (isolated from the dev instance)
echo  Enrich    data\cache\enrichment.db (shared KEV/EPSS/NVD cache)
echo  RAG       data\rag_corpus\chroma_db (shared advisory index)
echo.
echo  Demo credentials
echo    admin              / Admin1234!
echo    analyst            / Analyst1234!
echo    remediation_owner  / RemOwner1234!
echo    risk_owner         / RiskOwner1234!
echo    auditor            / Auditor1234!
echo.

REM ── 1. Ollama (shared with dev instance — skip if already running) ─────────
echo  [1/3] Ensuring Ollama is running...
start "Ollama" cmd /c "ollama serve" 2>nul
timeout /t 2 /nobreak >nul

REM ── 2. Demo backend ───────────────────────────────────────────────────────
echo  [2/3] Starting demo backend on :8001 ...
start "VRA Demo Backend" cmd /k "set PYTHONIOENCODING=utf-8 && set JWT_SECRET_KEY=demo-8bcc5f6893289288bcd65f53e7e28360e9d6eb09 && set PLATFORM_DB_PATH=data/cache/demo.db && set API_PORT=8001 && set VRA_SKIP_SEED=true && python run_api.py"
timeout /t 4 /nobreak >nul

REM ── 3. Demo frontend ──────────────────────────────────────────────────────
echo  [3/3] Starting demo frontend on :5174 ...
start "VRA Demo Frontend" cmd /k "cd frontend && set VITE_API_URL=http://localhost:8001 && npx vite --port 5174"

echo.
echo  All three windows launched.  Browser: http://localhost:5174
echo.
echo  Demo script order:
echo    1. Upload  ^> scanner_demo1.csv   (shows LLM parser)
echo    2. Findings list                  (AI triage + FP filter)
echo    3. Open a CRITICAL finding        (grounded advice + citations)
echo    4. Chat panel                     ("does this fix apply on RHEL 9?")
echo    5. Blast Radius tab               (propagation graph)
echo    6. Executive Report button        (live PDF generation)
echo.
pause
