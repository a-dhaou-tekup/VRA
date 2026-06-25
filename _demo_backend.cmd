@echo off
cd /d "%~dp0"
set "PYTHONIOENCODING=utf-8"
set "JWT_SECRET_KEY=demo-8bcc5f6893289288bcd65f53e7e28360e9d6eb09"
set "PLATFORM_DB_PATH=data/cache/demo.db"
set "API_PORT=8001"
set "VRA_SKIP_SEED=true"
set "APP_ENV=prod"
set "CORS_ORIGINS=http://localhost:5174"
python run_api.py
