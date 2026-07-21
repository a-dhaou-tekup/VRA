"""run_api.py — VRA API server entry point.

Run from the project root:
    python run_api.py

Or with custom host/port:
    API_HOST=0.0.0.0 API_PORT=8080 python run_api.py
"""
import os
import sys
import logging
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

# Add src/ to path so `api`, `rag`, `ingestion` etc. are importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

import uvicorn

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

if __name__ == "__main__":
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    reload = os.getenv("APP_ENV", "dev") == "dev"

    print(f"""
  ██╗   ██╗██████╗  █████╗
  ██║   ██║██╔══██╗██╔══██╗
  ██║   ██║██████╔╝███████║
  ╚██╗ ██╔╝██╔══██╗██╔══██║
   ╚████╔╝ ██║  ██║██║  ██║
    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝

  Vulnerability Remediation Assistant
  RTX 4070 Ti Super · Ryzen 7600X
  ─────────────────────────────────────
  API   → http://{host}:{port}
  Docs  → http://{host}:{port}/docs
  ENV   → {os.getenv('APP_ENV', 'dev')}
""")

    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )
