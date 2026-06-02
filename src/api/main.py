"""VRA — Vulnerability Remediation Assistant — FastAPI application factory."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VRA startup: running database migrations…")
    from api.db.connection import get_connection
    from api.db.migrate import run_migrations
    from api.services.compliance_service import load_control_catalog

    conn = get_connection()
    try:
        run_migrations(conn)
        try:
            n = load_control_catalog(conn)
            logger.info("VRA startup: loaded %d compliance controls.", n)
        except Exception as exc:
            logger.warning("VRA startup: compliance catalog load failed — %s", exc)
    finally:
        conn.close()

    logger.info("VRA startup: ready.")
    yield
    logger.info("VRA shutdown.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="VRA — Vulnerability Remediation Assistant",
        description=(
            "Semi-automated vulnerability remediation with risk scoring, SLA tracking, "
            "RAG-powered AI recommendations, and re-scan lifecycle detection. "
            "Hardware: RTX 4070 Ti Super · Ryzen 7600X."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    ).split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ───────────────────────────────────────────────────────────────
    from api.routers import (
        jobs, metrics, tickets, rescan, uploads,
        assets, findings, enrichment,
        auth as auth_router,
        users as users_router,
        lifecycle as lifecycle_router,
        threat_alerts as threat_alerts_router,
    )
    from api.routers import rag as rag_router
    from api.routers import compliance as compliance_router
    from api.routers import agent as agent_router
    from api.routers import chat as chat_router
    from api.routers import graph as graph_router
    from api.routers import reports as reports_router

    # Auth first so login is always reachable
    app.include_router(auth_router.router)
    app.include_router(users_router.router)
    app.include_router(jobs.router)
    app.include_router(lifecycle_router.router)
    app.include_router(metrics.router)
    app.include_router(tickets.router)
    app.include_router(rescan.router)
    app.include_router(uploads.router)
    app.include_router(assets.router)
    app.include_router(threat_alerts_router.router)
    app.include_router(findings.router)
    app.include_router(enrichment.router)
    app.include_router(rag_router.router)
    app.include_router(compliance_router.router)
    app.include_router(agent_router.router)
    app.include_router(chat_router.router)
    app.include_router(graph_router.router)
    app.include_router(reports_router.router)

    # ── Health check ──────────────────────────────────────────────────────────
    @app.get("/health", tags=["Health"])
    def health():
        return {"status": "ok", "service": "VRA"}

    return app


app = create_app()
