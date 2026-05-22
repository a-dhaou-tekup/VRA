"""Re-scan router — trigger and status check for scan lifecycle detection."""

import logging
import sqlite3
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.models.schemas import RescanRequest
from api.services import rescan_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rescan", tags=["Re-scan"])

_WRITERS = ("analyst", "remediation_owner", "admin")


@router.post("/run")
def run_rescan(
    payload: RescanRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS)),
):
    """Trigger re-scan detection against the latest CSV outputs."""
    summary = rescan_service.run_rescan(
        conn,
        enriched_csv=payload.enriched_csv,
        jobs_csv=payload.jobs_csv,
        changed_by=payload.changed_by,
    )
    return {"data": summary}


@router.get("/status")
def rescan_status(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    """Return counts of RESURFACED jobs and recently DONE jobs (last 48 h)."""
    resurfaced_count = conn.execute(
        "SELECT COUNT(*) AS cnt FROM jobs WHERE status = 'RESURFACED'"
    ).fetchone()["cnt"]

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    recently_fixed = conn.execute(
        "SELECT COUNT(*) AS cnt FROM jobs WHERE status = 'DONE' AND fixed_at >= ?",
        (cutoff,),
    ).fetchone()["cnt"]

    return {
        "data": {
            "resurfaced_jobs":     resurfaced_count,
            "recently_fixed_jobs": recently_fixed,
        }
    }
