"""Metrics router — overview, SLA compliance, and timeline analytics."""

import logging
import sqlite3
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends

from api.auth import get_current_user
from api.db.connection import get_db
from api.repositories.jobs_repo import (
    count_by_status,
    count_by_risk_level,
    get_overdue_jobs,
    get_all_jobs,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/metrics", tags=["Metrics"])


# ── Overview ──────────────────────────────────────────────────────────────────

@router.get("/overview")
def metrics_overview(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    by_status     = count_by_status(conn)
    by_risk       = count_by_risk_level(conn)
    total_jobs    = sum(by_status.values())
    kev_count_row = conn.execute("SELECT COUNT(*) AS cnt FROM jobs WHERE kev_present = 1").fetchone()
    kev_jobs_count = kev_count_row["cnt"] if kev_count_row else 0

    overdue = get_overdue_jobs(conn)
    overdue_count = len(overdue)

    # SLA compliance: % of non-terminal jobs that are NOT overdue
    non_closed = conn.execute(
        "SELECT COUNT(*) AS cnt FROM jobs WHERE status NOT IN ('DONE','CLOSED')"
    ).fetchone()["cnt"]

    sla_compliance_pct = (
        round((non_closed - overdue_count) / non_closed * 100, 1)
        if non_closed > 0
        else 100.0
    )

    return {
        "data": {
            "total_jobs":         total_jobs,
            "jobs_by_status":     by_status,
            "jobs_by_risk_level": by_risk,
            "kev_jobs_count":     kev_jobs_count,
            "overdue_count":      overdue_count,
            "sla_compliance_pct": sla_compliance_pct,
        }
    }


# ── SLA detail ────────────────────────────────────────────────────────────────

@router.get("/sla")
def metrics_sla(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    now = datetime.now(timezone.utc)

    open_jobs = conn.execute(
        "SELECT job_id, due_date FROM jobs WHERE status NOT IN ('DONE','CLOSED')"
    ).fetchall()

    total_open = len(open_jobs)
    overdue_details: list[dict] = []

    for row in open_jobs:
        if not row["due_date"]:
            continue
        try:
            due = datetime.fromisoformat(row["due_date"].replace("Z", "+00:00"))
        except ValueError:
            continue
        if due < now:
            days_overdue = (now - due).days
            overdue_details.append({
                "job_id":       row["job_id"],
                "due_date":     row["due_date"],
                "days_overdue": days_overdue,
            })

    breached       = len(overdue_details)
    within_sla     = total_open - breached
    compliance_pct = round(within_sla / total_open * 100, 1) if total_open > 0 else 100.0

    return {
        "data": {
            "total_open":     total_open,
            "within_sla":     within_sla,
            "breached":       breached,
            "compliance_pct": compliance_pct,
            "overdue_jobs":   overdue_details,
        }
    }


# ── Timeline ──────────────────────────────────────────────────────────────────

@router.get("/timeline")
def metrics_timeline(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    """Jobs created per day for the last 30 days, grouped by risk_level."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    cursor = conn.execute(
        """SELECT DATE(created_at) AS day, max_risk_level, COUNT(*) AS cnt
           FROM jobs
           WHERE created_at >= ?
           GROUP BY day, max_risk_level
           ORDER BY day ASC""",
        (cutoff,),
    )

    rows = cursor.fetchall()
    timeline: dict[str, dict[str, int]] = {}
    for row in rows:
        day   = row["day"]
        level = row["max_risk_level"] or "UNKNOWN"
        cnt   = row["cnt"]
        timeline.setdefault(day, {})[level] = cnt

    return {"data": timeline}
