"""Compliance control-mapping router."""

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.services.compliance_service import enrich_control, load_control_catalog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/compliance", tags=["Compliance"])


class JobControlsRequest(BaseModel):
    control_ids: list[str]


# ── Controls list ─────────────────────────────────────────────────────────────

@router.get("/controls")
def list_controls(
    framework: Optional[str] = None,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(get_current_user),
):
    """Return all controls with live evidence snapshot.

    Optional ``?framework=ISO27001|CIS|CSF`` filter.
    """
    sql    = "SELECT * FROM control_catalog"
    params: list = []
    if framework:
        sql += " WHERE framework = ?"
        params.append(framework)
    sql += " ORDER BY framework, control_id"

    rows     = conn.execute(sql, params).fetchall()
    enriched = [enrich_control(conn, dict(r)) for r in rows]
    return {"data": enriched}


# ── Single control ────────────────────────────────────────────────────────────

@router.get("/controls/{control_id}")
def get_control(
    control_id: str,
    conn:       sqlite3.Connection = Depends(get_db),
    user:       dict               = Depends(get_current_user),
):
    """Return one control with full live snapshot and deep links."""
    row = conn.execute(
        "SELECT * FROM control_catalog WHERE control_id = ?", (control_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control '{control_id}' not found.",
        )
    return {"data": enrich_control(conn, dict(row))}


# ── Aggregate summary ─────────────────────────────────────────────────────────

@router.get("/summary")
def compliance_summary(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    """Aggregate control counts by status and framework."""
    rows = conn.execute(
        "SELECT * FROM control_catalog ORDER BY framework, control_id"
    ).fetchall()

    totals:       dict = {"full": 0, "partial": 0, "supporting": 0, "total": 0}
    by_framework: dict = {}

    for row in rows:
        enriched = enrich_control(conn, dict(row))
        st       = enriched["status"]
        fw       = enriched["framework"]

        totals["total"] += 1
        if st in totals:
            totals[st] += 1

        if fw not in by_framework:
            by_framework[fw] = {"full": 0, "partial": 0, "supporting": 0, "total": 0}
        by_framework[fw]["total"] += 1
        if st in by_framework[fw]:
            by_framework[fw][st] += 1

    return {"data": {**totals, "by_framework": by_framework}}


# ── Tag a job with controls ───────────────────────────────────────────────────

@router.post("/jobs/{job_id}/controls", status_code=status.HTTP_201_CREATED)
def tag_job_controls(
    job_id:  str,
    payload: JobControlsRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role("analyst", "admin")),
):
    """Associate one or more control IDs with a remediation job."""
    if not conn.execute(
        "SELECT 1 FROM jobs WHERE job_id = ?", (job_id,)
    ).fetchone():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    now = datetime.now(timezone.utc).isoformat()
    for ctrl_id in payload.control_ids:
        if not conn.execute(
            "SELECT 1 FROM control_catalog WHERE control_id = ?", (ctrl_id,)
        ).fetchone():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown control '{ctrl_id}'.",
            )
        conn.execute(
            """INSERT OR REPLACE INTO job_controls
                   (job_id, control_id, tagged_by, tagged_at)
               VALUES (?,?,?,?)""",
            (job_id, ctrl_id, user.get("sub", "unknown"), now),
        )

    conn.commit()
    return {"data": {"job_id": job_id, "tagged_controls": payload.control_ids}}


# ── Admin: reload catalog ─────────────────────────────────────────────────────

@router.post("/catalog/reload", status_code=status.HTTP_200_OK)
def reload_catalog(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(require_role("admin")),
):
    """Re-read control_mapping.yaml and refresh control_catalog (admin only)."""
    try:
        n = load_control_catalog(conn)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Catalog reload failed: {exc}",
        )
    return {"data": {"controls_loaded": n}}
