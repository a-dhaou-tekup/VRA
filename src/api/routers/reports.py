"""Executive report router — Prompt #9.

POST /api/reports/executive          create + kick off background generation
GET  /api/reports/executive          list past reports (newest first)
GET  /api/reports/executive/{id}     metadata for one report
GET  /api/reports/executive/{id}/pdf stream the PDF bytes
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from api.auth import get_current_user, require_role
from api.db.connection import get_db, DB_PATH
from api.services.reports import executive as _svc

logger = logging.getLogger(__name__)

# Configure service with the correct DB path on first import
_svc.configure(Path(DB_PATH))

router = APIRouter(tags=["Reports"])

_REPORT_ROLES = ("admin", "analyst", "risk_owner")


# ── Schemas ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    period_days: int = Field(7, ge=1, le=90, description="Days of history to cover")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d.pop("metadata_json", None)   # omit heavy blob from list view
    d.pop("summary_text", None)    # omit from list; available in detail endpoint
    return d


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/api/reports/executive", status_code=202)
def create_executive_report(
    body:             ReportRequest,
    background_tasks: BackgroundTasks,
    conn:             sqlite3.Connection = Depends(get_db),
    user:             dict               = Depends(require_role(*_REPORT_ROLES)),
):
    """Kick off asynchronous executive PDF generation.

    Returns 202 Accepted with the report ID immediately.
    Poll GET /api/reports/executive/{id} until status == 'done'.
    """
    report_id  = str(uuid.uuid4())
    now        = datetime.now(timezone.utc).isoformat()
    period_end = now[:10]

    from datetime import timedelta
    period_start = (datetime.now(timezone.utc) - timedelta(days=body.period_days)).date().isoformat()

    conn.execute(
        """INSERT INTO exec_reports
           (id, created_at, created_by, period_start, period_end, status)
           VALUES (?, ?, ?, ?, ?, 'pending')""",
        (report_id, now, user["username"], period_start, period_end),
    )
    conn.commit()

    background_tasks.add_task(
        _svc.produce_report,
        report_id=report_id,
        period_days=body.period_days,
        actor_id=user["username"],
        db_path=Path(DB_PATH),
    )

    logger.info(
        "exec_report: created %s (period=%d d, by=%s)",
        report_id, body.period_days, user["username"],
    )
    return {
        "data": {
            "id":          report_id,
            "status":      "pending",
            "period_days": body.period_days,
            "created_by":  user["username"],
            "created_at":  now,
        }
    }


@router.get("/api/reports/executive")
def list_executive_reports(
    limit:  int                = Query(20, ge=1, le=100),
    offset: int                = Query(0,  ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    """Return past executive reports, newest first (metadata only, no PDF bytes)."""
    rows = conn.execute(
        """SELECT id, created_at, created_by, period_start, period_end,
                  status, summary_source, pdf_path, error_message
           FROM exec_reports
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?""",
        (limit, offset),
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM exec_reports").fetchone()[0]
    return {
        "data":  [dict(r) for r in rows],
        "total": total,
    }


@router.get("/api/reports/executive/{report_id}")
def get_executive_report(
    report_id: str,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(get_current_user),
):
    """Return full metadata for one executive report (includes summary_text)."""
    row = conn.execute(
        """SELECT id, created_at, created_by, period_start, period_end,
                  status, summary_text, summary_source, pdf_path, error_message
           FROM exec_reports WHERE id = ?""",
        (report_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    return {"data": dict(row)}


@router.get("/api/reports/executive/{report_id}/pdf")
def download_executive_pdf(
    report_id: str,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(get_current_user),
):
    """Stream the PDF bytes for a completed executive report."""
    row = conn.execute(
        "SELECT status, pdf_path FROM exec_reports WHERE id = ?",
        (report_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")
    if row["status"] != "done":
        raise HTTPException(
            status_code=409,
            detail=f"Report is not ready yet (status={row['status']}).",
        )

    pdf_path = Path(row["pdf_path"])
    if not pdf_path.exists():
        raise HTTPException(status_code=410, detail="PDF file missing from disk.")

    pdf_bytes = pdf_path.read_bytes()
    filename  = f"vra-exec-report-{report_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )
