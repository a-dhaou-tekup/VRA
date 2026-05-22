"""Tickets router — create and list ticket links."""

import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.models.schemas import TicketRequest
from api.services.ticket_service import create_ticket_for_job

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tickets", tags=["Tickets"])

_WRITERS = ("analyst", "remediation_owner", "admin")


# ── Create ticket for a job ───────────────────────────────────────────────────

@router.post("/jobs/{job_id}", status_code=status.HTTP_201_CREATED)
def create_ticket(
    job_id:  str,
    payload: TicketRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS)),
):
    result = create_ticket_for_job(conn, job_id, payload.provider)
    return {"data": result}


# ── List all ticket links ─────────────────────────────────────────────────────

@router.get("")
def list_tickets(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    cursor = conn.execute(
        "SELECT * FROM ticket_links ORDER BY created_at DESC"
    )
    rows = [dict(row) for row in cursor.fetchall()]
    return {"data": rows, "total": len(rows)}


# ── Tickets for a specific job ────────────────────────────────────────────────

@router.get("/jobs/{job_id}")
def get_tickets_for_job(
    job_id: str,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    from api.repositories.jobs_repo import get_job_by_id

    if get_job_by_id(conn, job_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    cursor = conn.execute(
        "SELECT * FROM ticket_links WHERE job_id = ? ORDER BY created_at DESC",
        (job_id,),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    return {"data": rows, "total": len(rows)}
