"""Jobs router — CRUD, status transitions, triage, and event history."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
import sqlite3

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.models.schemas import JobStatusUpdate, TriageUpdate, SlaOverrideUpdate
from api.repositories import jobs_repo, events_repo
from api.services import lifecycle_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["Jobs"])

# Roles allowed to write/modify jobs
_WRITERS = ("analyst", "remediation_owner", "admin")


# ── List jobs ─────────────────────────────────────────────────────────────────

@router.get("")
def list_jobs(
    status:        Optional[str]  = Query(None),
    risk_level:    Optional[str]  = Query(None),
    business_unit: Optional[str]  = Query(None),
    kev_only:      bool           = Query(False),
    sort_by:       str            = Query("created_at"),
    sort_dir:      str            = Query("desc"),
    limit:         int            = Query(50, ge=1, le=1000),
    offset:        int            = Query(0, ge=0),
    conn:          sqlite3.Connection = Depends(get_db),
    user:          dict           = Depends(get_current_user),
):
    jobs, total = jobs_repo.get_all_jobs(
        conn,
        status=status,
        risk_level=risk_level,
        business_unit=business_unit,
        kev_only=kev_only,
        sort_by=sort_by,
        sort_dir=sort_dir,
        limit=limit,
        offset=offset,
    )
    return {"data": jobs, "total": total}


# ── Get single job ────────────────────────────────────────────────────────────

@router.get("/{job_id}")
def get_job(
    job_id: str,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    job = jobs_repo.get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )
    return {"data": job}


# ── Update status ─────────────────────────────────────────────────────────────

@router.patch("/{job_id}/status")
def update_status(
    job_id:  str,
    payload: JobStatusUpdate,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS)),
):
    updated = lifecycle_service.transition_job(
        conn,
        job_id=job_id,
        new_status=payload.status,
        changed_by=user["username"],   # use authenticated identity, not client-supplied
        comment=payload.comment,
    )
    return {"data": updated}


# ── Triage ────────────────────────────────────────────────────────────────────

@router.patch("/{job_id}/triage")
def triage_job(
    job_id:  str,
    payload: TriageUpdate,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS, "risk_owner")),
):
    valid_decisions = {"CONFIRMED", "FALSE_POSITIVE", "RISK_ACCEPTED", "DEFERRED"}
    if payload.triage_decision not in valid_decisions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid triage_decision. Must be one of {sorted(valid_decisions)}",
        )

    # Separation of duties: RISK_ACCEPTED is exclusively risk_owner / admin
    if (
        payload.triage_decision == "RISK_ACCEPTED"
        and user["role"] not in ("risk_owner", "admin")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Only 'risk_owner' or 'admin' may approve a risk acceptance. "
                f"Your role is '{user['role']}'."
            ),
        )

    ok = jobs_repo.update_triage(
        conn,
        job_id=job_id,
        triage_decision=payload.triage_decision,
        assigned_team=payload.assigned_team,
        changed_by=user["username"],
        comment=payload.comment,
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    job = jobs_repo.get_job_by_id(conn, job_id)
    return {"data": job}


# ── Custom SLA override ───────────────────────────────────────────────────────

@router.patch("/{job_id}/sla")
def set_sla_override(
    job_id:  str,
    payload: SlaOverrideUpdate,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS, "risk_owner")),
):
    """Set or clear a custom SLA override (days) for a job."""
    job = jobs_repo.get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    conn.execute(
        "UPDATE jobs SET sla_override_days = ?, updated_at = datetime('now') WHERE job_id = ?",
        (payload.sla_override_days, job_id),
    )

    # audit trail
    action = f"SLA override set to {payload.sla_override_days}d" if payload.sla_override_days else "SLA override cleared"
    comment = payload.comment or action
    events_repo.write_event(
        conn,
        job_id=job_id,
        event_type="sla_override",
        old_status=None,
        new_status=None,
        changed_by=user["username"],
        comment=comment,
    )
    conn.commit()

    updated = jobs_repo.get_job_by_id(conn, job_id)
    return {"data": updated}


# ── Event history ─────────────────────────────────────────────────────────────

@router.get("/{job_id}/events")
def get_job_events(
    job_id: str,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    job = jobs_repo.get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )
    evts = events_repo.get_events_for_job(conn, job_id)
    return {"data": evts, "total": len(evts)}
