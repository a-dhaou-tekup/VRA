"""Lifecycle router — extended state machine, risk acceptances, workarounds.

Endpoints
---------
POST  /api/jobs/{job_id}/transition          — advance lifecycle state
POST  /api/jobs/{job_id}/risk-acceptance     — create a risk acceptance record (risk_owner|admin)
PATCH /api/risk-acceptances/{ra_id}          — expire/supersede an acceptance (risk_owner|admin)
GET   /api/risk-register                     — all active risk acceptances (any auth'd user)
POST  /api/jobs/{job_id}/workaround          — record a workaround control
GET   /api/jobs/{job_id}/workarounds         — list workarounds for a job
"""

from fastapi import APIRouter, Depends, HTTPException, status

from api.db.connection import get_db
from api.dependencies import get_current_user, require_role
from api.models.schemas import (
    LifecycleTransition,
    RiskAcceptanceCreate,
    RiskAcceptanceExpire,
    WorkaroundCreate,
)
from api.services.lifecycle_service import transition_job
from api.repositories import risk_acceptance_repo, workaround_repo

router = APIRouter(prefix="/api", tags=["Lifecycle"])


# ── Lifecycle transition ──────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/transition")
def advance_lifecycle(
    job_id: str,
    payload: LifecycleTransition,
    conn=Depends(get_db),
    user: dict = Depends(require_role(
        "analyst", "remediation_owner", "risk_owner", "admin"
    )),
):
    """Move a job to a new lifecycle state.

    Only *risk_owner* / *admin* may transition INTO risk-acceptance states.
    """
    RISK_STATES = {"RISK_ACCEPTED"}
    if payload.new_status in RISK_STATES and user["role"] not in ("risk_owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only 'risk_owner' or 'admin' may move a job to RISK_ACCEPTED.",
        )

    updated = transition_job(
        conn,
        job_id,
        payload.new_status,
        changed_by=user["username"],
        comment=payload.comment,
        lifecycle_note=payload.lifecycle_note,
    )
    return {"data": updated}


# ── Risk acceptances ──────────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/risk-acceptance", status_code=status.HTTP_201_CREATED)
def create_risk_acceptance(
    job_id: str,
    payload: RiskAcceptanceCreate,
    conn=Depends(get_db),
    user: dict = Depends(require_role("risk_owner", "admin")),
):
    """Record formal risk acceptance for a job. Requires risk_owner or admin role."""
    ra = risk_acceptance_repo.create(
        conn,
        job_id=job_id,
        accepted_by=user["username"],
        justification=payload.justification,
        compensating_controls=payload.compensating_controls,
        expiry_date=payload.expiry_date,
        review_trigger=payload.review_trigger,
    )
    return {"data": ra}


@router.patch("/risk-acceptances/{ra_id}")
def update_risk_acceptance(
    ra_id: int,
    payload: RiskAcceptanceExpire,
    conn=Depends(get_db),
    user: dict = Depends(require_role("risk_owner", "admin")),
):
    """Mark a risk acceptance as expired or superseded."""
    valid = {"expired", "superseded"}
    if payload.status not in valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status must be one of {sorted(valid)}",
        )
    ra = risk_acceptance_repo.get_by_id(conn, ra_id)
    if not ra:
        raise HTTPException(status_code=404, detail=f"Risk acceptance {ra_id} not found.")
    risk_acceptance_repo.update_status(conn, ra_id, payload.status)
    return {"data": risk_acceptance_repo.get_by_id(conn, ra_id)}


@router.get("/jobs/{job_id}/risk-acceptances")
def list_risk_acceptances_for_job(
    job_id: str,
    conn=Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return {"data": risk_acceptance_repo.get_by_job(conn, job_id)}


@router.get("/risk-register")
def risk_register(
    conn=Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Return all active risk acceptances with job context (the Risk Register page)."""
    rows = risk_acceptance_repo.get_all_active(conn)
    # Flag any that have passed their expiry_date
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).date().isoformat()
    for r in rows:
        r["overdue"] = bool(r.get("expiry_date") and r["expiry_date"] < today)
    return {"data": rows, "total": len(rows)}


# ── Workarounds ───────────────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/workaround", status_code=status.HTTP_201_CREATED)
def create_workaround(
    job_id: str,
    payload: WorkaroundCreate,
    conn=Depends(get_db),
    user: dict = Depends(require_role(
        "analyst", "remediation_owner", "risk_owner", "admin"
    )),
):
    wr = workaround_repo.create(
        conn,
        job_id=job_id,
        control_description=payload.control_description,
        recorded_by=user["username"],
        followup_date=payload.followup_date,
    )
    return {"data": wr}


@router.get("/jobs/{job_id}/workarounds")
def list_workarounds(
    job_id: str,
    conn=Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return {"data": workaround_repo.get_by_job(conn, job_id)}
