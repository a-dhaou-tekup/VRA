"""Threat-exposure alerts router (P4b).

Endpoints
---------
GET   /api/threat-alerts                  — list all alerts (filterable)
GET   /api/threat-alerts/summary          — open-alert counts
GET   /api/assets/{asset_id}/threats      — per-asset open alerts
POST  /api/threat-alerts/match            — trigger a new matching run
PATCH /api/threat-alerts/{alert_id}       — dismiss / resolve an alert
GET   /api/threat-alerts/breach-check     — optional HIBP domain check
"""

import logging
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from pydantic import BaseModel

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.repositories import threat_alerts_repo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Threat Alerts"])

_WRITERS = ("analyst", "remediation_owner", "admin")


# ── Schemas ────────────────────────────────────────────────────────────────────

class AlertStatusUpdate(BaseModel):
    status: str   # dismissed | resolved | open


class MatchRequest(BaseModel):
    asset_id:  Optional[str] = None   # None = scan all assets
    use_nvd:   bool = True
    use_osv:   bool = True


# ── Summary ────────────────────────────────────────────────────────────────────

@router.get("/threat-alerts/summary")
def alert_summary(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return {"data": threat_alerts_repo.summary_counts(conn)}


# ── List all alerts ────────────────────────────────────────────────────────────

@router.get("/threat-alerts")
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    alert_type:    Optional[str] = Query(None),
    asset_id:      Optional[str] = Query(None),
    kev_only:      bool          = Query(False),
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict = Depends(get_current_user),
):
    rows, total = threat_alerts_repo.get_all(
        conn,
        status     = status_filter or "open",
        alert_type = alert_type,
        asset_id   = asset_id,
        is_kev     = True if kev_only else None,
        limit      = limit,
        offset     = offset,
    )
    return {"data": rows, "total": total}


# ── Per-asset alerts ──────────────────────────────────────────────────────────

@router.get("/assets/{asset_id}/threats")
def asset_threats(
    asset_id: str,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(get_current_user),
):
    return {"data": threat_alerts_repo.get_by_asset(conn, asset_id)}


# ── Trigger matching run ───────────────────────────────────────────────────────

@router.post("/threat-alerts/match")
def run_match(
    payload:    MatchRequest,
    background: BackgroundTasks,
    conn:       sqlite3.Connection = Depends(get_db),
    user:       dict = Depends(require_role(*_WRITERS)),
):
    """Trigger a CPE→CVE matching pass. Runs in the background."""
    from api.services.threat_matching_service import run_threat_matching

    # Run synchronously (small fleets finish fast; add background=True for large ones)
    try:
        result = run_threat_matching(
            conn,
            asset_id = payload.asset_id,
            use_nvd  = payload.use_nvd,
            use_osv  = payload.use_osv,
        )
    except Exception as exc:
        logger.error("Threat matching failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    return {"data": result}


# ── Update alert status ────────────────────────────────────────────────────────

@router.patch("/threat-alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload:  AlertStatusUpdate,
    conn:     sqlite3.Connection = Depends(get_db),
    user:     dict = Depends(require_role(*_WRITERS)),
):
    valid = {"open", "dismissed", "resolved"}
    if payload.status not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(valid)}",
        )
    ok = threat_alerts_repo.update_status(conn, alert_id, payload.status)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    rows, _ = threat_alerts_repo.get_all(conn, status=None, limit=1, offset=0)
    row = conn.execute(
        "SELECT ta.*, a.hostname FROM threat_alerts ta JOIN assets a ON a.asset_id=ta.asset_id WHERE ta.id=?",
        (alert_id,)
    ).fetchone()
    return {"data": dict(row) if row else {"id": alert_id}}


# ── Domain breach-notification check (optional HIBP) ──────────────────────────

@router.get("/threat-alerts/breach-check")
def domain_breach_check(
    domain: str = Query(..., description="Your own domain to check (e.g. company.com)"),
    user:   dict = Depends(get_current_user),
):
    """Opt-in breach-notification check via HIBP Domain API.

    Requires HIBP_API_KEY env var. Stubs gracefully if absent.
    Only ever call for your OWN domain.
    """
    from api.services.threat_matching_service import check_domain_breach
    result = check_domain_breach(domain)
    return {"data": result}
