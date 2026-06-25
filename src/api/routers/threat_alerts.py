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
from pydantic import BaseModel, Field

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
    asset_id:    Optional[str] = None   # None = scan all assets
    use_nvd:     bool = True
    use_osv:     bool = True
    force_reset: bool = Field(
        False,
        description="Delete open alerts for the scanned scope first, "
                    "so this run's new_alerts count is accurate.",
    )
    auto_promote: bool = Field(
        False,
        description="Immediately promote newly-found open alerts into remediation "
                    "jobs after matching completes (grouping='by_cve').",
    )
    auto_promote_grouping: str = Field(
        "by_cve",
        description="Grouping strategy used when auto_promote=true: "
                    "by_cve | by_asset_product | by_product",
    )


class PromoteRequest(BaseModel):
    alert_ids: Optional[list[int]] = Field(
        None, description="Specific alert IDs to promote; omit to promote all open alerts."
    )
    grouping: str = Field(
        "by_cve",
        description="Grouping strategy: by_cve | by_asset_product | by_product",
    )


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
    status_filter:   Optional[str] = Query(None, alias="status"),
    alert_type:      Optional[str] = Query(None),
    asset_id:        Optional[str] = Query(None, description="Partial match on hostname or IP"),
    kev_only:        bool          = Query(False),
    cve_id:          Optional[str] = Query(None, description="Partial match on CVE ID"),
    severity:        Optional[str] = Query(None, description="Exact severity: CRITICAL|HIGH|MEDIUM|LOW"),
    matched_product: Optional[str] = Query(None, description="Partial match on matched product name"),
    sort_by:         str           = Query("is_kev",  description="Column to sort by"),
    sort_dir:        str           = Query("desc",    description="asc | desc"),
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict = Depends(get_current_user),
):
    rows, total = threat_alerts_repo.get_all(
        conn,
        status          = status_filter or "open",
        alert_type      = alert_type,
        asset_id        = asset_id,
        is_kev          = True if kev_only else None,
        cve_id          = cve_id,
        severity        = severity,
        matched_product = matched_product,
        sort_by         = sort_by,
        sort_dir        = sort_dir,
        limit           = limit,
        offset          = offset,
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
    """Trigger a CPE→CVE matching pass.

    If ``auto_promote=true`` the newly found open alerts are immediately
    promoted into remediation jobs in the same request (using the
    ``auto_promote_grouping`` strategy, default ``by_cve``).
    """
    from api.services.threat_matching_service import run_threat_matching

    try:
        match_result = run_threat_matching(
            conn,
            asset_id    = payload.asset_id,
            use_nvd     = payload.use_nvd,
            use_osv     = payload.use_osv,
            force_reset = payload.force_reset,
        )
    except Exception as exc:
        logger.error("Threat matching failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    promotion_result: dict | None = None
    if payload.auto_promote:
        from api.services.alert_promotion_service import promote_alerts_to_jobs
        try:
            promotion_result = promote_alerts_to_jobs(
                conn,
                alert_ids = None,          # all open alerts for the scanned scope
                grouping  = payload.auto_promote_grouping,
                actor     = user.get("username", "system"),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"auto_promote: {exc}")
        except Exception as exc:
            logger.error("Auto-promotion after match failed: %s", exc)
            # Don't mask the match result — return it alongside the error
            return {"data": {**match_result, "promotion_error": str(exc)}}

    response: dict = {**match_result}
    if promotion_result is not None:
        response["promotion"] = promotion_result

    return {"data": response}


# ── Promote alerts → remediation jobs ────────────────────────────────────────

@router.post("/threat-alerts/promote")
def promote_alerts(
    payload:    PromoteRequest,
    conn:       sqlite3.Connection = Depends(get_db),
    user:       dict = Depends(require_role(*_WRITERS)),
):
    """Promote open threat alerts into remediation jobs.

    Groups alerts by the chosen strategy and creates one job per group with
    idempotent fingerprinting (re-running skips already-existing jobs).
    """
    from api.services.alert_promotion_service import promote_alerts_to_jobs

    try:
        result = promote_alerts_to_jobs(
            conn,
            alert_ids = payload.alert_ids,
            grouping  = payload.grouping,
            actor     = user.get("username", "system"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("Alert promotion failed: %s", exc)
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
