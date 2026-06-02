"""Job lifecycle state machine — validates and applies status transitions.

P2 extends the original 8 states to 15, adds SLA-clock pause/resume when a job
enters / leaves RISK_ACCEPTED, and records a lifecycle_note on every transition.
"""

import logging
import sqlite3
from typing import Optional

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# ── State machine definition ──────────────────────────────────────────────────

ALLOWED_STATUSES = {
    "TO_DO",
    "TRIAGED",
    "PATCHABLE",
    "WORKAROUND_AVAILABLE",
    "NO_FIX",
    "IN_PROGRESS",
    "PATCHED",
    "MITIGATED",
    "DONE",
    "RISK_ACCEPTED",
    "FALSE_POSITIVE",
    "DEFERRED",
    "VERIFIED",
    "CLOSED",
    "RESURFACED",
}

STATUS_TRANSITIONS: dict[str, set[str]] = {
    "TO_DO":                {"TRIAGED", "IN_PROGRESS", "FALSE_POSITIVE", "RISK_ACCEPTED", "DEFERRED"},
    "TRIAGED":              {"PATCHABLE", "WORKAROUND_AVAILABLE", "NO_FIX", "IN_PROGRESS"},
    "PATCHABLE":            {"IN_PROGRESS"},
    "WORKAROUND_AVAILABLE": {"IN_PROGRESS"},
    "NO_FIX":               {"RISK_ACCEPTED", "DEFERRED", "IN_PROGRESS"},
    "IN_PROGRESS":          {"PATCHED", "MITIGATED", "FALSE_POSITIVE", "RISK_ACCEPTED", "DONE", "DEFERRED"},
    "PATCHED":              {"VERIFIED"},
    "MITIGATED":            {"VERIFIED", "RISK_ACCEPTED"},
    "DONE":                 {"VERIFIED", "CLOSED", "RESURFACED"},
    "RISK_ACCEPTED":        {"IN_PROGRESS"},
    "FALSE_POSITIVE":       {"TO_DO"},
    "DEFERRED":             {"IN_PROGRESS", "RISK_ACCEPTED"},
    "VERIFIED":             {"CLOSED"},
    "CLOSED":               {"RESURFACED"},  # can reopen via RESURFACED
    "RESURFACED":           {"TO_DO", "IN_PROGRESS"},
}

# States that pause the SLA clock
SLA_PAUSING_STATES = {"RISK_ACCEPTED"}


# ── Validation ────────────────────────────────────────────────────────────────

def validate_transition(current_status: str, new_status: str) -> None:
    """Raise HTTPException(400) if the transition is not allowed."""
    if new_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown status '{new_status}'. Allowed: {sorted(ALLOWED_STATUSES)}",
        )
    allowed = STATUS_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Transition '{current_status}' → '{new_status}' is not allowed. "
                f"Valid next states: {sorted(allowed) or '(none — terminal)'}"
            ),
        )


# ── SLA helpers ───────────────────────────────────────────────────────────────

def _pause_sla(conn: sqlite3.Connection, job_id: str, now: str) -> None:
    """Set sla_paused_at to *now* (only if not already paused)."""
    conn.execute(
        """UPDATE jobs
           SET sla_paused_at = CASE WHEN sla_paused_at IS NULL THEN ? ELSE sla_paused_at END,
               updated_at = ?
           WHERE job_id = ?""",
        (now, now, job_id),
    )


def _resume_sla(conn: sqlite3.Connection, job_id: str, now: str) -> None:
    """Accumulate paused days into sla_paused_days and clear sla_paused_at."""
    row = conn.execute(
        "SELECT sla_paused_at, sla_paused_days FROM jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    if not row or not row["sla_paused_at"]:
        return  # was not paused — nothing to do

    from datetime import datetime, timezone
    try:
        paused_since = datetime.fromisoformat(row["sla_paused_at"])
        now_dt = datetime.fromisoformat(now)
        delta_days = max(0, (now_dt - paused_since).days)
    except Exception:
        delta_days = 0

    accumulated = (row["sla_paused_days"] or 0) + delta_days
    conn.execute(
        """UPDATE jobs
           SET sla_paused_at = NULL,
               sla_paused_days = ?,
               updated_at = ?
           WHERE job_id = ?""",
        (accumulated, now, job_id),
    )


# ── Transition ────────────────────────────────────────────────────────────────

def transition_job(
    conn: sqlite3.Connection,
    job_id: str,
    new_status: str,
    changed_by: str,
    comment: Optional[str] = None,
    lifecycle_note: Optional[str] = None,
) -> dict:
    """Validate transition, manage SLA clock, apply status, return updated job dict."""
    from datetime import datetime, timezone
    from api.repositories.jobs_repo import get_job_by_id, update_job_status

    job = get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    old_status = job["status"]
    validate_transition(old_status, new_status)

    now = datetime.now(timezone.utc).isoformat()

    # SLA clock management
    entering_pause = new_status in SLA_PAUSING_STATES
    leaving_pause  = old_status in SLA_PAUSING_STATES and new_status not in SLA_PAUSING_STATES

    if entering_pause:
        _pause_sla(conn, job_id, now)
    elif leaving_pause:
        _resume_sla(conn, job_id, now)

    # Write lifecycle_note if provided
    if lifecycle_note is not None:
        conn.execute(
            "UPDATE jobs SET lifecycle_note = ?, updated_at = ? WHERE job_id = ?",
            (lifecycle_note, now, job_id),
        )

    update_job_status(conn, job_id, new_status, changed_by, comment)

    updated = get_job_by_id(conn, job_id)
    return updated
