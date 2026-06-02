"""Repository for the risk_acceptances table."""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def create(
    conn: sqlite3.Connection,
    job_id: str,
    accepted_by: str,
    justification: str,
    compensating_controls: Optional[str] = None,
    expiry_date: Optional[str] = None,
    review_trigger: Optional[str] = None,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO risk_acceptances
               (job_id, accepted_by, justification, compensating_controls,
                expiry_date, review_trigger, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?)""",
        (job_id, accepted_by, justification, compensating_controls,
         expiry_date, review_trigger, now),
    )
    conn.commit()
    return get_by_id(conn, cur.lastrowid)


def get_by_id(conn: sqlite3.Connection, ra_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM risk_acceptances WHERE id = ?", (ra_id,)
    ).fetchone()
    return dict(row) if row else None


def get_by_job(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM risk_acceptances WHERE job_id = ? ORDER BY created_at DESC",
        (job_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_all_active(conn: sqlite3.Connection) -> list[dict]:
    """Return all active acceptances across all jobs (for the Risk Register)."""
    rows = conn.execute(
        """SELECT ra.*,
                  j.main_product, j.max_risk_level, j.status AS job_status,
                  j.asset_ids, j.cve_list, j.risk_score_max,
                  j.created_at AS job_created_at
           FROM risk_acceptances ra
           JOIN jobs j ON j.job_id = ra.job_id
           WHERE ra.status = 'active'
           ORDER BY ra.created_at DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_expired_active(conn: sqlite3.Connection) -> list[dict]:
    """Return acceptances whose expiry_date has passed but status is still 'active'."""
    today = datetime.now(timezone.utc).date().isoformat()
    rows = conn.execute(
        """SELECT * FROM risk_acceptances
           WHERE status = 'active'
             AND expiry_date IS NOT NULL
             AND expiry_date < ?""",
        (today,),
    ).fetchall()
    return [dict(r) for r in rows]


def update_status(conn: sqlite3.Connection, ra_id: int, new_status: str) -> bool:
    conn.execute(
        "UPDATE risk_acceptances SET status = ? WHERE id = ?",
        (new_status, ra_id),
    )
    conn.commit()
    return conn.execute(
        "SELECT changes()"
    ).fetchone()[0] > 0
