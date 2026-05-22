"""Repository for the workaround_records table."""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def create(
    conn: sqlite3.Connection,
    job_id: str,
    control_description: str,
    recorded_by: str,
    followup_date: Optional[str] = None,
) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """INSERT INTO workaround_records
               (job_id, control_description, followup_date, recorded_by, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (job_id, control_description, followup_date, recorded_by, now),
    )
    conn.commit()
    return get_by_id(conn, cur.lastrowid)


def get_by_id(conn: sqlite3.Connection, wr_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM workaround_records WHERE id = ?", (wr_id,)
    ).fetchone()
    return dict(row) if row else None


def get_by_job(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM workaround_records WHERE job_id = ? ORDER BY created_at DESC",
        (job_id,),
    ).fetchall()
    return [dict(r) for r in rows]
