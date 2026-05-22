"""Event log repository — write and retrieve job lifecycle events."""

import sqlite3
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def write_event(
    conn: sqlite3.Connection,
    job_id: str,
    event_type: str,
    old_status: Optional[str],
    new_status: Optional[str],
    changed_by: str,
    comment: Optional[str] = None,
) -> int:
    """Insert a job_events row. Returns the new row id."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """INSERT INTO job_events
               (job_id, event_type, old_status, new_status, changed_by, comment, created_at)
           VALUES (?,?,?,?,?,?,?)""",
        (job_id, event_type, old_status, new_status, changed_by, comment, now),
    )
    return cursor.lastrowid


def get_events_for_job(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    """Return all events for a job, newest first."""
    cursor = conn.execute(
        "SELECT * FROM job_events WHERE job_id = ? ORDER BY created_at DESC",
        (job_id,),
    )
    return [dict(row) for row in cursor.fetchall()]
