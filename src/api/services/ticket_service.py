"""Ticket service — resolves provider and persists ticket links."""

import logging
import sqlite3
from datetime import datetime, timezone

from fastapi import HTTPException, status

from api.ticketing.base import TicketProvider

logger = logging.getLogger(__name__)


def get_provider(name: str) -> TicketProvider:
    """Return the appropriate TicketProvider for *name*."""
    name = name.lower().strip()
    if name == "jira":
        from api.ticketing.jira_provider import JiraProvider
        return JiraProvider()
    if name in ("console", ""):
        from api.ticketing.console_provider import ConsoleProvider
        return ConsoleProvider()
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unknown ticket provider '{name}'. Supported: console, jira",
    )


def create_ticket_for_job(
    conn: sqlite3.Connection,
    job_id: str,
    provider_name: str,
) -> dict:
    """Create a ticket for job_id using provider_name. Persists result in ticket_links."""
    from api.repositories.jobs_repo import get_job_by_id

    job = get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    provider = get_provider(provider_name)

    try:
        result = provider.create_ticket(job)
    except Exception as exc:
        logger.error("Ticket creation failed for job %s: %s", job_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Ticket provider error: {exc}",
        ) from exc

    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """INSERT INTO ticket_links (job_id, provider, ticket_id, ticket_url, created_at, synced_at)
           VALUES (?,?,?,?,?,?)""",
        (
            job_id,
            result.get("provider", provider_name),
            result["ticket_id"],
            result["ticket_url"],
            now,
            now,
        ),
    )
    conn.commit()
    row_id = cursor.lastrowid

    return {
        "id":         row_id,
        "job_id":     job_id,
        "provider":   result.get("provider", provider_name),
        "ticket_id":  result["ticket_id"],
        "ticket_url": result["ticket_url"],
        "created_at": now,
        "synced_at":  now,
    }
