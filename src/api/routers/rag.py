"""AI Recommendations (RAG) router."""

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.models.schemas import FeedbackRequest
from api.repositories.jobs_repo import get_job_by_id, safe_json_loads
from api.services import rag_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rag", tags=["AI Recommendations"])

_WRITERS = ("analyst", "remediation_owner", "admin")


# ── Generate / retrieve recommendation ───────────────────────────────────────

@router.get("/jobs/{job_id}/recommend")
def recommend(
    job_id: str,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(get_current_user),
):
    job = get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    # Check cache first
    cached = rag_service.get_cached_advice(conn, job)
    if cached:
        rec = cached.get("recommendation_json", {})
        rec["cached"]    = True
        rec["cache_id"]  = cached.get("id")
        rec["model"]     = cached.get("model_name")
        rec["latency_ms"] = cached.get("latency_ms")
        return {"data": rec}

    # Generate fresh recommendation
    import time
    start = time.monotonic()
    result = rag_service.generate_recommendation(job)
    latency_ms = int((time.monotonic() - start) * 1000)

    # Persist to cache
    try:
        rag_service.cache_advice(
            conn,
            job_id=job_id,
            job=job,
            recommendation_json=result,
            model_name=result.get("model", "unknown"),
            latency_ms=latency_ms,
            prompt_tokens=result.get("prompt_tokens", 0),
            response_tokens=result.get("response_tokens", 0),
        )
    except Exception as exc:
        logger.warning("Failed to cache advice for job %s: %s", job_id, exc)

    result["cached"] = False
    return {"data": result}


# ── Feedback ──────────────────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/feedback")
def submit_feedback(
    job_id:  str,
    payload: FeedbackRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS)),
):
    if payload.feedback not in (1, -1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="feedback must be 1 (helpful) or -1 (not helpful)",
        )

    # Update most recent llm_advice for this job
    row = conn.execute(
        "SELECT id FROM llm_advice WHERE job_id = ? ORDER BY created_at DESC LIMIT 1",
        (job_id,),
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No advice found for job '{job_id}'.",
        )

    conn.execute(
        "UPDATE llm_advice SET feedback = ? WHERE id = ?",
        (payload.feedback, row["id"]),
    )
    conn.commit()

    return {"data": {"job_id": job_id, "advice_id": row["id"], "feedback": payload.feedback}}


# ── ChromaDB stats ────────────────────────────────────────────────────────────

@router.get("/stats")
def rag_stats(
    user: dict = Depends(get_current_user),
):
    stats = rag_service.get_chroma_stats()
    return {"data": stats}
