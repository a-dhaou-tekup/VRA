"""AI Recommendations (RAG) router."""

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.models.schemas import (
    FeedbackRequest,
    AdviceFeedbackRequest,
    DispositionRequest,
)
from api.repositories.jobs_repo import get_job_by_id, safe_json_loads
from api.services import rag_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rag", tags=["AI Recommendations"])

_WRITERS      = ("analyst", "remediation_owner", "admin")
_DISPOSITIONS = frozenset({"accepted", "edited", "rejected"})


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

    # Persist to cache — metadata is nested under result["_meta"] by recommender.py
    _meta = result.get("_meta") or {}
    advice_id = None
    try:
        advice_id = rag_service.cache_advice(
            conn,
            job_id=job_id,
            job=job,
            recommendation_json=result,
            model_name=_meta.get("model") or result.get("model", "unknown"),
            latency_ms=_meta.get("latency_ms") or latency_ms,
            prompt_tokens=_meta.get("prompt_tokens") or result.get("prompt_tokens", 0),
            response_tokens=_meta.get("response_tokens") or result.get("response_tokens", 0),
        )
    except Exception as exc:
        logger.warning("Failed to cache advice for job %s: %s", job_id, exc)

    result["cached"]   = False
    result["cache_id"] = advice_id
    # Flatten _meta so the frontend can read model/latency_ms consistently
    _m = result.get("_meta") or {}
    result.setdefault("model",      _m.get("model", "unknown"))
    result.setdefault("latency_ms", _m.get("latency_ms", latency_ms))
    return {"data": result}


# ── Job-level feedback (DEPRECATED) ──────────────────────────────────────────

@router.post("/jobs/{job_id}/feedback")
def submit_feedback(
    job_id:  str,
    payload: FeedbackRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_WRITERS)),
):
    """
    Update the most-recent llm_advice row for this job.

    **DEPRECATED** — this endpoint targets the *most recent* row and cannot
    address specific advice records.  Prefer
    ``POST /api/rag/advice/{advice_id}/feedback`` which targets a row by PK
    (the ``cache_id`` returned by ``/recommend``).  This endpoint is kept for
    backward compatibility.
    """
    if payload.feedback not in (1, -1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="feedback must be 1 (helpful) or -1 (not helpful)",
        )

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


# ── Advice-level feedback (preferred) ────────────────────────────────────────

@router.post("/advice/{advice_id}/feedback", status_code=status.HTTP_200_OK)
def advice_feedback(
    advice_id: int,
    payload:   AdviceFeedbackRequest,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(require_role(*_WRITERS)),
):
    """
    Rate a specific llm_advice row by its ``id`` (the ``cache_id`` field
    returned by ``/recommend``).  ``feedback=1`` helpful, ``-1`` not helpful.
    Optionally attach a free-text ``note``.
    """
    if payload.feedback not in (1, -1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="feedback must be 1 (helpful) or -1 (not helpful)",
        )

    row = conn.execute(
        "SELECT id FROM llm_advice WHERE id = ?", (advice_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No advice row with id={advice_id}",
        )

    conn.execute(
        "UPDATE llm_advice SET feedback = ?, feedback_note = ? WHERE id = ?",
        (payload.feedback, payload.note, advice_id),
    )
    conn.commit()

    return {
        "data": {
            "advice_id": advice_id,
            "feedback":  payload.feedback,
            "note":      payload.note,
        }
    }


# ── Advice-level disposition ──────────────────────────────────────────────────

@router.post("/advice/{advice_id}/disposition", status_code=status.HTTP_200_OK)
def advice_disposition(
    advice_id: int,
    payload:   DispositionRequest,
    conn:      sqlite3.Connection = Depends(get_db),
    user:      dict               = Depends(require_role(*_WRITERS)),
):
    """
    Record what the analyst did with the advice:

    * ``accepted``  — followed the recommendation as-is
    * ``edited``    — adapted it before applying
    * ``rejected``  — decided not to follow it
    """
    if payload.disposition not in _DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"disposition must be one of {sorted(_DISPOSITIONS)}",
        )

    row = conn.execute(
        "SELECT id FROM llm_advice WHERE id = ?", (advice_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No advice row with id={advice_id}",
        )

    conn.execute(
        "UPDATE llm_advice SET disposition = ? WHERE id = ?",
        (payload.disposition, advice_id),
    )
    conn.commit()

    return {"data": {"advice_id": advice_id, "disposition": payload.disposition}}


# ── Feedback / disposition summary ───────────────────────────────────────────

@router.get("/feedback/summary")
def feedback_summary(
    conn: sqlite3.Connection = Depends(get_db),
    user: dict               = Depends(get_current_user),
):
    """
    Aggregate feedback and disposition counts across all llm_advice rows,
    split by ``interaction_type`` (currently only ``recommendation``; future
    types: ``chat``, ``guided_question``).
    """
    rows = conn.execute(
        """SELECT
               COALESCE(interaction_type, 'recommendation') AS itype,
               SUM(CASE WHEN feedback =  1 THEN 1 ELSE 0 END) AS helpful,
               SUM(CASE WHEN feedback = -1 THEN 1 ELSE 0 END) AS unhelpful,
               SUM(CASE WHEN feedback =  0 OR feedback IS NULL
                        THEN 1 ELSE 0 END)                    AS no_feedback,
               SUM(CASE WHEN disposition = 'accepted'  THEN 1 ELSE 0 END) AS accepted,
               SUM(CASE WHEN disposition = 'edited'    THEN 1 ELSE 0 END) AS edited,
               SUM(CASE WHEN disposition = 'rejected'  THEN 1 ELSE 0 END) AS rejected,
               SUM(CASE WHEN disposition IS NULL        THEN 1 ELSE 0 END) AS no_disposition,
               COUNT(*) AS total
           FROM llm_advice
           GROUP BY itype"""
    ).fetchall()

    by_type: dict = {}
    totals = dict(
        helpful=0, unhelpful=0, no_feedback=0,
        accepted=0, edited=0, rejected=0, no_disposition=0, total=0,
    )

    for r in rows:
        itype = r["itype"]
        entry = {
            "helpful":        r["helpful"],
            "unhelpful":      r["unhelpful"],
            "no_feedback":    r["no_feedback"],
            "accepted":       r["accepted"],
            "edited":         r["edited"],
            "rejected":       r["rejected"],
            "no_disposition": r["no_disposition"],
            "total":          r["total"],
        }
        by_type[itype] = entry
        for k in totals:
            totals[k] += entry.get(k, 0)

    return {
        "data": {
            **totals,
            "by_interaction_type": by_type,
        }
    }


# ── ChromaDB stats ────────────────────────────────────────────────────────────

@router.get("/stats")
def rag_stats(
    user: dict = Depends(get_current_user),
):
    stats = rag_service.get_chroma_stats()
    return {"data": stats}


# ── Multi-collection inventory (admin + auditor) ──────────────────────────────

@router.get("/collections")
def list_collections(
    user: dict = Depends(require_role("admin", "auditor")),
):
    """Return all ChromaDB collections with their document counts.

    RBAC: Administrator and Auditor roles only.

    Response shape::

        {
          "data": [
            {
              "name": "vra_advisories",
              "count": 1592,
              "description": "Legacy unified collection …",
              "embedding_model": "all-MiniLM-L6-v2"
            },
            { "name": "cve_descriptions",  "count": …, … },
            { "name": "vendor_advisories", "count": …, … },
            { "name": "internal_runbooks", "count": …, … }
          ]
        }
    """
    from rag.indexer import get_all_collection_stats
    return {"data": get_all_collection_stats()}
