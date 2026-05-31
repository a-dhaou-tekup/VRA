"""Chat-with-Finding router.

Endpoints
---------
POST  /api/findings/{job_id}/chat
    Start or continue a conversation about a specific job.
    Body: { conversation_id?: str, message: str }
    Returns: SSE stream.  Each event is `data: <json>\n\n`.
    Event types:
      {"type":"token",   "content":"..."}          — LLM text chunk
      {"type":"done",    "conversation_id":"...",
                         "turn_id":"..."}           — stream finished
      {"type":"error",   "detail":"..."}            — error (stream terminates)

GET   /api/findings/{job_id}/conversations
    List conversations for this job (newest first).

GET   /api/conversations/{conversation_id}
    Full transcript with all turns and retrieved_docs per assistant turn.

RBAC
----
Security Analyst (analyst), Remediation Owner (remediation_owner), Admin → read + write
Risk Manager (risk_owner)                                               → read + write
Auditor (auditor)                                                       → read only

The SSE endpoint enforces "no auditor POST" and returns 403 before opening
the stream.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from api.auth import get_current_user, require_role
from api.db.connection import get_db
from api.repositories.jobs_repo import get_job_by_id

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Chat"])

_READERS = ("analyst", "remediation_owner", "risk_owner", "admin", "auditor")
_WRITERS = ("analyst", "remediation_owner", "risk_owner", "admin")


# ── Schemas ────────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message:         str            = Field(..., min_length=1, max_length=4000)
    conversation_id: str | None     = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


async def _generate_sse(
    job: dict,
    conversation_id: str,
    user_message: str,
    actor: str,
    db_path: str,
) -> AsyncIterator[str]:
    """Async generator that streams SSE events for one chat turn.

    Opens its own SQLite connection (separate from the request connection
    that FastAPI owns) so we can write partial turns during streaming without
    conflicting with the request lifecycle.
    """
    import asyncio
    import sqlite3 as _sqlite3

    from api.services.chat_service import (
        build_chat_query, build_chat_prompt,
        get_recent_turns, save_turn, upsert_partial_turn,
        promote_partial_to_assistant, write_audit_event,
        _load_config,
    )
    from rag.multi_collection import multi_collection_search
    from rag.reranker import rerank

    conn = _sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = _sqlite3.Row

    config = _load_config()
    full_response: list[str] = []
    retrieved_docs: list[dict] = []

    try:
        # ── 1. Persist user turn ──────────────────────────────────────────────
        save_turn(conn, conversation_id, "user", user_message)
        write_audit_event(conn, job["job_id"], conversation_id,
                          "chat.user_message", actor)

        # ── 2. Retrieve relevant docs ─────────────────────────────────────────
        recent_turns = get_recent_turns(conn, conversation_id, n=4)
        retrieval_query = build_chat_query(user_message, recent_turns[:-1])  # exclude just-saved turn
        logger.info(
            "chat[%s] retrieval query: %.80s", conversation_id, retrieval_query
        )

        candidates = multi_collection_search(retrieval_query, k=50)
        reranked   = rerank(retrieval_query, candidates, top_n=5)
        retrieved_docs = [
            {
                "source_class": d.get("source_class", ""),
                "source_id":    d.get("source_id", ""),
                "snippet":      d["text"][:200],
            }
            for d in reranked
        ]
        chunks = [
            {"text": d["text"], "metadata": d["metadata"], "distance": d.get("distance", 0.0)}
            for d in reranked
        ]

        # ── 3. Build prompt ───────────────────────────────────────────────────
        system_prompt, user_msg_for_llm = build_chat_prompt(
            job, chunks, recent_turns, user_message
        )

        # ── 4. Stream LLM tokens ──────────────────────────────────────────────
        from api.services.chat_service import stream_llm

        loop = asyncio.get_event_loop()

        def _sync_stream():
            return list(stream_llm(system_prompt, user_msg_for_llm, config))

        # Run the blocking Ollama request in a thread to stay async-friendly
        try:
            tokens = await loop.run_in_executor(None, _sync_stream)
        except RuntimeError as exc:
            yield _sse_event({"type": "error", "detail": str(exc)})
            return

        for token in tokens:
            full_response.append(token)
            yield _sse_event({"type": "token", "content": token})
            # Periodically flush partial to DB (every 20 tokens)
            if len(full_response) % 20 == 0:
                upsert_partial_turn(conn, conversation_id, "".join(full_response))

        # ── 5. Persist final assistant turn ───────────────────────────────────
        full_content = "".join(full_response)
        promote_partial_to_assistant(conn, conversation_id, full_content, retrieved_docs)
        write_audit_event(conn, job["job_id"], conversation_id,
                          "chat.assistant_reply", "system")

        turn_id = conn.execute(
            """SELECT id FROM conversation_turns
               WHERE conversation_id = ? AND role = 'assistant'
               ORDER BY created_at DESC LIMIT 1""",
            (conversation_id,),
        ).fetchone()

        yield _sse_event({
            "type":            "done",
            "conversation_id": conversation_id,
            "turn_id":         turn_id["id"] if turn_id else None,
        })

    except Exception as exc:
        logger.exception("chat SSE error for conv %s: %s", conversation_id, exc)
        # Write whatever we have so far as a partial
        if full_response:
            upsert_partial_turn(conn, conversation_id, "".join(full_response))
        yield _sse_event({"type": "error", "detail": str(exc)})

    finally:
        conn.close()


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/api/findings/{job_id}/chat")
async def chat_with_finding(
    job_id:  str,
    body:    ChatRequest,
    request: Request,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(require_role(*_READERS)),
):
    """Stream a conversational response about a specific finding/job.

    Auditors can read conversations but cannot post messages (403).
    """
    if user["role"] == "auditor":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Auditors can read conversations but cannot send messages.",
        )

    job = get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found.",
        )

    from api.services.chat_service import create_conversation
    from api.db.connection import DB_PATH

    # Resolve or create the conversation
    conv_id = body.conversation_id
    if conv_id:
        # Validate it exists and belongs to this job
        row = conn.execute(
            "SELECT id FROM conversations WHERE id = ? AND job_id = ?",
            (conv_id, job_id),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Conversation '{conv_id}' not found for job '{job_id}'.",
            )
    else:
        conv_id = create_conversation(conn, job_id, user["username"])

    # Convert Row → plain dict so it's picklable across thread boundary
    job_dict = dict(job)

    return StreamingResponse(
        _generate_sse(job_dict, conv_id, body.message, user["username"], str(DB_PATH)),
        media_type="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


@router.get("/api/findings/{job_id}/conversations")
def list_conversations(
    job_id: str,
    conn:   sqlite3.Connection = Depends(get_db),
    user:   dict               = Depends(require_role(*_READERS)),
):
    """List all conversations for a finding, newest first."""
    job = get_job_by_id(conn, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    from api.services.chat_service import get_conversations
    return {"data": get_conversations(conn, job_id)}


@router.get("/api/conversations/{conversation_id}")
def get_conversation(
    conversation_id: str,
    conn:            sqlite3.Connection = Depends(get_db),
    user:            dict               = Depends(require_role(*_READERS)),
):
    """Return the full transcript for a conversation."""
    from api.services.chat_service import get_transcript
    transcript = get_transcript(conn, conversation_id)
    if transcript is None:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return {"data": transcript}
