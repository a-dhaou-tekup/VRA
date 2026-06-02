"""Agent chat router — POST /api/agent/chat.

Runs the multi-step agent loop (native Ollama tool-calling → ReAct fallback)
and returns a structured response suitable for display and eval_agent.py:

    {
      "answer":       str,            -- final synthesised answer
      "tools_called": [               -- ordered trace of tool invocations
          {"name": str, "args": dict, "ok": bool}
      ],
      "contexts":     [...]           -- RAG chunks if search_knowledge was used
      "iterations":   int,            -- loop iterations consumed
      "mode":         "native"|"react",
      "model":        str,
    }

Auth: JWT required (all authenticated roles may read).
Write operations are impossible — the tool layer is read-only by construction.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.auth import get_current_user
from api.db.connection import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["Agent"])


# ── Request schema ────────────────────────────────────────────────────────────

class HistoryMessage(BaseModel):
    role:    str = Field(..., pattern="^(user|assistant)$")
    content: str = Field(..., min_length=1, max_length=4000)


class ChatRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="The user's natural-language question.",
    )
    history: Optional[list[HistoryMessage]] = Field(
        default=None,
        max_length=20,
        description="Optional prior turns for multi-turn conversations.",
    )


class AgentFeedbackRequest(BaseModel):
    feedback: int  = Field(..., description="1 = helpful, -1 = not helpful")
    question: str  = Field(default="", max_length=2000)
    answer:   str  = Field(default="", max_length=10_000)
    note:     Optional[str] = Field(default=None, max_length=1000)


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/chat")
def agent_chat(
    body: ChatRequest,
    user: dict = Depends(get_current_user),
):
    """Run the VRA agent loop for a natural-language question.

    The agent selects and calls read-only VRA tools to retrieve live data,
    then synthesises a grounded answer. The full tool-call trace and any
    RAG advisory contexts are returned alongside the answer so the caller
    can display them or feed them to ``eval_agent.py``.
    """
    from agent.orchestrator import run_agent

    history_dicts = (
        [h.model_dump() for h in body.history] if body.history else None
    )

    try:
        result = run_agent(
            question=body.question,
            role=user["role"],
            username=user["username"],
            history=history_dicts,
        )
    except Exception as exc:
        logger.exception("Agent chat error for user '%s': %s", user["username"], exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent error: {exc}",
        )

    return {"data": result}


# ── Feedback ─────────────────────────────────────────────────────────────────

@router.post("/feedback", status_code=status.HTTP_200_OK)
def agent_feedback(
    payload: AgentFeedbackRequest,
    conn:    sqlite3.Connection = Depends(get_db),
    user:    dict               = Depends(get_current_user),
):
    """Store thumbs-up / thumbs-down feedback for an agent chat turn.

    Writes a row into ``llm_advice`` with ``interaction_type='chat'`` so the
    existing feedback-summary endpoint (``/api/rag/feedback/summary``) can
    aggregate chat satisfaction alongside recommendation feedback.
    """
    if payload.feedback not in (1, -1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="feedback must be 1 (helpful) or -1 (not helpful)",
        )

    cur = conn.execute(
        """INSERT INTO llm_advice
               (interaction_type, question, recommendation_json,
                feedback, feedback_note, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            "chat",
            payload.question[:2000],
            json.dumps({"answer": payload.answer[:5000]}),
            payload.feedback,
            payload.note,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    return {"data": {"id": cur.lastrowid, "feedback": payload.feedback}}


# ── Introspection ─────────────────────────────────────────────────────────────

@router.get("/tools")
def list_agent_tools(user: dict = Depends(get_current_user)):
    """Return the registered tool descriptors (name, description, schema).

    Useful for building UI tool-trace chips and for eval_agent.py to validate
    that expected tools are present.
    """
    from agent.registry import list_tools
    return {"data": list_tools()}
