"""Chat-with-Finding service.

Orchestrates the retrieval → prompt → streaming LLM call for the
conversational interface on the Finding Detail page.

Public API
----------
create_conversation(conn, job_id, started_by) -> str
    Insert a new conversations row; return its id.

get_conversations(conn, job_id) -> list[dict]
    List all conversations for a job with their last turn timestamp.

get_transcript(conn, conversation_id) -> dict | None
    Return the conversation header + all turns.

get_recent_turns(conn, conversation_id, n) -> list[dict]
    Return the last *n* turns (used for prompt assembly).

build_chat_query(user_message, recent_turns) -> str
    Build the retrieval query: user message + previous user turn (sliding window).

build_chat_prompt(job, chunks, recent_turns, user_message) -> tuple[str, str]
    Return (system_prompt, user_message_for_llm).

stream_llm(system_prompt, user_message, config) -> Iterator[str]
    Yield raw text chunks from Ollama.

save_turn(conn, conversation_id, role, content, retrieved_docs) -> str
    Persist a turn; return its id.

upsert_partial_turn(conn, conversation_id, partial_content) -> str
    Write / overwrite a 'partial' turn so we survive navigation-away.

promote_partial_to_assistant(conn, turn_id, full_content, retrieved_docs) -> None
    Flip a partial turn to role='assistant' once streaming finishes.

write_audit_event(conn, job_id, conversation_id, role, started_by) -> None
    Append a job_events row for auditor reconstruction.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Iterator, Optional

import requests
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "policy.yaml"


def _load_config() -> dict:
    with open(_CONFIG_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)["rag"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short_id() -> str:
    return "conv_" + uuid.uuid4().hex[:12]


def _turn_id() -> str:
    return "turn_" + uuid.uuid4().hex[:12]


# ── Conversation CRUD ─────────────────────────────────────────────────────────

def create_conversation(
    conn: sqlite3.Connection,
    job_id: str,
    started_by: str,
    title: Optional[str] = None,
) -> str:
    conv_id = _short_id()
    conn.execute(
        "INSERT INTO conversations(id, job_id, started_by, started_at, title)"
        " VALUES (?, ?, ?, ?, ?)",
        (conv_id, job_id, started_by, _now(), title),
    )
    conn.commit()
    logger.info("chat: created conversation %s for job %s by %s", conv_id, job_id, started_by)
    return conv_id


def get_conversations(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT c.id, c.started_by, c.started_at, c.title,
                  MAX(t.created_at) AS last_turn_at,
                  COUNT(t.id)       AS turn_count
           FROM conversations c
           LEFT JOIN conversation_turns t ON t.conversation_id = c.id
                                        AND t.role != 'partial'
           WHERE c.job_id = ?
           GROUP BY c.id
           ORDER BY c.started_at DESC""",
        (job_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_transcript(conn: sqlite3.Connection, conversation_id: str) -> Optional[dict]:
    conv = conn.execute(
        "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
    ).fetchone()
    if not conv:
        return None
    turns = conn.execute(
        """SELECT id, role, content, retrieved_docs_json, created_at
           FROM conversation_turns
           WHERE conversation_id = ? AND role != 'partial'
           ORDER BY created_at""",
        (conversation_id,),
    ).fetchall()
    return {
        **dict(conv),
        "turns": [
            {
                **dict(t),
                "retrieved_docs": json.loads(t["retrieved_docs_json"])
                if t["retrieved_docs_json"]
                else [],
            }
            for t in turns
        ],
    }


def get_recent_turns(
    conn: sqlite3.Connection, conversation_id: str, n: int = 4
) -> list[dict]:
    rows = conn.execute(
        """SELECT role, content
           FROM conversation_turns
           WHERE conversation_id = ? AND role IN ('user', 'assistant')
           ORDER BY created_at DESC
           LIMIT ?""",
        (conversation_id, n),
    ).fetchall()
    return list(reversed([dict(r) for r in rows]))


# ── Turn persistence ──────────────────────────────────────────────────────────

def save_turn(
    conn: sqlite3.Connection,
    conversation_id: str,
    role: str,
    content: str,
    retrieved_docs: list[dict] | None = None,
) -> str:
    tid = _turn_id()
    conn.execute(
        """INSERT INTO conversation_turns
               (id, conversation_id, role, content, retrieved_docs_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            tid,
            conversation_id,
            role,
            content,
            json.dumps(retrieved_docs) if retrieved_docs else None,
            _now(),
        ),
    )
    conn.commit()
    return tid


def upsert_partial_turn(
    conn: sqlite3.Connection,
    conversation_id: str,
    partial_content: str,
) -> str:
    """Write-or-replace the single 'partial' row for this conversation."""
    existing = conn.execute(
        "SELECT id FROM conversation_turns WHERE conversation_id = ? AND role = 'partial'",
        (conversation_id,),
    ).fetchone()

    if existing:
        tid = existing["id"]
        conn.execute(
            "UPDATE conversation_turns SET content = ?, created_at = ? WHERE id = ?",
            (partial_content, _now(), tid),
        )
    else:
        tid = _turn_id()
        conn.execute(
            """INSERT INTO conversation_turns
                   (id, conversation_id, role, content, retrieved_docs_json, created_at)
               VALUES (?, ?, 'partial', ?, NULL, ?)""",
            (tid, conversation_id, partial_content, _now()),
        )
    conn.commit()
    return tid


def promote_partial_to_assistant(
    conn: sqlite3.Connection,
    conversation_id: str,
    full_content: str,
    retrieved_docs: list[dict] | None,
) -> None:
    """Delete the partial stub and insert the final assistant turn."""
    conn.execute(
        "DELETE FROM conversation_turns WHERE conversation_id = ? AND role = 'partial'",
        (conversation_id,),
    )
    save_turn(conn, conversation_id, "assistant", full_content, retrieved_docs)
    logger.info("chat: promoted partial → assistant for conv %s", conversation_id)


# ── Audit ─────────────────────────────────────────────────────────────────────

def write_audit_event(
    conn: sqlite3.Connection,
    job_id: str,
    conversation_id: str,
    event_type: str,
    actor: str,
) -> None:
    conn.execute(
        """INSERT INTO job_events(job_id, event_type, changed_by, comment, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (job_id, event_type,
         actor,
         f"chat conversation {conversation_id}",
         _now()),
    )
    conn.commit()


# ── Retrieval + prompt ────────────────────────────────────────────────────────

def build_chat_query(
    user_message: str,
    recent_turns: list[dict],
    cve_ids: list[str] | None = None,
) -> str:
    """Sliding-window retrieval query: CVE IDs + current message + previous user turn.

    CVE IDs are prepended so BM25 keyword matching anchors on the right
    advisories before semantic similarity runs.  Without them a generic
    question like "how does this work?" retrieves similar-sounding CVEs
    from unrelated products.
    """
    prev_user = next(
        (t["content"] for t in reversed(recent_turns) if t["role"] == "user"),
        "",
    )
    parts: list[str] = []
    if cve_ids:
        # Up to 4 CVE IDs as the lead retrieval signal
        parts.append(" ".join(cve_ids[:4]))
    parts.append(user_message)
    if prev_user and prev_user != user_message:
        parts.append(prev_user)
    return " ".join(parts)


_SYSTEM_PROMPT = (
    "You are a security remediation assistant helping an analyst understand "
    "a specific vulnerability remediation job.\n"
    "Rules:\n"
    "1. Prefer information from the retrieved sources. Cite inline as [source_class:source_id].\n"
    "2. If the retrieved sources lack specific details, answer from your training knowledge "
    "but clearly prefix that section with '**From training knowledge:**' so the analyst "
    "knows it is not corpus-verified. Never fabricate CVE IDs, CVSS scores, or vendor "
    "patch URLs — state those only if you are certain.\n"
    "3. Be concise and actionable. Prefer bullet points for steps.\n"
    "4. Always address the specific CVE(s) listed in the job context, not generic advice.\n"
    "5. The conversation history is provided for continuity; retrieved sources take "
    "precedence over prior turns."
)


def build_chat_prompt(
    job: dict,
    chunks: list[dict],
    recent_turns: list[dict],
    user_message: str,
) -> tuple[str, str]:
    """Assemble the user message for the LLM (system prompt is returned separately)."""
    import json as _json

    # Structured job metadata block
    cve_list = job.get("cve_list", "[]")
    if isinstance(cve_list, str):
        try:
            cves = _json.loads(cve_list)
        except Exception:
            cves = [cve_list] if cve_list else []
    else:
        cves = list(cve_list or [])

    meta_lines = [
        f"Job ID: {job.get('job_id', 'N/A')}",
        f"Product: {job.get('main_product', 'N/A')}",
        f"CVEs: {', '.join(str(c) for c in cves) or 'N/A'}",
        f"Risk Level: {job.get('max_risk_level', 'N/A')}",
        f"Status: {job.get('status', 'N/A')}",
        f"KEV Present: {bool(job.get('kev_present', False))}",
    ]

    # Inject detected software versions from threat_alerts (set in chat.py)
    affected = job.get("_affected_software") or []
    if affected:
        meta_lines.append("")
        meta_lines.append("Affected Software (detected on hosts):")
        for sw in affected:
            parts = []
            if sw.get("hostname"):
                parts.append(f"  Host: {sw['hostname']}")
            if sw.get("cve_id"):
                parts.append(f"CVE: {sw['cve_id']}")
            if sw.get("product"):
                parts.append(f"Product: {sw['product']}")
            if sw.get("version"):
                parts.append(f"Version: {sw['version']}")
            if sw.get("severity"):
                parts.append(f"Severity: {sw['severity']}")
            meta_lines.append("  " + " | ".join(parts))

    # Retrieved chunks tagged with source
    context_lines: list[str] = []
    for i, chunk in enumerate(chunks, start=1):
        meta  = chunk.get("metadata", {})
        sc    = meta.get("source_class", "")
        si    = meta.get("source_id", "")
        tag   = f"[{sc}:{si}]" if sc and si else ""
        context_lines.append(f"[{i}]{tag} {chunk['text']}")

    # Last 4 turns of conversation history (already limited by caller)
    history_lines: list[str] = []
    for t in recent_turns:
        prefix = "User" if t["role"] == "user" else "Assistant"
        history_lines.append(f"{prefix}: {t['content']}")

    user_msg = (
        "## Vulnerability Job\n"
        + "\n".join(meta_lines)
        + "\n\n## Retrieved Advisory Sources\n"
        + ("\n\n".join(context_lines) if context_lines else "(No sources retrieved)")
        + "\n\n## Conversation History\n"
        + ("\n".join(history_lines) if history_lines else "(New conversation)")
        + "\n\n## Current Question\n"
        + user_message
    )
    return _SYSTEM_PROMPT, user_msg


# ── LLM streaming ─────────────────────────────────────────────────────────────

def stream_llm(
    system_prompt: str,
    user_message: str,
    config: dict,
) -> Iterator[str]:
    """Yield text chunks from Ollama with stream=True.

    Raises on connection error; caller handles the SSE event loop.
    """
    import os
    url     = f"{config['ollama_url']}/api/chat"
    timeout = int(config.get("ollama_timeout") or os.getenv("OLLAMA_TIMEOUT_SECONDS", "300"))

    payload = {
        "model":   config["model"],
        "stream":  True,
        "messages": [
            {"role": "system",  "content": system_prompt},
            {"role": "user",    "content": user_message},
        ],
    }

    try:
        resp = requests.post(url, json=payload, timeout=timeout, stream=True)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(f"Could not connect to Ollama at {config['ollama_url']}: {exc}") from exc

    for line in resp.iter_lines():
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        token = data.get("message", {}).get("content", "")
        if token:
            yield token
        if data.get("done"):
            break
