"""FTS5 mirror of the ChromaDB advisory corpus.

A separate SQLite database at ``data/cache/rag_fts.db`` holds a single
FTS5 virtual table ``rag_chunks_fts`` that mirrors every document upserted
into the ChromaDB collection.  This gives us exact-match / BM25 keyword
search as the sparse leg of hybrid retrieval.

Public API
----------
init_fts_db()          Create the virtual table if absent (idempotent).
write_chunks(rows)     Bulk insert-or-replace (list of (doc_id, text)).
delete_chunk(doc_id)   Remove a single chunk.
bm25_search(query, k)  Return top-k results as list[dict(id, text, score)].
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_FTS_DB_PATH = Path(__file__).parent.parent.parent / "data" / "cache" / "rag_fts.db"

_conn: Optional[sqlite3.Connection] = None


# ── Connection management ─────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    """Return (or create) the singleton WAL-mode connection to rag_fts.db."""
    global _conn
    if _conn is not None:
        return _conn

    _FTS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(_FTS_DB_PATH), check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    init_fts_db(_conn)
    logger.info("FTS5 database ready at %s", _FTS_DB_PATH)
    return _conn


# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS rag_chunks_fts USING fts5(
    doc_id UNINDEXED,
    text,
    tokenize = 'porter ascii'
);
"""

_CREATE_LOOKUP = """
CREATE TABLE IF NOT EXISTS rag_chunks_lookup (
    doc_id   TEXT PRIMARY KEY,
    text     TEXT NOT NULL
);
"""


def init_fts_db(conn: Optional[sqlite3.Connection] = None) -> None:
    """Create FTS5 virtual table and lookup table if they don't exist."""
    c = conn or _get_conn()
    c.execute(_CREATE_FTS)
    c.execute(_CREATE_LOOKUP)
    c.commit()
    logger.debug("FTS5 schema ensured.")


# ── Write helpers ─────────────────────────────────────────────────────────────

def write_chunks(rows: list[tuple[str, str]]) -> int:
    """Bulk insert-or-replace (doc_id, text) pairs into the FTS5 index.

    Safe to call repeatedly — existing rows are replaced.
    Returns the number of rows written.
    """
    if not rows:
        return 0

    conn = _get_conn()
    # Delete existing entries first to avoid FTS5 duplicate accumulation
    doc_ids = [r[0] for r in rows]
    placeholders = ",".join("?" * len(doc_ids))
    conn.execute(
        f"DELETE FROM rag_chunks_fts WHERE doc_id IN ({placeholders})", doc_ids
    )
    conn.executemany(
        "INSERT INTO rag_chunks_fts(doc_id, text) VALUES (?, ?)", rows
    )
    # Keep a plain-text lookup table for easy text fetch by ID
    conn.executemany(
        "INSERT OR REPLACE INTO rag_chunks_lookup(doc_id, text) VALUES (?, ?)",
        rows,
    )
    conn.commit()
    return len(rows)


def delete_chunk(doc_id: str) -> None:
    """Remove a single chunk from the FTS5 index."""
    conn = _get_conn()
    conn.execute("DELETE FROM rag_chunks_fts WHERE doc_id = ?", (doc_id,))
    conn.execute("DELETE FROM rag_chunks_lookup WHERE doc_id = ?", (doc_id,))
    conn.commit()


# ── Query ─────────────────────────────────────────────────────────────────────

def bm25_search(query: str, k: int = 50) -> list[dict]:
    """Run a BM25 keyword search and return up to *k* results.

    Each result dict has keys: ``id``, ``text``, ``score``.
    ``score`` is the raw FTS5 bm25() value — more-negative = more relevant.
    Results are ordered best-first (ascending bm25 value).

    Escapes FTS5 special characters to avoid syntax errors on bare CVE IDs
    and other structured query strings.
    """
    conn = _get_conn()

    # Check row count first — avoids confusing FTS5 errors on empty tables
    count = conn.execute("SELECT COUNT(*) FROM rag_chunks_lookup").fetchone()[0]
    if count == 0:
        logger.warning("FTS5 table is empty — run scripts/backfill_fts.py first")
        return []

    # Escape FTS5 special characters so raw CVE IDs like "CVE-2024-3094" work
    safe_query = _escape_fts5(query)

    try:
        rows = conn.execute(
            """
            SELECT doc_id, text, bm25(rag_chunks_fts) AS score
            FROM   rag_chunks_fts
            WHERE  rag_chunks_fts MATCH ?
            ORDER  BY score          -- more-negative bm25 = better rank
            LIMIT  ?
            """,
            (safe_query, k),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        logger.warning("FTS5 query failed (query=%r): %s", safe_query, exc)
        return []

    results = [{"id": r["doc_id"], "text": r["text"], "score": r["score"]} for r in rows]
    logger.info("FTS5 BM25 search returned %d results for query: %.60s", len(results), query)
    return results


def chunk_count() -> int:
    """Return the number of chunks currently in the FTS5 index."""
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) FROM rag_chunks_lookup").fetchone()
    return row[0] if row else 0


# ── FTS5 query sanitiser ──────────────────────────────────────────────────────

def _escape_fts5(query: str) -> str:
    """Wrap each token in double-quotes so FTS5 treats them as phrase literals.

    This avoids syntax errors from hyphens (CVE-2024-...) and other chars
    that FTS5 parses as operators.  Simple but effective for our use-case.
    """
    tokens = query.split()
    # Escape embedded double-quotes inside tokens
    escaped = ['"' + t.replace('"', '""') + '"' for t in tokens if t]
    return " OR ".join(escaped) if escaped else '""'
