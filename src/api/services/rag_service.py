"""RAG service — wraps the recommendation pipeline and manages the llm_advice cache."""

import hashlib
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def safe_json_loads(v, default=None):
    if default is None:
        default = {}
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


# ── Helpers ───────────────────────────────────────────────────────────────────

def compute_cve_hash(cve_list: list[str], product: str) -> str:
    """SHA-256 of sorted CVE list + product — used as cache key."""
    payload = ",".join(sorted(c.strip().upper() for c in cve_list)) + "|" + product.lower()
    return hashlib.sha256(payload.encode()).hexdigest()


# ── Cache operations ──────────────────────────────────────────────────────────

def get_cached_advice(conn: sqlite3.Connection, job: dict) -> Optional[dict]:
    """Return cached llm_advice for this job's CVE+product combination, or None."""
    from api.repositories.jobs_repo import safe_json_loads as sjl

    cve_list = sjl(job.get("cve_list"), [])
    product  = job.get("main_product", "")

    if not cve_list:
        return None

    cve_hash = compute_cve_hash(cve_list, product)

    cursor = conn.execute(
        """SELECT * FROM llm_advice
           WHERE cve_hash = ? AND job_id = ?
           ORDER BY created_at DESC LIMIT 1""",
        (cve_hash, job.get("job_id", "")),
    )
    row = cursor.fetchone()
    if row is None:
        return None

    record = dict(row)
    record["recommendation_json"] = safe_json_loads(
        record.get("recommendation_json"), {}
    )
    return record


def cache_advice(
    conn: sqlite3.Connection,
    job_id: str,
    job: dict,
    recommendation_json: dict,
    model_name: str,
    latency_ms: int,
    prompt_tokens: int = 0,
    response_tokens: int = 0,
) -> int:
    """Persist a recommendation to llm_advice. Returns row id."""
    from api.repositories.jobs_repo import safe_json_loads as sjl

    cve_list = sjl(job.get("cve_list"), [])
    product  = job.get("main_product", "")
    cve_hash = compute_cve_hash(cve_list, product)
    now      = datetime.now(timezone.utc).isoformat()

    cursor = conn.execute(
        """INSERT INTO llm_advice
               (job_id, cve_hash, product, recommendation_json, model_name,
                prompt_tokens, response_tokens, latency_ms, feedback, created_at)
           VALUES (?,?,?,?,?,?,?,?,0,?)""",
        (
            job_id,
            cve_hash,
            product,
            json.dumps(recommendation_json),
            model_name,
            prompt_tokens,
            response_tokens,
            latency_ms,
            now,
        ),
    )
    conn.commit()
    return cursor.lastrowid


# ── Generation ────────────────────────────────────────────────────────────────

def generate_recommendation(job: dict) -> dict:
    """Call the RAG recommender pipeline. Gracefully handles missing module."""
    start = time.monotonic()

    try:
        from rag.recommender import generate_recommendation as _gen
        result = _gen(job)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        if isinstance(result, dict) and "latency_ms" not in result:
            result["latency_ms"] = elapsed_ms
        return result
    except ModuleNotFoundError:
        logger.warning("rag.recommender not available — returning stub recommendation")
    except Exception as exc:
        logger.error("RAG generation error for job %s: %s", job.get("job_id"), exc)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return {
        "job_id":           job.get("job_id"),
        "product":          job.get("main_product", "N/A"),
        "risk_level":       job.get("max_risk_level", "N/A"),
        "recommendation":   "RAG pipeline not available. Please ensure rag.recommender is configured.",
        "remediation_steps": [],
        "references":        [],
        "model":             "unavailable",
        "latency_ms":        elapsed_ms,
        "cached":            False,
    }


# ── ChromaDB stats ────────────────────────────────────────────────────────────

def get_chroma_stats() -> dict:
    """Return ChromaDB collection stats. Returns stub if ChromaDB is not available."""
    try:
        from rag.retriever import get_collection_stats
        return get_collection_stats()
    except Exception as exc:
        logger.warning("Could not retrieve ChromaDB stats: %s", exc)

    return {
        "total_chunks":    0,
        "total_files":     0,
        "collection_name": "vra_rag",
        "model":           "unavailable",
        "error":           "RAG retriever not initialised",
    }
