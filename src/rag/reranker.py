"""Cross-encoder re-ranker for advisory documents.

Uses ``cross-encoder/ms-marco-MiniLM-L-6-v2`` (~80 MB) via the
sentence-transformers library.  The model is loaded lazily on the first
call to :func:`rerank` and kept resident in process memory thereafter.

Graceful fallback
-----------------
If the model package is not installed, or the model cannot be loaded
(network not available and no local cache), :func:`rerank` logs a WARNING
and returns the input list truncated to ``top_n``.  This lets the hybrid
pipeline degrade gracefully to pure RRF ordering on demo machines without
internet access.
"""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from rag.hybrid_search import RetrievedDoc

logger = logging.getLogger(__name__)

_CROSS_ENCODER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# Module-level singleton — populated on first use, never at import time
_cross_encoder: Optional[object] = None
_load_failed:   bool = False


def _load_cross_encoder():
    """Attempt to load the cross-encoder; set _load_failed on any error."""
    global _cross_encoder, _load_failed
    if _cross_encoder is not None or _load_failed:
        return

    try:
        from sentence_transformers import CrossEncoder  # type: ignore
        logger.info("Loading cross-encoder model '%s'…", _CROSS_ENCODER_MODEL)
        _cross_encoder = CrossEncoder(_CROSS_ENCODER_MODEL)
        logger.info("Cross-encoder '%s' loaded and resident in memory.", _CROSS_ENCODER_MODEL)
    except ImportError:
        logger.warning(
            "sentence-transformers not installed — reranker falling back to RRF order."
        )
        _load_failed = True
    except Exception as exc:
        logger.warning(
            "Could not load cross-encoder '%s': %s — falling back to RRF order.",
            _CROSS_ENCODER_MODEL, exc,
        )
        _load_failed = True


def rerank(
    query: str,
    docs:  list["RetrievedDoc"],
    top_n: int = 5,
) -> list["RetrievedDoc"]:
    """Re-rank *docs* against *query* using a cross-encoder model.

    Parameters
    ----------
    query:
        The original retrieval query string.
    docs:
        Candidate documents (e.g. top-50 from :func:`hybrid_search`).
    top_n:
        How many documents to return after re-ranking.

    Returns
    -------
    The top ``top_n`` documents sorted by descending cross-encoder score.
    Falls back to the first ``top_n`` input documents (already sorted by
    RRF) if the model is unavailable.
    """
    if not docs:
        return []

    # Lazy load — happens here, NOT at module import or backend startup
    _load_cross_encoder()

    if _load_failed or _cross_encoder is None:
        logger.warning(
            "rerank: model unavailable, returning first %d docs by RRF score.", top_n
        )
        return list(docs[:top_n])

    # Build (query, passage) pairs
    pairs = [(query, doc["text"]) for doc in docs]

    try:
        scores = _cross_encoder.predict(pairs, show_progress_bar=False)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.warning("rerank: prediction failed (%s) — falling back to RRF order.", exc)
        return list(docs[:top_n])

    # Attach scores and sort descending
    scored = sorted(
        zip(scores, docs),
        key=lambda x: float(x[0]),
        reverse=True,
    )

    result = [doc for _, doc in scored[:top_n]]
    logger.info(
        "rerank: %d → %d docs (top cross-encoder score=%.4f, query=%.60s)",
        len(docs), len(result),
        float(scored[0][0]) if scored else 0.0,
        query,
    )
    return result
