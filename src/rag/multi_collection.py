"""Multi-collection hybrid retrieval with per-source weighting.

Public API
----------
multi_collection_search(query, k=50, weights=None) -> list[RetrievedDoc]
    Fan out across all three collections, merge with weighted RRF, return
    the combined ranked list.

Weight semantics
----------------
After RRF fusion within each collection, the collection-level RRF score is
multiplied by the collection's weight before the global sort.  This means
internal runbooks (weight 1.5) will rank higher than raw CVE descriptions
(weight 1.0) when their raw relevance is similar.

Default weights (also in policy.yaml):
    cve_descriptions:  1.0
    vendor_advisories: 1.2
    internal_runbooks: 1.5

Overridable at runtime via environment variables:
    RAG_WEIGHT_CVE      (float, default 1.0)
    RAG_WEIGHT_ADVISORY (float, default 1.2)
    RAG_WEIGHT_RUNBOOK  (float, default 1.5)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rag.hybrid_search import RetrievedDoc

logger = logging.getLogger(__name__)

# ── Default weights ───────────────────────────────────────────────────────────

_DEFAULT_WEIGHTS: dict[str, float] = {
    "cve_descriptions":  1.0,
    "vendor_advisories": 1.2,
    "internal_runbooks": 1.5,
}


def _get_weights(override: dict[str, float] | None = None) -> dict[str, float]:
    """Return effective weights, merging env-var overrides with defaults."""
    weights = dict(_DEFAULT_WEIGHTS)
    # Environment-variable overrides
    for env_var, key in [
        ("RAG_WEIGHT_CVE",      "cve_descriptions"),
        ("RAG_WEIGHT_ADVISORY", "vendor_advisories"),
        ("RAG_WEIGHT_RUNBOOK",  "internal_runbooks"),
    ]:
        val = os.getenv(env_var)
        if val is not None:
            try:
                weights[key] = float(val)
            except ValueError:
                logger.warning("Invalid value for %s: %r (ignored)", env_var, val)
    # Caller-provided override (highest priority)
    if override:
        weights.update(override)
    return weights


# ── Per-collection hybrid retrieval ──────────────────────────────────────────

def _search_one_collection(
    query: str,
    collection_name: str,
    k: int,
) -> list["RetrievedDoc"]:
    """Run vector + BM25 hybrid search against a single named collection.

    Returns merged RRF-sorted docs with ``source_class`` set to
    *collection_name* and ``source_id`` extracted from the doc_id.
    """
    from rag.indexer import get_named_collection, get_embedder
    from rag.fts import bm25_search_by_class
    from rag.hybrid_search import (
        reciprocal_rank_fusion, RetrievedDoc,
        _infer_source_id,
    )

    # ── Vector leg ────────────────────────────────────────────────────────────
    vector_results: list[dict] = []
    try:
        collection = get_named_collection(collection_name)
        count = collection.count()
        if count > 0:
            embedder = get_embedder()
            qe = embedder.encode([query], show_progress_bar=False).tolist()[0]
            raw = collection.query(
                query_embeddings=[qe],
                n_results=min(k, count),
                include=["documents", "metadatas", "distances"],
            )
            if raw and raw.get("ids"):
                for doc_id, doc, meta, dist in zip(
                    raw["ids"][0], raw["documents"][0],
                    raw["metadatas"][0], raw["distances"][0],
                ):
                    vector_results.append({
                        "id": doc_id, "text": doc, "metadata": meta, "distance": dist,
                    })
    except Exception as exc:
        logger.warning("Vector search failed for collection '%s': %s", collection_name, exc)

    # ── BM25 leg ──────────────────────────────────────────────────────────────
    bm25_raw = bm25_search_by_class(query, source_class=collection_name, k=k)

    logger.info(
        "multi_collection[%s]: vector=%d bm25=%d  query=%.50s",
        collection_name, len(vector_results), len(bm25_raw), query,
    )

    if not vector_results and not bm25_raw:
        return []

    # ── RRF fusion within this collection ────────────────────────────────────
    vector_order = [r["id"] for r in vector_results]
    bm25_order   = [r["id"] for r in bm25_raw]
    rrf_scores   = reciprocal_rank_fusion(vector_order, bm25_order)

    # Build unified doc store
    doc_store: dict[str, dict] = {}
    for r in bm25_raw:
        doc_store[r["id"]] = {"text": r["text"], "metadata": {}, "distance": 0.0}
    for r in vector_results:
        doc_store[r["id"]] = {
            "text": r["text"], "metadata": r["metadata"], "distance": r["distance"],
        }

    merged: list[RetrievedDoc] = []
    for doc_id, score in sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True):
        if doc_id not in doc_store:
            continue
        d = doc_store[doc_id]
        meta = d["metadata"]
        merged.append(RetrievedDoc(
            id=doc_id,
            text=d["text"],
            metadata=meta,
            distance=d["distance"],
            rrf_score=score,
            source_class=collection_name,
            source_id=meta.get("source_id") or _infer_source_id(doc_id),
        ))

    return merged


# ── Multi-collection fan-out ──────────────────────────────────────────────────

def multi_collection_search(
    query:   str,
    k:       int = 50,
    weights: dict[str, float] | None = None,
) -> list["RetrievedDoc"]:
    """Fan out across all three collections and merge with weighted RRF.

    Parameters
    ----------
    query:
        The retrieval query string.
    k:
        Number of candidates to fetch per collection per retrieval leg.
    weights:
        Per-collection weight multipliers.  ``None`` uses defaults +
        any ``RAG_WEIGHT_*`` environment variables.

    Returns
    -------
    Merged list of :class:`~rag.hybrid_search.RetrievedDoc` sorted by
    descending weighted RRF score.
    """
    from rag.indexer import ALL_COLLECTIONS

    effective_weights = _get_weights(weights)
    logger.info(
        "multi_collection_search: weights=%s  query=%.60s",
        {k: round(v, 3) for k, v in effective_weights.items()}, query,
    )

    # ── Retrieve from each collection ─────────────────────────────────────────
    all_docs: dict[str, "RetrievedDoc"] = {}   # doc_id → doc (best metadata wins)
    weighted_scores: dict[str, float] = {}      # doc_id → weighted score

    for col_name in ALL_COLLECTIONS:
        w = effective_weights.get(col_name, 1.0)
        col_docs = _search_one_collection(query, col_name, k)
        for doc in col_docs:
            did   = doc["id"]
            wscore = doc["rrf_score"] * w
            if did not in weighted_scores or wscore > weighted_scores[did]:
                weighted_scores[did] = wscore
                all_docs[did] = doc

    # ── Global sort by weighted score ─────────────────────────────────────────
    merged = sorted(
        [
            {**all_docs[did], "rrf_score": weighted_scores[did]}
            for did in weighted_scores
        ],
        key=lambda d: d["rrf_score"],
        reverse=True,
    )

    logger.info(
        "multi_collection_search: merged %d unique docs from %d collections",
        len(merged), len(ALL_COLLECTIONS),
    )
    return merged   # type: ignore[return-value]
