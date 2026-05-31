"""Hybrid retrieval: ChromaDB vector search + FTS5 BM25 fused with RRF.

Public API
----------
hybrid_search(query, k=50) -> list[RetrievedDoc]
    Run both retrieval legs, merge with Reciprocal Rank Fusion, return the
    merged list sorted by descending RRF score.

RetrievedDoc
    TypedDict with keys: id, text, metadata, distance, rrf_score.

RRF formula (Cormack et al., 2009):
    score(d) = Σ  1 / (RRF_K + rank_in_list)
               lists
where RRF_K = 60 is the standard constant.
"""

from __future__ import annotations

import logging
from typing import TypedDict

logger = logging.getLogger(__name__)

RRF_K = 60  # standard constant; do not change without re-evaluation

# ── Provenance helpers ────────────────────────────────────────────────────────

def _infer_source_class(source_file: str) -> str:
    """Infer collection name from the source file path stored in metadata.

    Heuristic (same logic used in migrate_collections.py):
      - path contains 'nvd_advisories' or 'cisa_kev_notes' → cve_descriptions
      - path contains 'vendor_advisories'                   → vendor_advisories
      - path contains 'runbooks'                            → internal_runbooks
      - default                                             → cve_descriptions
    """
    p = source_file.replace("\\", "/").lower()
    if "vendor_advisories" in p:
        return "vendor_advisories"
    if "runbooks" in p:
        return "internal_runbooks"
    return "cve_descriptions"


def _infer_source_id(doc_id: str) -> str:
    """Extract the document-level identifier from a chunk doc_id.

    doc_ids follow the pattern ``{stem}_{chunk_index}``, e.g.
    ``CVE-2024-3400_0``  →  ``CVE-2024-3400``
    ``RHSA-2024-1234_2`` →  ``RHSA-2024-1234``
    ``postgres-upgrade_1`` → ``postgres-upgrade``

    If the pattern doesn't match, return the full doc_id.
    """
    # Strip trailing ``_N`` suffix
    parts = doc_id.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return doc_id


# ── Data types ────────────────────────────────────────────────────────────────

class RetrievedDoc(TypedDict):
    """A single document retrieved (and optionally re-ranked) from the corpus."""

    id:           str    # ChromaDB / FTS5 document ID, e.g. "CVE-2024-3400_0"
    text:         str    # chunk text
    metadata:     dict   # ChromaDB metadata (source_file, chunk_index, …)
    distance:     float  # vector distance; 0.0 for BM25-only results
    rrf_score:    float  # Reciprocal Rank Fusion score (higher = more relevant)
    source_class: str    # collection name: "cve_descriptions" | "vendor_advisories" | "internal_runbooks"
    source_id:    str    # document-level identifier: CVE ID, advisory ID, runbook slug


# ── RRF core ─────────────────────────────────────────────────────────────────

def reciprocal_rank_fusion(
    *ranked_lists: list[str],
    k: int = RRF_K,
) -> dict[str, float]:
    """Compute RRF scores for document IDs across multiple ranked lists.

    Each list element is a doc_id string.  Returns a dict mapping doc_id →
    RRF score.  Docs appearing in more lists accumulate more score.
    """
    scores: dict[str, float] = {}
    for ranked in ranked_lists:
        for rank, doc_id in enumerate(ranked, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return scores


# ── Hybrid search ─────────────────────────────────────────────────────────────

def hybrid_search(query: str, k: int = 50) -> list[RetrievedDoc]:
    """Run ChromaDB vector search and FTS5 BM25, merge with RRF.

    Parameters
    ----------
    query:
        Natural-language or keyword query string.
    k:
        Number of candidates to fetch from *each* retrieval leg.

    Returns
    -------
    Merged list of :class:`RetrievedDoc` sorted by descending RRF score.
    The list length is ≤ 2k but typically ~k (many docs overlap).
    """
    # Lazy imports so neither model loads at module import time
    from rag.indexer import get_collection, get_embedder
    from rag.fts import bm25_search

    # ── Vector leg ────────────────────────────────────────────────────────────
    collection = get_collection()
    count = collection.count()

    vector_results: list[dict] = []
    if count > 0:
        embedder = get_embedder()
        query_embedding = embedder.encode([query], show_progress_bar=False).tolist()[0]
        n_fetch = min(k, count)
        raw = collection.query(
            query_embeddings=[query_embedding],
            n_results=n_fetch,
            include=["documents", "metadatas", "distances"],
        )
        if raw and raw.get("ids"):
            for doc_id, doc, meta, dist in zip(
                raw["ids"][0],
                raw["documents"][0],
                raw["metadatas"][0],
                raw["distances"][0],
            ):
                vector_results.append({
                    "id": doc_id, "text": doc,
                    "metadata": meta, "distance": dist,
                })
    logger.info(
        "hybrid_search: vector leg returned %d candidates (query=%.60s)",
        len(vector_results), query,
    )

    # ── BM25 leg ──────────────────────────────────────────────────────────────
    bm25_raw = bm25_search(query, k=k)
    logger.info(
        "hybrid_search: BM25 leg returned %d candidates (query=%.60s)",
        len(bm25_raw), query,
    )

    # ── RRF fusion ────────────────────────────────────────────────────────────
    vector_order = [r["id"] for r in vector_results]
    bm25_order   = [r["id"] for r in bm25_raw]

    rrf_scores = reciprocal_rank_fusion(vector_order, bm25_order)

    # Build a unified doc store (vector docs take precedence for metadata)
    doc_store: dict[str, dict] = {}
    for r in bm25_raw:
        doc_store[r["id"]] = {"text": r["text"], "metadata": {}, "distance": 0.0}
    for r in vector_results:          # overwrite with richer vector metadata
        doc_store[r["id"]] = {
            "text": r["text"], "metadata": r["metadata"], "distance": r["distance"],
        }

    # Sort by descending RRF score
    merged: list[RetrievedDoc] = []
    for doc_id, score in sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True):
        if doc_id not in doc_store:
            continue
        d = doc_store[doc_id]
        meta = d["metadata"]
        # Populate provenance fields from metadata when present;
        # fall back to inference from the doc_id for legacy single-collection docs.
        sc = meta.get("source_class") or _infer_source_class(meta.get("source_file", ""))
        si = meta.get("source_id") or _infer_source_id(doc_id)
        merged.append(RetrievedDoc(
            id=doc_id,
            text=d["text"],
            metadata=meta,
            distance=d["distance"],
            rrf_score=score,
            source_class=sc,
            source_id=si,
        ))

    logger.info(
        "hybrid_search: RRF merged %d unique docs (vector=%d, bm25=%d)",
        len(merged), len(vector_results), len(bm25_raw),
    )
    return merged
