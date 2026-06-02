"""RAG Retriever.

Queries ChromaDB for the top-k advisory chunks most relevant to a job.

Retrieval strategy (two-pass):
  1. Direct CVE-ID lookup: use collection.get() with where_document $contains
     to pull chunks that literally contain the CVE ID string. No extra embedding
     model needed — ChromaDB does plain-text document matching.
  2. Semantic search: embed a product-focused query (no CVE IDs to avoid
     keyword noise) and fetch the remaining slots, deduplicating against pass 1.
"""

import json
import logging

from rag.indexer import _load_config, get_collection, get_embedder

logger = logging.getLogger(__name__)


def retrieve_chunks(query: str, top_k: int = None) -> list[dict]:
    """Embed *query* and return the top-k most similar advisory chunks.

    Each item in the returned list has keys: ``text``, ``metadata``, ``distance``.
    """
    config = _load_config()
    if top_k is None:
        top_k = config.get("top_k_chunks", 5)

    embedder   = get_embedder()
    collection = get_collection()
    count      = collection.count()
    if count == 0:
        logger.warning("ChromaDB collection is empty — no chunks to retrieve.")
        return []

    query_embedding = embedder.encode([query], show_progress_bar=False).tolist()[0]

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=min(top_k, count),
        include=["documents", "metadatas", "distances"],
    )

    chunks: list[dict] = []
    if results and results.get("documents"):
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            chunks.append({"text": doc, "metadata": meta, "distance": dist})

    logger.debug("Retrieved %d chunks for query: %.80s", len(chunks), query)
    return chunks


def _direct_cve_lookup(collection, cve_ids: list[str], limit: int) -> list[dict]:
    """Return chunks whose document text contains any of the given CVE IDs.

    Uses collection.get() with where_document — pure text match, no ONNX
    or extra embedding model required.
    """
    found: list[dict] = []
    seen: set[str] = set()

    for cve_id in cve_ids[:8]:   # cap to avoid excessive queries
        try:
            result = collection.get(
                where_document={"$contains": cve_id},
                include=["documents", "metadatas"],
                limit=3,
            )
            if not result or not result.get("documents"):
                continue
            for doc, meta in zip(result["documents"], result["metadatas"]):
                key = doc[:80]
                if key not in seen:
                    seen.add(key)
                    found.append({"text": doc, "metadata": meta, "distance": 0.0})
                    if len(found) >= limit:
                        return found
        except Exception as exc:
            logger.debug("Direct CVE get() for %s failed: %s", cve_id, exc)

    return found


def retrieve_for_job(job: dict, top_k: int = None) -> list[dict]:
    """Two-pass retrieval: exact CVE lookup first, then semantic fill.

    Pass 1 – collection.get() with $contains filter on CVE IDs:
              guarantees the advisory for each known CVE is returned regardless
              of embedding distance noise.
    Pass 2 – semantic search on product + vulnerability type:
              fills remaining slots with contextually similar advisories.
    """
    config = _load_config()
    if top_k is None:
        top_k = config.get("top_k_chunks", 5)

    collection = get_collection()
    count      = collection.count()
    if count == 0:
        logger.warning("ChromaDB collection is empty — no chunks to retrieve.")
        return []

    # Parse cve_list
    cve_raw = job.get("cve_list", "[]")
    if isinstance(cve_raw, str):
        try:
            cves = json.loads(cve_raw)
        except (json.JSONDecodeError, ValueError):
            cves = [cve_raw] if cve_raw else []
    else:
        cves = list(cve_raw) if isinstance(cve_raw, (list, tuple)) else []

    # ── Pass 1: exact CVE text match ──────────────────────────────────────────
    direct_chunks: list[dict] = []
    if cves:
        direct_chunks = _direct_cve_lookup(collection, cves, limit=min(len(cves) * 2, top_k))
        logger.info("Direct CVE lookup returned %d chunks for %s", len(direct_chunks), cves)

    # ── Pass 2: semantic search for remaining slots ───────────────────────────
    remaining = top_k - len(direct_chunks)
    semantic_chunks: list[dict] = []

    if remaining > 0:
        # Focus semantic query on product + plugin_family (not CVE IDs — those
        # create keyword noise that pulls wrong Java/Oracle advisories).
        sem_parts: list[str] = []
        if job.get("main_product"):
            sem_parts.append(job["main_product"])
        if job.get("plugin_family"):
            sem_parts.append(job["plugin_family"])
        if job.get("max_risk_level"):
            sem_parts.append(f"{job['max_risk_level']} vulnerability")

        sem_query = " ".join(sem_parts) if sem_parts else "vulnerability remediation advisory"
        logger.debug("Semantic fill query: %s", sem_query)

        embedder        = get_embedder()
        query_embedding = embedder.encode([sem_query], show_progress_bar=False).tolist()[0]
        n_fetch         = min(remaining + len(direct_chunks) + 5, count)

        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=n_fetch,
            include=["documents", "metadatas", "distances"],
        )

        direct_texts = {c["text"][:80] for c in direct_chunks}
        if results and results.get("documents"):
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            ):
                if doc[:80] not in direct_texts:
                    semantic_chunks.append({"text": doc, "metadata": meta, "distance": dist})
                    if len(semantic_chunks) >= remaining:
                        break

    all_chunks = direct_chunks + semantic_chunks
    logger.info(
        "retrieve_for_job: %d direct + %d semantic = %d total",
        len(direct_chunks), len(semantic_chunks), len(all_chunks),
    )
    return all_chunks
