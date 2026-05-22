"""RAG Retriever.

Queries ChromaDB for the top-k advisory chunks most relevant to a query.
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

    embedder = get_embedder()
    query_embedding = embedder.encode([query], show_progress_bar=False).tolist()[0]

    collection = get_collection()
    count = collection.count()
    if count == 0:
        logger.warning("ChromaDB collection is empty — no chunks to retrieve.")
        return []

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


def retrieve_for_job(job: dict, top_k: int = None) -> list[dict]:
    """Build a composite query from job fields and call retrieve_chunks.

    Fields used (when present): cve_list, main_product, plugin_family, vuln_title.
    """
    parts: list[str] = []

    # Parse cve_list — may arrive as a JSON string or a list
    cve_list = job.get("cve_list", "[]")
    if isinstance(cve_list, str):
        try:
            cves = json.loads(cve_list)
        except (json.JSONDecodeError, ValueError):
            cves = [cve_list] if cve_list else []
    else:
        cves = list(cve_list) if isinstance(cve_list, (list, tuple)) else []

    if cves:
        parts.append("CVEs: " + ", ".join(str(c) for c in cves))

    if job.get("main_product"):
        parts.append(f"Product: {job['main_product']}")

    if job.get("plugin_family"):
        parts.append(f"Plugin family: {job['plugin_family']}")

    if job.get("vuln_title"):
        parts.append(f"Vulnerability: {job['vuln_title']}")

    query = " | ".join(parts) if parts else "vulnerability remediation advisory"
    logger.debug("retrieve_for_job query: %s", query)
    return retrieve_chunks(query, top_k=top_k)
